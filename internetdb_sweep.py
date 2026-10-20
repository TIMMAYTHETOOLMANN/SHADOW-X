"""
Shodan InternetDB — free, keyless, fast.
Batch IP risk-scoring against Shodan's already-indexed port/vuln metadata.
Feed cloud /16s through at ~40 IPs/request, filter for open target ports.
"""
import json
import logging
import random
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple

from .rotation import RotatingSession, build_rotating_session
from .ledger import Ledger
from . import discover as D
from . import docker_swarm, jupyter_scan
from .port_spectrum import IDB_SPECTRUM

log = logging.getLogger("shadowray.internetdb")

_idb_session: RotatingSession | None = None


def _get_idb_session() -> RotatingSession:
    global _idb_session
    if _idb_session is None:
        _idb_session = build_rotating_session()
    return _idb_session

URL = "https://internetdb.shodan.io/{ip}"

PORTS_OF_INTEREST = tuple(IDB_SPECTRUM)  # All 38 spectrum ports via metadata (filtering is free)

VECTOR_PORTS = {
    "ray": 8265,
    "docker": 2375,
    "docker_tls": 2376,
    "jupyter": 8888,
    "comfyui": 8188,
    "kubeflow": 7860,
}


def lookup(ip: str, timeout: int = 8, max_retries: int = 3) -> Tuple[str, List[int], List[str], List[str]] | None:
    """Query InternetDB for a single IP. Returns (ip, ports, vulns, cpes) or None.
    Handles 429 rate limiting with exponential backoff."""
    session = _get_idb_session()
    for attempt in range(max_retries):
        try:
            r = session.get(URL.format(ip=ip), timeout=timeout)
            if r.ok:
                d = r.json()
                return (ip, d.get("ports", []), d.get("vulns", []), d.get("cpes", []))
            if r.status_code == 429:
                # rate limited — back off and retry
                wait = min(2 ** attempt, 30)
                log.debug("InternetDB 429 on %s, backing off %ds", ip, wait)
                time.sleep(wait)
                continue
            return None
        except Exception:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            pass
    return None


def batch_ips(cidrs: List[str], shuffle: bool = True) -> List[str]:
    """Expand CIDRs to a host list."""
    ips: List[str] = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            ips.extend(str(i) for i in net.hosts())
        except ValueError:
            log.warning("Bad CIDR skipped: %s", c)
    if shuffle:
        random.shuffle(ips)
    return ips


def sweep(cfg: Dict[str, Any], ledger: Ledger,
          ports_of_interest: Tuple[int, ...] = PORTS_OF_INTEREST) -> int:
    """InternetDB sweep of configured CIDRs. Only validation-probes hits."""
    ips = batch_ips(cfg.get("scan_cidrs", []))
    log.info("internetdb sweep: %d IPs across %d CIDR blocks",
             len(ips), len(cfg.get("scan_cidrs", [])))
    threads = min(cfg.get("scan_threads", 600), 1000)
    hit_count = [0]

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(lookup, ip): ip for ip in ips}
        for fut in as_completed(futs):
            res = fut.result()
            if not res:
                continue
            ip, ports, vulns, cpes = res
            for p in ports_of_interest:
                if p in ports:
                    hit_count[0] += 1
                    ledger.upsert(ip, p, status="idb_candidate",
                                  vulns=vulns[:10], cpes=cpes[:10],
                                  source="internetdb")
                    log.info("[IDB-HIT] %s port %s vulns=%s cpes=%s",
                             ip, p, vulns[:5], cpes[:5])
            # small rate courtesy — InternetDB is free/keyless
            time.sleep(0.01)

    log.info("internetdb complete: %d candidate endpoints", hit_count[0])
    return hit_count[0]


def validate_and_enroll(cfg: Dict[str, Any], ledger: Ledger) -> Tuple[int, int]:
    """Take idb_candidate entries, validate each vector, enroll live ones."""
    from . import discover as D
    from . import docker_swarm as DS
    from . import jupyter_scan as JS

    candidates = [(rec["ip"], rec["port"]) for rec in ledger._state.values()
                  if rec.get("status") == "idb_candidate"]
    random.shuffle(candidates)

    validated = 0
    enrolled = 0

    for ip, port in candidates:
        # Detect which vector this port belongs to
        vector = None
        for vname, vport in VECTOR_PORTS.items():
            if port == vport:
                vector = vname
                break
        if vector is None:
            continue

        # Validate via the appropriate vector's check function
        fp = None
        if vector == "ray":
            fp = D.check_ray(ip, port)
        elif vector == "docker":
            fp = DS.check_docker(ip, port)
        elif vector == "jupyter":
            fp = JS.check_jupyter(ip, port)
        elif vector == "comfyui":
            fp = JS.check_comfyui(ip, port)
        elif vector == "kubeflow":
            fp = JS.check_kubeflow(ip, port)

        if fp:
            ledger.upsert(ip, port, status="ray_alive", source="internetdb", vector=vector, **fp)
            validated += 1
            log.info("[+] %s:%s %s ALIVE %s", ip, port, vector, fp.get("version", ""))
        else:
            ledger.upsert(ip, port, status="dead", source="internetdb")

    # Enroll all validated live targets via Ray Jobs API (or vector-specific path)
    if cfg.get("enroll_concurrency", 20) > 0:
        from .rayapi import enroll_all
        enrolled = enroll_all(cfg, ledger)
        log.info("[+] Enrolled %d/%d clusters", enrolled, validated)

    return validated, enrolled
