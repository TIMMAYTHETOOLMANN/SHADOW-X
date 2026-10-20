import ipaddress
import json
import logging
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List, Tuple

from .rotation import RotatingSession, build_rotating_session
from .ledger import Ledger
from .fastscan import fastscan, idb_sweep_cidrs, BRUTE_PRIORITY, get_port_vector

log = logging.getLogger("shadowray.discover")

SHODAN_SEARCH = "https://api.shodan.io/shodan/host/search"
CENSYS_SEARCH = "https://search.censys.io/api/v2/hosts/search"
_NGROK_HEADERS = {"ngrok-skip-browser-warning": "true"}

# Global rotating session — air-gapped, keyless, anti-traceability
_session: RotatingSession | None = None


def _get_session() -> RotatingSession:
    global _session
    if _session is None:
        _session = build_rotating_session()
    return _session


def check_ray(ip: str, port: int, timeout: float = 8.0) -> Dict[str, Any] | None:
    """Validate that ip:port is a live Ray dashboard. Returns fingerprint or None."""
    base = f"http://{ip}:{port}"
    session = _get_session()
    try:
        r = session.get(f"{base}/", timeout=timeout, verify=False, headers=_NGROK_HEADERS)
        text = r.text[:4000].lower()
        if r.status_code == 200 and ("ray" in text or "dashboard" in text):
            version = None
            try:
                v = session.get(f"{base}/api/version", timeout=timeout, verify=False, headers=_NGROK_HEADERS)
                if v.ok:
                    version = v.json().get("version") or v.json().get("data")
            except Exception:
                pass
            try:
                nodes = session.get(f"{base}/api/nodes", timeout=timeout, verify=False, headers=_NGROK_HEADERS)
                ncount = len(nodes.json()) if nodes.ok else None
            except Exception:
                ncount = None
            return {"ray": True, "http_status": r.status_code, "ray_version": version, "node_count": ncount}
    except Exception:
        pass
    return None


def _shodan_query(api_key: str, query: str, max_hits: int) -> List[Tuple[str, int]]:
    out = []
    page = 1
    session = _get_session()
    while len(out) < max_hits and page <= 5:
        try:
            r = session.get(
                SHODAN_SEARCH,
                params={"key": api_key, "query": query, "page": page, "facets": ""},
                timeout=30,
            )
            if r.status_code != 200:
                log.error("Shodan API error %s: %s", r.status_code, r.text[:300])
                break
            matches = r.json().get("matches", [])
            if not matches:
                break
            for m in matches:
                out.append((m["ip_str"], m.get("port", 8265)))
            page += 1
            time.sleep(1.0)
        except Exception as e:
            log.error("Shodan request failed: %s", e)
            break
    return out[:max_hits]


def _censys_query(cid: str, secret: str, max_hits: int) -> List[Tuple[str, int]]:
    q = 'service.http.response.html_title:"Ray Dashboard" OR (labels:"ray" AND port:8265)'
    out = []
    cursor = None
    session = _get_session()
    while len(out) < max_hits:
        params: Dict[str, Any] = {"q": q, "per_page": 100}
        if cursor:
            params["cursor"] = cursor
        try:
            r = session.get(
                CENSYS_SEARCH, params=params,
                auth=(cid, secret), timeout=30,
            )
            if not r.ok:
                log.error("Censys error %s: %s", r.status_code, r.text[:300])
                break
            data = r.json().get("result", {})
            for hit in data.get("hits", []):
                for svc in hit.get("services", []):
                    out.append((hit["ip"], svc.get("port", 8265)))
            cursor = data.get("links", {}).get("next")
            if not cursor:
                break
        except Exception as e:
            log.error("Censys request failed: %s", e)
            break
    return out[:max_hits]


def _iter_ips(cidrs: Iterable[str], shuffle: bool = True) -> Iterable[str]:
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            log.warning("Bad CIDR skipped: %s", c)
    ips = (str(ip) for net in nets for ip in net.hosts())
    if shuffle:  # dispersion; avoid patterned sequential scanning (Section 5.2)
        items = list(ips)
        random.shuffle(items)
        return items
    return ips


def scan_cidrs(cfg: Dict[str, Any], ledger: Ledger) -> List[Tuple[str, int]]:
    """Raw brute-scan of CIDR ranges for spectrum ports.
    Uses bounded-window async scanner (fastscan) — no upfront future list.
    """
    import asyncio
    ports = cfg["scan_ports"]
    cidrs = cfg.get("scan_cidrs", [])
    results = asyncio.run(fastscan(cidrs, ledger, ports))
    return [(ip, port) for ip, port, vec in results]


def idb_sweep(cfg: Dict[str, Any], ledger: Ledger) -> List[Tuple[str, List[int]]]:
    """Keyless InternetDB sweep for spectrum ports across CIDRs."""
    cidrs = cfg.get("scan_cidrs", [])
    return idb_sweep_cidrs(cidrs, ledger)


def discover(source: str, cfg: Dict[str, Any], ledger: Ledger,
             query: str = None) -> List[Dict[str, Any]]:
    """
    source: 'shodan' | 'censys'
    Returns validated cluster records and records them in the ledger.
    """
    max_hits = cfg["max_targets"]
    if source == "shodan":
        api_key = cfg.get("shodan_api_key")
        if not api_key:
            raise SystemExit("Shodan API key missing (config.shodan_api_key or SHODAN_API_KEY env)")
        q = query or 'http.html:"Ray Dashboard"'
        candidates = _shodan_query(api_key, q, max_hits * 3)
    elif source == "censys":
        if not (cfg.get("censys_id") and cfg.get("censys_secret")):
            raise SystemExit("Censys credentials missing (censys_id / censys_secret)")
        candidates = _censys_query(cfg["censys_id"], cfg["censys_secret"], max_hits * 3)
    else:
        raise ValueError(f"unknown source {source}")

    log.info("candidates from %s: %d — validating...", source, len(candidates))
    # never re-strike burned hosts (Section 4.4)
    to_validate = [(ip, p) for ip, p in set(candidates)
                  if (ledger.get(ip, p) or {}).get("status") != "burned"]
    random.shuffle(to_validate)

    validated = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(check_ray, ip, port): (ip, port) for ip, port in to_validate}
        for fut in as_completed(futs):
            ip, port = futs[fut]
            try:
                fp = fut.result()
            except Exception:
                fp = None
            if fp:
                rec = ledger.upsert(ip, port, status="ray_alive", source=source, **fp)
                validated.append(rec)
                log.info("[+] %s:%s Ray %s nodes=%s", ip, port, fp.get("ray_version"), fp.get("node_count"))
            else:
                ledger.upsert(ip, port, status="dead")
            if len(validated) >= max_hits:
                break
    log.info("validated %d live Ray clusters", len(validated))
    return validated


def discover_spectrum(cfg: Dict[str, Any], ledger: Ledger) -> List[Dict[str, Any]]:
    """
    Spectrum Doctrine discovery: InternetDB sweep → fastscan validation → ledger.
    Finds ALL vector types (Docker, Jupyter, Ray, Ollama, vLLM, etc.) not just Ray.
    """
    log.info("Spectrum discovery: InternetDB sweep + fastscan validation")
    
    # Phase 1: InternetDB sweep (keyless, fast metadata)
    idb_results = idb_sweep(cfg, ledger)
    log.info("InternetDB sweep: %d IPs with spectrum ports", len(idb_results))
    
    # Phase 2: FastScan validation on candidate /24s
    # Build /24 CIDRs from discovered IPs
    candidate_cidrs = set()
    for ip, ports in idb_results:
        cidr = ip.rsplit(".", 1)[0] + ".0/24"
        candidate_cidrs.add(cidr)
    
    if candidate_cidrs:
        # Filter to BRUTE_PRIORITY ports for validation
        validation_ports = [p for p in BRUTE_PRIORITY if p in cfg.get("scan_ports", BRUTE_PRIORITY)]
        import asyncio
        asyncio.run(fastscan(list(candidate_cidrs), ledger, validation_ports))
    
    # Phase 3: Collect all alive services from ledger
    alive = []
    for rec in ledger.list_clusters(only_alive=False):
        if rec.get("status", "").endswith("_alive") or rec.get("status") == "ray_alive":
            alive.append(rec)
    
    log.info("Spectrum discovery complete: %d alive services across %d /24s", len(alive), len(candidate_cidrs))
    return alive
