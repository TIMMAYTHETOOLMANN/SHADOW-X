import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_LOCK = threading.Lock()


class Ledger:
    """Persistent cluster ledger: known targets, enrollment status, job IDs."""

    def __init__(self, path: str):
        self.path = Path(path)
        self._state: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                self._state = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                backup = self.path.with_suffix(".corrupt")
                self.path.rename(backup)  # quarantine; Section 2.6 Isolate
                self._state = {}

    def _save(self):
        with _LOCK:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._state, indent=2), encoding="utf-8")

    @staticmethod
    def _key(ip: str, port: int) -> str:
        return f"{ip}:{port}"

    def upsert(self, ip: str, port: int, **fields) -> Dict[str, Any]:
        key = self._key(ip, port)
        with _LOCK:
            rec = self._state.setdefault(key, {"ip": ip, "port": port})
            rec.update(fields)
            rec.setdefault("first_seen", time.time())
            rec["last_seen"] = time.time()
        self._save()
        return rec

    def get(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        return self._state.get(self._key(ip, port))

    def list_clusters(self, only_alive: bool = False) -> List[Dict[str, Any]]:
        recs = list(self._state.values())
        if only_alive:
            recs = [r for r in recs if r.get("status", "").endswith("_alive")]
        return sorted(recs, key=lambda r: r.get("first_seen", 0))

    def add_job(self, ip: str, port: int, job_id: str):
        rec = self.get(ip, port)
        if rec is None:
            rec = self.upsert(ip, port)
        jobs = rec.setdefault("job_ids", [])
        if job_id not in jobs:
            jobs.append(job_id)
        self._save()

    def burned(self, ip: str, port: int, reason: str):
        """Negative knowledge: never re-enroll a burned target (Section 4.4)."""
        self.upsert(ip, port, status="burned", burn_reason=reason)

    def stats(self) -> Dict[str, Any]:
        recs = list(self._state.values())
        by_status: Dict[str, int] = {}
        for r in recs:
            s = r.get("status", "unknown")
            by_status[s] = by_status.get(s, 0) + 1
        return {"total": len(recs), "by_status": by_status}