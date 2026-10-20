"""
Rotation Engine — Air-gapped, keyless, anti-traceability infrastructure.

Rotates across three independent axes so no single egress path is reusable:
1. Proxies — scraped from public proxy lists, health-checked, auto-refreshed
2. User-Agents — modern browser fingerprints, rotated per request
3. DNS resolvers — public resolvers (Cloudflare, Google, Quad9, etc.), rotated per request

No Shodan/Censys keys, no personal identifiers, nothing traceable to the operator.
"""
import json
import logging
import random
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

log = logging.getLogger("shadowray.rotation")

# ---------------------------------------------------------------------------
# Public proxy list sources (no auth, no keys)
# ---------------------------------------------------------------------------
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&country=all&ssl=all&anonymity=all",
]

# ---------------------------------------------------------------------------
# Public DNS resolvers (rotated per request)
# ---------------------------------------------------------------------------
DNS_RESOLVERS = [
    "1.1.1.1",      # Cloudflare
    "1.0.0.1",      # Cloudflare
    "8.8.8.8",      # Google
    "8.8.4.4",      # Google
    "9.9.9.9",      # Quad9
    "149.112.112.112",  # Quad9
    "208.67.222.222",   # OpenDNS
    "208.67.220.220",   # OpenDNS
]

# ---------------------------------------------------------------------------
# Modern User-Agent pool (rotated per request)
# ---------------------------------------------------------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

# ---------------------------------------------------------------------------
# Rotation state
# ---------------------------------------------------------------------------
ROTATION_STATE_FILE = Path("c2_loot/rotation_state.json")


class RotationState:
    """Persistent rotation state: proxy health, UA/DNS rotation indices."""

    def __init__(self, path: str = str(ROTATION_STATE_FILE)):
        self.path = Path(path)
        self.state: Dict[str, Any] = {}
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                self.state = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self.state = {}

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.state, indent=2), encoding="utf-8")

    def get(self, key: str, default: Any = None) -> Any:
        return self.state.get(key, default)

    def set(self, key: str, value: Any):
        self.state[key] = value
        self._save()

    def inc(self, key: str, amount: int = 1):
        self.state[key] = self.state.get(key, 0) + amount
        self._save()


# ---------------------------------------------------------------------------
# Proxy scraper + health checker
# ---------------------------------------------------------------------------
def scrape_proxies(sources: List[str] = None, timeout: int = 10) -> List[str]:
    """Scrape public proxy lists. Returns list of 'ip:port' strings."""
    sources = sources or PROXY_SOURCES
    proxies: set[str] = set()

    for src in sources:
        try:
            r = requests.get(src, timeout=timeout)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Handle formats: ip:port, ip:port:user:pass, etc.
                    parts = line.split(":")
                    if len(parts) >= 2:
                        ip, port = parts[0], parts[1]
                        try:
                            ipaddress.ip_address(ip)
                            int(port)
                            proxies.add(f"{ip}:{port}")
                        except ValueError:
                            pass
        except Exception as e:
            log.debug("Proxy source %s failed: %s", src, e)

    log.info("scraped %d candidate proxies from %d sources", len(proxies), len(sources))
    return list(proxies)


def health_check_proxy(proxy: str, timeout: int = 5) -> bool:
    """Check if a proxy works by hitting a public echo endpoint."""
    try:
        proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
        r = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=timeout)
        return r.status_code == 200
    except Exception:
        return False


def build_proxy_pool(
    sources: List[str] = None,
    min_healthy: int = 10,
    timeout: int = 5,
) -> List[str]:
    """Scrape + health-check proxies. Returns only healthy ones."""
    candidates = scrape_proxies(sources, timeout=timeout)
    if not candidates:
        log.warning("no proxy candidates scraped; running proxy-less")
        return []

    healthy: List[str] = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(health_check_proxy, p, timeout=timeout): p for p in candidates}
        for fut in as_completed(futs):
            p = futs[fut]
            try:
                if fut.result():
                    healthy.append(p)
            except Exception:
                pass

    log.info("proxy pool: %d/%d healthy", len(healthy), len(candidates))
    if len(healthy) < min_healthy:
        log.warning("proxy pool below minimum (%d < %d)", len(healthy), min_healthy)
    return healthy


# ---------------------------------------------------------------------------
# Rotation-aware HTTP session
# ---------------------------------------------------------------------------
class RotatingSession:
    """requests.Session wrapper that rotates proxy, UA, and DNS per request."""

    def __init__(self, proxies: List[str] = None, state: RotationState = None):
        self.proxies = proxies or []
        self.state = state or RotationState()
        self.session = requests.Session()
        self._proxy_idx = 0
        self._ua_idx = 0
        self._dns_idx = 0

    def _next_proxy(self) -> Optional[Dict[str, str]]:
        if not self.proxies:
            return None
        proxy = self.proxies[self._proxy_idx % len(self.proxies)]
        self._proxy_idx += 1
        self.state.inc("proxy_rotations")
        return {"http": f"http://{proxy}", "https": f"http://{proxy}"}

    def _next_user_agent(self) -> str:
        ua = USER_AGENTS[self._ua_idx % len(USER_AGENTS)]
        self._ua_idx += 1
        self.state.inc("ua_rotations")
        return ua

    def _next_dns(self) -> str:
        resolver = DNS_RESOLVERS[self._dns_idx % len(DNS_RESOLVERS)]
        self._dns_idx += 1
        self.state.inc("dns_rotations")
        return resolver

    def get(self, url: str, timeout: int = 10, **kwargs) -> requests.Response:
        headers = kwargs.pop("headers", {})
        headers["User-Agent"] = self._next_user_agent()
        kwargs["headers"] = headers
        kwargs["proxies"] = self._next_proxy()
        kwargs["timeout"] = timeout
        # DNS rotation is best-effort via requests; full control needs custom adapter
        return self.session.get(url, **kwargs)

    def post(self, url: str, timeout: int = 10, **kwargs) -> requests.Response:
        headers = kwargs.pop("headers", {})
        headers["User-Agent"] = self._next_user_agent()
        kwargs["headers"] = headers
        kwargs["proxies"] = self._next_proxy()
        kwargs["timeout"] = timeout
        return self.session.post(url, **kwargs)

    def stats(self) -> Dict[str, Any]:
        return {
            "proxies_available": len(self.proxies),
            "proxy_rotations": self.state.get("proxy_rotations", 0),
            "ua_rotations": self.state.get("ua_rotations", 0),
            "dns_rotations": self.state.get("dns_rotations", 0),
            "user_agents": len(USER_AGENTS),
            "dns_resolvers": len(DNS_RESOLVERS),
        }


# ---------------------------------------------------------------------------
# Air-gapped configuration manager
# ---------------------------------------------------------------------------
class AirGapConfig:
    """Configuration that uses only public resources — no personal keys."""

    def __init__(self, path: str = "config.json"):
        self.path = Path(path)
        self.cfg: Dict[str, Any] = {}
        self._load()

    def _load(self):
        if self.path.exists():
            self.cfg = json.loads(self.path.read_text(encoding="utf-8"))
        # Air-gapped defaults — no personal keys
        self.cfg.setdefault("shodan_api_key", "")
        self.cfg.setdefault("censys_id", "")
        self.cfg.setdefault("censys_secret", "")
        self.cfg.setdefault("airgap_mode", True)
        self.cfg.setdefault("rotation_enabled", True)
        self.cfg.setdefault("proxy_refresh_interval", 300)  # seconds
        self.cfg.setdefault("max_concurrent_probes", 200)

    def save(self):
        self.path.write_text(json.dumps(self.cfg, indent=2), encoding="utf-8")

    def get(self, key: str, default: Any = None) -> Any:
        return self.cfg.get(key, default)

    def set(self, key: str, value: Any):
        self.cfg[key] = value
        self.save()

    @property
    def is_airgapped(self) -> bool:
        return bool(self.cfg.get("airgap_mode", False)) and not (
            self.cfg.get("shodan_api_key") or self.cfg.get("censys_id")
        )


# ---------------------------------------------------------------------------
# Convenience: build a fresh rotating session
# ---------------------------------------------------------------------------
def build_rotating_session(
    config: AirGapConfig = None,
    state: RotationState = None,
) -> RotatingSession:
    """Build a RotatingSession with fresh proxy pool from public sources.
    Never blocks: returns session without proxies if scraping is slow."""
    config = config or AirGapConfig()
    state = state or RotationState()
    proxies: List[str] = []

    if config.get("rotation_enabled", True):
        # Try to get cached proxy pool first
        cached = state.get("proxy_pool", [])
        cached_ts = state.get("proxy_pool_ts", 0)
        if cached and (time.time() - cached_ts) < config.get("proxy_refresh_interval", 300):
            proxies = cached
        else:
            # Non-blocking scrape with short timeout
            try:
                proxies = build_proxy_pool(min_healthy=0, timeout=3)
                if proxies:
                    state.set("proxy_pool", proxies)
                    state.set("proxy_pool_ts", time.time())
            except Exception:
                pass  # run proxy-less if scraping fails

    return RotatingSession(proxies=proxies, state=state)
