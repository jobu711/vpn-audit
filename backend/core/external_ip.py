"""External IP geolocation lookup with caching and VPN masking detection."""

import json
import time
import urllib.request
from datetime import datetime, timezone

from backend.core.models import AuditResult

# Known VPN provider patterns (matched case-insensitively against ISP/org fields)
_DEFAULT_VPN_PATTERNS = [
    "proton",
    "mullvad",
    "nordvpn",
    "expressvpn",
    "surfshark",
    "private internet access",
    "cyberghost",
    "windscribe",
    "ivpn",
]

_API_URL = "http://ip-api.com/json/?fields=query,country,city,isp,org,as"


class ExternalIPChecker:
    """Fetches external IP info from ip-api.com with TTL caching."""

    def __init__(
        self,
        cache_ttl: float = 30.0,
        vpn_patterns: list[str] | None = None,
        api_url: str = _API_URL,
        timeout: float = 5.0,
    ):
        self.cache_ttl = cache_ttl
        self.vpn_patterns = [p.lower() for p in (vpn_patterns or _DEFAULT_VPN_PATTERNS)]
        self.api_url = api_url
        self.timeout = timeout
        self._cache: dict | None = None
        self._cache_time: float = 0.0

    def lookup(self) -> dict:
        """Return external IP info dict, using cache if still valid."""
        now = time.monotonic()
        if self._cache is not None and (now - self._cache_time) < self.cache_ttl:
            return self._cache

        try:
            req = urllib.request.Request(self.api_url, headers={"User-Agent": "vpn-audit/0.1"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())

            isp = data.get("isp", "")
            org = data.get("org", "")
            vpn_masked = self._check_vpn(isp, org)

            result = {
                "ip": data.get("query"),
                "country": data.get("country"),
                "city": data.get("city"),
                "isp": isp,
                "org": org,
                "vpn_masked": vpn_masked,
                "status": "ok",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception:
            result = {
                "ip": None,
                "country": None,
                "city": None,
                "isp": None,
                "org": None,
                "vpn_masked": None,
                "status": "error",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        self._cache = result
        self._cache_time = now
        return result

    def _check_vpn(self, isp: str, org: str) -> bool:
        """Return True if ISP or org matches a known VPN provider."""
        combined = f"{isp} {org}".lower()
        return any(pattern in combined for pattern in self.vpn_patterns)

    def run(self) -> AuditResult:
        """Return an AuditResult for consistency with other core modules."""
        info = self.lookup()
        if info["status"] == "error":
            status = "warning"
        elif info["vpn_masked"]:
            status = "pass"
        else:
            status = "fail"
        return AuditResult(status=status, details=info)
