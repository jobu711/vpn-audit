"""External IP geolocation lookup with caching and VPN masking detection."""

import json
import re
import time
import urllib.request
from datetime import datetime, timezone

from backend.core.models import AuditResult

# Known VPN provider patterns (matched case-insensitively against ISP/org fields)
_DEFAULT_VPN_PATTERNS = [
    "proton",
    "datacamp",
    "pv-sl-hosted",
    "mullvad",
    "nordvpn",
    "expressvpn",
    "surfshark",
    "private internet access",
    "cyberghost",
    "windscribe",
    "ivpn",
]

# Ordered fallback API sources: (url, normalizer_function_name)
_API_SOURCES = [
    {
        "url": "http://ip-api.com/json/?fields=query,country,city,isp,org,as",
        "name": "ip-api.com",
    },
    {
        "url": "https://ipinfo.io/json",
        "name": "ipinfo.io",
    },
    {
        "url": "https://ifconfig.me/all.json",
        "name": "ifconfig.me",
    },
]

# Regex to strip AS number prefix like "AS12345 " from org strings
_AS_PREFIX_RE = re.compile(r"^AS\d+\s+")


def _normalize_ip_api(data: dict) -> dict:
    """Normalize ip-api.com response to standard format."""
    return {
        "ip": data.get("query"),
        "country": data.get("country"),
        "city": data.get("city"),
        "isp": data.get("isp", ""),
        "org": data.get("org", ""),
    }


def _normalize_ipinfo(data: dict) -> dict:
    """Normalize ipinfo.io response to standard format."""
    org = data.get("org", "")
    # Strip AS number prefix (e.g. "AS51395 Proton AG" -> "Proton AG")
    if org:
        org = _AS_PREFIX_RE.sub("", org)
    return {
        "ip": data.get("ip"),
        "country": data.get("country"),
        "city": data.get("city"),
        "isp": org,  # ipinfo has no separate isp field; use org
        "org": org,
    }


def _normalize_ifconfig(data: dict) -> dict:
    """Normalize ifconfig.me response to standard format."""
    return {
        "ip": data.get("ip_addr"),
        "country": None,
        "city": None,
        "isp": None,
        "org": None,
    }


_NORMALIZERS = {
    "ip-api.com": _normalize_ip_api,
    "ipinfo.io": _normalize_ipinfo,
    "ifconfig.me": _normalize_ifconfig,
}


class ExternalIPChecker:
    """Fetches external IP info with TTL caching and multi-API fallback."""

    def __init__(
        self,
        cache_ttl: float = 30.0,
        vpn_patterns: list[str] | None = None,
        api_url: str = _API_SOURCES[0]["url"],
        timeout: float = 5.0,
    ):
        self.cache_ttl = cache_ttl
        self.vpn_patterns = [p.lower() for p in (vpn_patterns or _DEFAULT_VPN_PATTERNS)]
        self.api_url = api_url
        self.timeout = timeout
        # When api_url is explicitly overridden, only use that single URL
        self._use_fallback = api_url == _API_SOURCES[0]["url"]
        self._cache: dict | None = None
        self._cache_time: float = 0.0

    def lookup(self) -> dict:
        """Return external IP info dict, using cache if still valid."""
        now = time.monotonic()
        if self._cache is not None and (now - self._cache_time) < self.cache_ttl:
            return self._cache

        result = None

        if self._use_fallback:
            result = self._try_fallback_chain()
        else:
            result = self._try_single_api(self.api_url, "ip-api.com")

        if result is None:
            # All APIs failed — return cached result if available
            if self._cache is not None:
                cached = dict(self._cache)
                cached["status"] = "cached"
                cached["timestamp"] = datetime.now(timezone.utc).isoformat()
                return cached
            # No cache either
            result = {
                "ip": None,
                "country": None,
                "city": None,
                "isp": None,
                "org": None,
                "vpn_masked": None,
                "source": None,
                "status": "error",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        self._cache = result
        self._cache_time = now
        return result

    def _try_fallback_chain(self) -> dict | None:
        """Try each API source in order, return first successful result or None."""
        for source in _API_SOURCES:
            result = self._try_single_api(source["url"], source["name"])
            if result is not None:
                return result
        return None

    def _try_single_api(self, url: str, source_name: str) -> dict | None:
        """Try a single API, return normalized result dict or None on failure."""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vpn-audit/0.1"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())

            normalizer = _NORMALIZERS.get(source_name, _normalize_ip_api)
            fields = normalizer(data)

            isp = fields.get("isp")
            org = fields.get("org")
            vpn_masked = self._check_vpn(isp or "", org or "")

            return {
                "ip": fields["ip"],
                "country": fields["country"],
                "city": fields["city"],
                "isp": isp,
                "org": org,
                "vpn_masked": vpn_masked,
                "source": source_name,
                "status": "ok",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception:
            return None

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
