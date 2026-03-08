"""Tests for the external IP geolocation module."""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from backend.core.external_ip import ExternalIPChecker
from backend.core.models import AuditResult

FAKE_API_RESPONSE = json.dumps({
    "query": "185.159.157.1",
    "country": "Switzerland",
    "city": "Zurich",
    "isp": "Proton AG",
    "org": "Proton VPN",
    "as": "AS51395 Proton AG",
}).encode()

FAKE_NON_VPN_RESPONSE = json.dumps({
    "query": "203.0.113.50",
    "country": "Australia",
    "city": "Sydney",
    "isp": "Telstra Internet",
    "org": "Telstra Corp",
    "as": "AS1221 Telstra",
}).encode()

FAKE_IPINFO_RESPONSE = json.dumps({
    "ip": "185.159.157.2",
    "city": "Geneva",
    "country": "CH",
    "org": "AS51395 Proton AG",
}).encode()

FAKE_IFCONFIG_RESPONSE = json.dumps({
    "ip_addr": "185.159.157.3",
}).encode()


def _mock_urlopen(data):
    """Return a context manager mock that yields data from read()."""
    resp = MagicMock()
    resp.read.return_value = data
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestLookup:
    @patch("backend.core.external_ip.urllib.request.urlopen")
    def test_successful_lookup_returns_expected_fields(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(FAKE_API_RESPONSE)
        checker = ExternalIPChecker()
        result = checker.lookup()

        assert result["ip"] == "185.159.157.1"
        assert result["country"] == "Switzerland"
        assert result["city"] == "Zurich"
        assert result["isp"] == "Proton AG"
        assert result["org"] == "Proton VPN"
        assert result["status"] == "ok"
        assert result["source"] == "ip-api.com"
        assert result["timestamp"] is not None

    @patch("backend.core.external_ip.urllib.request.urlopen")
    def test_vpn_masked_true_for_proton(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(FAKE_API_RESPONSE)
        checker = ExternalIPChecker()
        result = checker.lookup()
        assert result["vpn_masked"] is True

    @patch("backend.core.external_ip.urllib.request.urlopen")
    def test_vpn_masked_false_for_regular_isp(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(FAKE_NON_VPN_RESPONSE)
        checker = ExternalIPChecker()
        result = checker.lookup()
        assert result["vpn_masked"] is False

    @patch("backend.core.external_ip.urllib.request.urlopen", side_effect=Exception("timeout"))
    def test_api_failure_returns_error_dict(self, _mock):
        checker = ExternalIPChecker()
        result = checker.lookup()
        assert result["status"] == "error"
        assert result["ip"] is None
        assert result["vpn_masked"] is None


class TestCache:
    @patch("backend.core.external_ip.urllib.request.urlopen")
    def test_cache_returns_same_data_within_ttl(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(FAKE_API_RESPONSE)
        checker = ExternalIPChecker(cache_ttl=60.0)

        first = checker.lookup()
        second = checker.lookup()

        assert first is second
        assert mock_urlopen.call_count == 1

    @patch("backend.core.external_ip.urllib.request.urlopen")
    @patch("backend.core.external_ip.time.monotonic")
    def test_cache_expires_after_ttl(self, mock_time, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(FAKE_API_RESPONSE)
        # monotonic() called once per lookup()
        mock_time.side_effect = [0.0, 31.0]
        checker = ExternalIPChecker(cache_ttl=30.0)

        checker.lookup()  # t=0, cache miss, API called (count=1)
        checker.lookup()  # t=31, cache expired, API called (count=2)

        assert mock_urlopen.call_count == 2


class TestRun:
    @patch("backend.core.external_ip.urllib.request.urlopen")
    def test_run_returns_audit_result_pass_for_vpn(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(FAKE_API_RESPONSE)
        checker = ExternalIPChecker()
        result = checker.run()
        assert isinstance(result, AuditResult)
        assert result.status == "pass"

    @patch("backend.core.external_ip.urllib.request.urlopen")
    def test_run_returns_fail_for_non_vpn(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(FAKE_NON_VPN_RESPONSE)
        checker = ExternalIPChecker()
        result = checker.run()
        assert result.status == "fail"

    @patch("backend.core.external_ip.urllib.request.urlopen", side_effect=Exception("err"))
    def test_run_returns_warning_on_error(self, _mock):
        checker = ExternalIPChecker()
        result = checker.run()
        assert result.status == "warning"


class TestFallback:
    @patch("backend.core.external_ip.urllib.request.urlopen")
    def test_fallback_to_ipinfo_when_primary_fails(self, mock_urlopen):
        """When ip-api.com fails, ipinfo.io should be tried next."""
        mock_urlopen.side_effect = [
            Exception("primary down"),
            _mock_urlopen(FAKE_IPINFO_RESPONSE),
        ]
        checker = ExternalIPChecker()
        result = checker.lookup()

        assert result["status"] == "ok"
        assert result["source"] == "ipinfo.io"
        assert result["ip"] == "185.159.157.2"
        assert result["country"] == "CH"
        assert result["city"] == "Geneva"

    @patch("backend.core.external_ip.urllib.request.urlopen")
    def test_fallback_to_ifconfig_when_first_two_fail(self, mock_urlopen):
        """When ip-api.com and ipinfo.io both fail, ifconfig.me should be tried."""
        mock_urlopen.side_effect = [
            Exception("primary down"),
            Exception("secondary down"),
            _mock_urlopen(FAKE_IFCONFIG_RESPONSE),
        ]
        checker = ExternalIPChecker()
        result = checker.lookup()

        assert result["status"] == "ok"
        assert result["source"] == "ifconfig.me"
        assert result["ip"] == "185.159.157.3"

    @patch("backend.core.external_ip.urllib.request.urlopen", side_effect=Exception("all down"))
    def test_all_fail_no_cache_returns_error(self, _mock):
        """When all APIs fail and no cache exists, return status error."""
        checker = ExternalIPChecker()
        result = checker.lookup()
        assert result["status"] == "error"
        assert result["ip"] is None
        assert result["source"] is None

    @patch("backend.core.external_ip.urllib.request.urlopen")
    @patch("backend.core.external_ip.time.monotonic")
    def test_all_fail_with_cache_returns_cached(self, mock_time, mock_urlopen):
        """When all APIs fail but a cached result exists, return it with status cached."""
        # First call succeeds at t=0
        mock_urlopen.side_effect = [
            _mock_urlopen(FAKE_API_RESPONSE),
            Exception("fail1"), Exception("fail2"), Exception("fail3"),
        ]
        mock_time.side_effect = [0.0, 31.0]

        checker = ExternalIPChecker(cache_ttl=30.0)
        first = checker.lookup()  # t=0, succeeds
        assert first["status"] == "ok"

        second = checker.lookup()  # t=31, cache expired, all APIs fail
        assert second["status"] == "cached"
        assert second["ip"] == "185.159.157.1"

    @patch("backend.core.external_ip.urllib.request.urlopen")
    def test_source_field_present_in_successful_response(self, mock_urlopen):
        """Successful responses should include a source field."""
        mock_urlopen.return_value = _mock_urlopen(FAKE_API_RESPONSE)
        checker = ExternalIPChecker()
        result = checker.lookup()
        assert "source" in result
        assert result["source"] == "ip-api.com"

    @patch("backend.core.external_ip.urllib.request.urlopen")
    def test_ipinfo_strips_as_prefix_from_org(self, mock_urlopen):
        """ipinfo.io org field should have AS prefix stripped."""
        mock_urlopen.side_effect = [
            Exception("primary down"),
            _mock_urlopen(FAKE_IPINFO_RESPONSE),
        ]
        checker = ExternalIPChecker()
        result = checker.lookup()
        assert result["org"] == "Proton AG"
        assert result["isp"] == "Proton AG"

    @patch("backend.core.external_ip.urllib.request.urlopen")
    def test_ifconfig_missing_fields_are_null(self, mock_urlopen):
        """ifconfig.me response should have null for missing fields."""
        mock_urlopen.side_effect = [
            Exception("primary down"),
            Exception("secondary down"),
            _mock_urlopen(FAKE_IFCONFIG_RESPONSE),
        ]
        checker = ExternalIPChecker()
        result = checker.lookup()
        assert result["country"] is None
        assert result["city"] is None
        assert result["isp"] is None
        assert result["org"] is None

    @patch("backend.core.external_ip.urllib.request.urlopen")
    def test_custom_api_url_skips_fallback(self, mock_urlopen):
        """When api_url is explicitly set, only that URL should be tried."""
        mock_urlopen.side_effect = Exception("custom api down")
        checker = ExternalIPChecker(api_url="http://custom.api/json")
        result = checker.lookup()
        # Should fail without trying fallbacks — only 1 call made
        assert mock_urlopen.call_count == 1
        assert result["status"] == "error"
