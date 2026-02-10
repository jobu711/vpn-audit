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
