"""Unit tests for the leak detection module."""

import socket
from collections import namedtuple
from unittest.mock import MagicMock, patch

import pytest

from backend.core.leak_detect import LeakDetector

# Reusable psutil address struct
SnicAddr = namedtuple("snicaddr", ["family", "address", "netmask", "broadcast", "ptp"])


def _make_snic(family, address, netmask=None, broadcast=None, ptp=None):
    return SnicAddr(family, address, netmask, broadcast, ptp)


# ---------------------------------------------------------------------------
# Helper: build a fake Scapy packet with IP.dst and DNS layer
# ---------------------------------------------------------------------------

def _dns_packet(dst_ip: str):
    pkt = MagicMock()
    pkt.haslayer.side_effect = lambda layer: True
    ip_layer = MagicMock()
    ip_layer.dst = dst_ip
    pkt.__getitem__ = lambda self, layer: ip_layer
    return pkt


# ===== DNS leak tests =====


class TestCheckDns:
    """Tests for LeakDetector.check_dns."""

    @patch("backend.core.leak_detect.sniff")
    def test_pass_when_all_dns_goes_through_vpn(self, mock_sniff):
        mock_sniff.return_value = [_dns_packet("10.2.0.1")]
        detector = LeakDetector(vpn_dns=["10.2.0.1"])
        result = detector.check_dns()
        assert result.status == "pass"
        assert result.details["leaked_servers"] == []

    @patch("backend.core.leak_detect.sniff")
    def test_fail_when_dns_leaks_to_external(self, mock_sniff):
        mock_sniff.return_value = [
            _dns_packet("10.2.0.1"),
            _dns_packet("8.8.8.8"),
        ]
        detector = LeakDetector(vpn_dns=["10.2.0.1"])
        result = detector.check_dns()
        assert result.status == "fail"
        assert "8.8.8.8" in result.details["leaked_servers"]

    @patch("backend.core.leak_detect.sniff")
    def test_pass_when_no_packets_captured(self, mock_sniff):
        """No DNS on capturable interfaces means DNS is inside the VPN tunnel."""
        mock_sniff.return_value = []
        detector = LeakDetector()
        result = detector.check_dns()
        assert result.status == "pass"
        assert result.details["leaked_servers"] == []

    @patch("backend.core.leak_detect.sniff")
    def test_warning_when_sniff_raises(self, mock_sniff):
        mock_sniff.side_effect = PermissionError("no privileges")
        detector = LeakDetector()
        result = detector.check_dns()
        assert result.status == "warning"
        assert "no privileges" in result.details["error"]

    @patch("backend.core.leak_detect.sniff")
    def test_deduplicates_leaked_servers(self, mock_sniff):
        mock_sniff.return_value = [
            _dns_packet("8.8.8.8"),
            _dns_packet("8.8.8.8"),
        ]
        detector = LeakDetector(vpn_dns=["10.2.0.1"])
        result = detector.check_dns()
        assert result.status == "fail"
        assert result.details["leaked_servers"] == ["8.8.8.8"]


# ===== WebRTC leak tests =====


class TestCheckWebrtc:
    """Tests for LeakDetector.check_webrtc."""

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    def test_pass_when_only_private_ips(self, mock_addrs):
        mock_addrs.return_value = {
            "eth0": [_make_snic(socket.AF_INET, "192.168.1.10")],
        }
        result = LeakDetector().check_webrtc()
        assert result.status == "pass"
        assert result.details["public_ips"] == []

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    def test_fail_when_public_ip_on_non_tunnel(self, mock_addrs):
        mock_addrs.return_value = {
            "eth0": [_make_snic(socket.AF_INET, "93.184.216.34")],
        }
        result = LeakDetector().check_webrtc()
        assert result.status == "fail"
        assert "93.184.216.34" in result.details["public_ips"]

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    def test_pass_when_public_ip_on_tunnel(self, mock_addrs):
        mock_addrs.return_value = {
            "tun0": [_make_snic(socket.AF_INET, "203.0.113.5")],
        }
        result = LeakDetector().check_webrtc()
        assert result.status == "pass"

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    def test_ignores_loopback(self, mock_addrs):
        mock_addrs.return_value = {
            "lo": [_make_snic(socket.AF_INET, "127.0.0.1")],
        }
        result = LeakDetector().check_webrtc()
        assert result.status == "pass"

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    def test_warning_on_exception(self, mock_addrs):
        mock_addrs.side_effect = OSError("permission denied")
        result = LeakDetector().check_webrtc()
        assert result.status == "warning"
        assert "permission denied" in result.details["error"]


# ===== IPv6 leak tests =====


class TestCheckIpv6:
    """Tests for LeakDetector.check_ipv6."""

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    def test_pass_when_only_link_local_ipv6(self, mock_addrs):
        mock_addrs.return_value = {
            "eth0": [_make_snic(socket.AF_INET6, "fe80::1%eth0")],
        }
        result = LeakDetector().check_ipv6()
        assert result.status == "pass"
        assert result.details["ipv6_leaks"] == []

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    def test_fail_when_global_ipv6_on_non_tunnel(self, mock_addrs):
        mock_addrs.return_value = {
            "eth0": [_make_snic(socket.AF_INET6, "2001:db8::1")],
        }
        result = LeakDetector().check_ipv6()
        assert result.status == "fail"
        leaks = result.details["ipv6_leaks"]
        assert len(leaks) == 1
        assert leaks[0]["interface"] == "eth0"
        assert leaks[0]["address"] == "2001:db8::1"

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    def test_pass_when_global_ipv6_on_tunnel(self, mock_addrs):
        mock_addrs.return_value = {
            "tun0": [_make_snic(socket.AF_INET6, "2001:db8::1")],
        }
        result = LeakDetector().check_ipv6()
        assert result.status == "pass"

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    def test_ignores_loopback_ipv6(self, mock_addrs):
        mock_addrs.return_value = {
            "lo": [_make_snic(socket.AF_INET6, "::1")],
        }
        result = LeakDetector().check_ipv6()
        assert result.status == "pass"

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    def test_warning_on_exception(self, mock_addrs):
        mock_addrs.side_effect = OSError("no access")
        result = LeakDetector().check_ipv6()
        assert result.status == "warning"


# ===== Aggregated run() tests =====


class TestRun:
    """Tests for LeakDetector.run (aggregation logic)."""

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    @patch("backend.core.leak_detect.sniff")
    def test_all_pass(self, mock_sniff, mock_addrs):
        mock_sniff.return_value = [_dns_packet("10.2.0.1")]
        mock_addrs.return_value = {
            "tun0": [_make_snic(socket.AF_INET, "10.0.0.1")],
            "lo": [_make_snic(socket.AF_INET, "127.0.0.1")],
        }
        result = LeakDetector(vpn_dns=["10.2.0.1"]).run()
        assert result.status == "pass"
        assert "dns" in result.details
        assert "webrtc" in result.details
        assert "ipv6" in result.details

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    @patch("backend.core.leak_detect.sniff")
    def test_fail_propagates(self, mock_sniff, mock_addrs):
        # DNS leaks to external server
        mock_sniff.return_value = [_dns_packet("8.8.8.8")]
        mock_addrs.return_value = {
            "lo": [_make_snic(socket.AF_INET, "127.0.0.1")],
        }
        result = LeakDetector(vpn_dns=["10.2.0.1"]).run()
        assert result.status == "fail"

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    @patch("backend.core.leak_detect.sniff")
    def test_warning_when_no_fail_but_inconclusive(self, mock_sniff, mock_addrs):
        # DNS sniff fails (warning), other checks pass
        mock_sniff.side_effect = PermissionError("no privileges")
        mock_addrs.return_value = {
            "lo": [_make_snic(socket.AF_INET, "127.0.0.1")],
        }
        result = LeakDetector().run()
        assert result.status == "warning"

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    @patch("backend.core.leak_detect.sniff")
    def test_all_pass_when_dns_tunneled(self, mock_sniff, mock_addrs):
        # No DNS captured (tunneled) + no leaks = all pass
        mock_sniff.return_value = []
        mock_addrs.return_value = {
            "lo": [_make_snic(socket.AF_INET, "127.0.0.1")],
        }
        result = LeakDetector().run()
        assert result.status == "pass"

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    @patch("backend.core.leak_detect.sniff")
    def test_fail_takes_precedence_over_warning(self, mock_sniff, mock_addrs):
        # DNS sniff fails (warning) + WebRTC fail
        mock_sniff.side_effect = PermissionError("no privileges")
        mock_addrs.return_value = {
            "eth0": [_make_snic(socket.AF_INET, "93.184.216.34")],
        }
        result = LeakDetector(vpn_dns=["10.2.0.1"]).run()
        assert result.status == "fail"

    @patch("backend.core.leak_detect.psutil.net_if_addrs")
    @patch("backend.core.leak_detect.sniff")
    def test_result_has_timestamp(self, mock_sniff, mock_addrs):
        mock_sniff.return_value = [_dns_packet("10.2.0.1")]
        mock_addrs.return_value = {}
        result = LeakDetector(vpn_dns=["10.2.0.1"]).run()
        assert result.timestamp is not None
