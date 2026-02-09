"""Tests for the Traffic Fingerprinting Module."""

from unittest.mock import MagicMock, patch

import pytest

from backend.core.fingerprint import (
    HTTPS_PORT,
    OPENVPN_UDP_PORT,
    WIREGUARD_PORT,
    CaptureConfig,
    TrafficFingerprinter,
    TrafficStats,
)
from backend.core.models import AuditResult


# ---------------------------------------------------------------------------
# Helpers to build mock packets
# ---------------------------------------------------------------------------

def _make_packet(proto="tcp", sport=12345, dport=443, size=200, time=0.0, payload=b""):
    """Create a mock packet with the given characteristics."""
    pkt = MagicMock()
    pkt.time = time
    pkt.__len__ = lambda self: size

    ip_layer = MagicMock()

    def has_layer(layer_cls):
        name = layer_cls.__name__
        if name == "IP":
            return True
        if name == "UDP":
            return proto == "udp"
        if name == "TCP":
            return proto == "tcp"
        return False

    pkt.haslayer = has_layer

    if proto == "udp":
        udp_layer = MagicMock()
        udp_layer.sport = sport
        udp_layer.dport = dport
        pkt.__getitem__ = lambda self, cls: (
            udp_layer if cls.__name__ == "UDP" else ip_layer
        )
    elif proto == "tcp":
        tcp_layer = MagicMock()
        tcp_layer.sport = sport
        tcp_layer.dport = dport
        tcp_layer.payload = payload
        pkt.__getitem__ = lambda self, cls: (
            tcp_layer if cls.__name__ == "TCP" else ip_layer
        )
    else:
        pkt.__getitem__ = lambda self, cls: ip_layer

    return pkt


def _make_wireguard_packet(time=0.0):
    return _make_packet(proto="udp", dport=WIREGUARD_PORT, sport=54321, time=time)


def _make_openvpn_udp_packet(time=0.0):
    return _make_packet(proto="udp", dport=OPENVPN_UDP_PORT, sport=54321, time=time)


def _make_openvpn_tcp_packet(time=0.0):
    # OpenVPN over TCP: 2-byte length prefix + opcode byte.
    # opcode 7 (P_CONTROL_HARD_RESET_CLIENT_V2) shifted left 3 bits = 0x38
    payload = b"\x00\x10\x38" + b"\x00" * 16
    return _make_packet(
        proto="tcp", dport=HTTPS_PORT, sport=54321, time=time, payload=payload
    )


def _make_https_packet(time=0.0):
    return _make_packet(proto="tcp", dport=HTTPS_PORT, sport=54321, time=time)


# ---------------------------------------------------------------------------
# WireGuard detection tests
# ---------------------------------------------------------------------------

class TestWireGuardDetection:
    def test_wireguard_dport_detected(self):
        fp = TrafficFingerprinter()
        packets = [_make_wireguard_packet(time=i * 0.01) for i in range(20)]
        stats = fp._analyze_packets(packets)
        assert stats.wireguard_packets == 20
        assert stats.total_packets == 20

    def test_wireguard_sport_detected(self):
        fp = TrafficFingerprinter()
        pkt = _make_packet(proto="udp", sport=WIREGUARD_PORT, dport=54321, time=0.0)
        stats = fp._analyze_packets([pkt])
        assert stats.wireguard_packets == 1

    def test_wireguard_causes_fail(self):
        fp = TrafficFingerprinter()
        # All packets are WireGuard -> ratio = 1.0 -> fail
        packets = [_make_wireguard_packet(time=i * 0.01) for i in range(10)]
        result = fp._build_result(fp._analyze_packets(packets))
        assert result.status == "fail"
        assert "WireGuard" in result.details["reason"]


# ---------------------------------------------------------------------------
# OpenVPN detection tests
# ---------------------------------------------------------------------------

class TestOpenVPNDetection:
    def test_openvpn_udp_detected(self):
        fp = TrafficFingerprinter()
        packets = [_make_openvpn_udp_packet(time=i * 0.01) for i in range(5)]
        stats = fp._analyze_packets(packets)
        assert stats.openvpn_packets == 5

    def test_openvpn_tcp_detected(self):
        fp = TrafficFingerprinter()
        packets = [_make_openvpn_tcp_packet(time=i * 0.01) for i in range(5)]
        stats = fp._analyze_packets(packets)
        assert stats.openvpn_packets == 5

    def test_openvpn_causes_fail(self):
        fp = TrafficFingerprinter()
        packets = [_make_openvpn_udp_packet(time=i * 0.01) for i in range(10)]
        result = fp._build_result(fp._analyze_packets(packets))
        assert result.status == "fail"
        assert "OpenVPN" in result.details["reason"]


# ---------------------------------------------------------------------------
# Normal HTTPS traffic tests
# ---------------------------------------------------------------------------

class TestHTTPSTraffic:
    def test_https_classified_correctly(self):
        fp = TrafficFingerprinter()
        packets = [_make_https_packet(time=i * 0.01) for i in range(50)]
        stats = fp._analyze_packets(packets)
        assert stats.https_packets == 50
        assert stats.wireguard_packets == 0
        assert stats.openvpn_packets == 0

    def test_pure_https_passes(self):
        fp = TrafficFingerprinter()
        packets = [_make_https_packet(time=i * 0.01) for i in range(50)]
        result = fp._build_result(fp._analyze_packets(packets))
        assert result.status == "pass"
        assert "indistinguishable" in result.details["reason"]


# ---------------------------------------------------------------------------
# Edge-case tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_no_packets_warning(self):
        fp = TrafficFingerprinter()
        result = fp._build_result(TrafficStats())
        assert result.status == "warning"
        assert "No packets" in result.details["reason"]

    def test_non_ip_packets_ignored(self):
        """Packets without IP layer should be skipped entirely."""
        pkt = MagicMock()
        pkt.haslayer = lambda cls: False
        fp = TrafficFingerprinter()
        stats = fp._analyze_packets([pkt])
        assert stats.total_packets == 0

    def test_low_vpn_ratio_warning(self):
        """A small number of VPN packets among HTTPS should yield warning."""
        fp = TrafficFingerprinter()
        https = [_make_https_packet(time=i * 0.01) for i in range(97)]
        vpn = [_make_wireguard_packet(time=97 * 0.01 + i * 0.01) for i in range(4)]
        # 4 / 101 ~ 3.96% -> above WARNING_THRESHOLD but below DETECTION_THRESHOLD
        stats = fp._analyze_packets(https + vpn)
        result = fp._build_result(stats)
        assert result.status == "warning"

    def test_mixed_protocols_fail(self):
        """Both WireGuard and OpenVPN detected should list both."""
        fp = TrafficFingerprinter()
        packets = (
            [_make_wireguard_packet(time=i * 0.01) for i in range(10)]
            + [_make_openvpn_udp_packet(time=10 * 0.01 + i * 0.01) for i in range(10)]
        )
        result = fp._build_result(fp._analyze_packets(packets))
        assert result.status == "fail"
        assert "WireGuard" in result.details["reason"]
        assert "OpenVPN" in result.details["reason"]

    def test_single_packet_stats(self):
        """Single packet should produce zero stdev."""
        fp = TrafficFingerprinter()
        stats = fp._analyze_packets([_make_https_packet(time=0.0)])
        result = fp._build_result(stats)
        assert result.details["size_stdev"] == 0.0

    def test_config_defaults(self):
        config = CaptureConfig()
        assert config.count == 100
        assert config.timeout == 30
        assert config.iface is None

    def test_custom_config(self):
        config = CaptureConfig(count=50, timeout=10, iface="eth0")
        fp = TrafficFingerprinter(config=config)
        assert fp.config.count == 50
        assert fp.config.iface == "eth0"


# ---------------------------------------------------------------------------
# run() integration tests (with mocked sniff)
# ---------------------------------------------------------------------------

class TestRunMethod:
    @patch("backend.core.fingerprint.sniff")
    def test_run_pass(self, mock_sniff):
        """run() returns pass when only HTTPS traffic is captured."""
        mock_sniff.return_value = [
            _make_https_packet(time=i * 0.01) for i in range(20)
        ]
        fp = TrafficFingerprinter(CaptureConfig(count=20, timeout=5))
        result = fp.run()
        assert isinstance(result, AuditResult)
        assert result.status == "pass"
        mock_sniff.assert_called_once()

    @patch("backend.core.fingerprint.sniff")
    def test_run_fail_wireguard(self, mock_sniff):
        """run() returns fail when WireGuard traffic dominates."""
        mock_sniff.return_value = [
            _make_wireguard_packet(time=i * 0.01) for i in range(20)
        ]
        result = TrafficFingerprinter().run()
        assert result.status == "fail"
        assert "WireGuard" in result.details["reason"]

    @patch("backend.core.fingerprint.sniff")
    def test_run_fail_openvpn(self, mock_sniff):
        """run() returns fail when OpenVPN traffic dominates."""
        mock_sniff.return_value = [
            _make_openvpn_udp_packet(time=i * 0.01) for i in range(20)
        ]
        result = TrafficFingerprinter().run()
        assert result.status == "fail"
        assert "OpenVPN" in result.details["reason"]

    @patch("backend.core.fingerprint.sniff")
    def test_run_warning_empty(self, mock_sniff):
        """run() returns warning when no packets are captured."""
        mock_sniff.return_value = []
        result = TrafficFingerprinter().run()
        assert result.status == "warning"
        assert "No packets" in result.details["reason"]

    @patch("backend.core.fingerprint.sniff")
    def test_run_passes_config_to_sniff(self, mock_sniff):
        """Verify sniff is called with the right parameters."""
        mock_sniff.return_value = []
        config = CaptureConfig(count=50, timeout=15, iface="wlan0")
        TrafficFingerprinter(config).run()
        mock_sniff.assert_called_once_with(count=50, timeout=15, iface="wlan0")

    @patch("backend.core.fingerprint.sniff")
    def test_run_no_iface_omits_param(self, mock_sniff):
        """When iface is None, it should not be passed to sniff."""
        mock_sniff.return_value = []
        TrafficFingerprinter(CaptureConfig(count=10, timeout=5)).run()
        call_kwargs = mock_sniff.call_args[1]
        assert "iface" not in call_kwargs

    @patch("backend.core.fingerprint.sniff")
    def test_run_result_has_timestamp(self, mock_sniff):
        """AuditResult should always include a timestamp."""
        mock_sniff.return_value = [_make_https_packet(time=0.0)]
        result = TrafficFingerprinter().run()
        assert result.timestamp is not None
        assert len(result.timestamp) > 0
