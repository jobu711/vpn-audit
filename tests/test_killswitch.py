"""Tests for the kill switch audit module."""

from unittest.mock import MagicMock, patch

import pytest

from backend.core.killswitch import KillSwitchTester, TUNNEL_INTERFACE_PREFIXES


def _make_packet(iface: str, src: str, dst: str, ts: float, ipv6: bool = False,
                  udp_sport: int = 0, udp_dport: int = 0, udp_payload: bytes = b""):
    """Create a mock packet with the given attributes."""
    from scapy.all import IP, IPv6, UDP, TCP

    pkt = MagicMock()
    pkt.sniffed_on = iface
    pkt.time = ts

    has_udp = udp_sport or udp_dport or udp_payload

    if ipv6:
        ip6_layer = MagicMock()
        ip6_layer.src = src
        ip6_layer.dst = dst
        if has_udp:
            udp_layer = MagicMock()
            udp_layer.sport = udp_sport
            udp_layer.dport = udp_dport
            udp_layer.payload = udp_payload
            pkt.haslayer.side_effect = lambda layer: layer is IPv6 or layer is UDP
            pkt.__getitem__.side_effect = lambda layer: (
                ip6_layer if layer is IPv6 else udp_layer if layer is UDP
                else (_ for _ in ()).throw(KeyError(layer)))
        else:
            pkt.haslayer.side_effect = lambda layer: layer is IPv6
            pkt.__getitem__.side_effect = lambda layer: ip6_layer if layer is IPv6 else (_ for _ in ()).throw(KeyError(layer))
    else:
        ip_layer = MagicMock()
        ip_layer.src = src
        ip_layer.dst = dst
        if has_udp:
            udp_layer = MagicMock()
            udp_layer.sport = udp_sport
            udp_layer.dport = udp_dport
            udp_layer.payload = udp_payload
            pkt.haslayer.side_effect = lambda layer: layer is IP or layer is UDP
            pkt.__getitem__.side_effect = lambda layer: (
                ip_layer if layer is IP else udp_layer if layer is UDP
                else (_ for _ in ()).throw(KeyError(layer)))
        else:
            pkt.haslayer.side_effect = lambda layer: layer is IP
            pkt.__getitem__.side_effect = lambda layer: ip_layer if layer is IP else (_ for _ in ()).throw(KeyError(layer))

    return pkt


class TestKillSwitchTesterInit:
    """Test construction and default parameters."""

    def test_default_duration(self):
        tester = KillSwitchTester()
        assert tester.duration == 30

    def test_custom_duration(self):
        tester = KillSwitchTester(duration=60)
        assert tester.duration == 60

    def test_default_tunnel_prefixes(self):
        tester = KillSwitchTester()
        assert tester.tunnel_prefixes == TUNNEL_INTERFACE_PREFIXES

    def test_custom_tunnel_prefixes(self):
        custom = ("vpn", "wg")
        tester = KillSwitchTester(tunnel_prefixes=custom)
        assert tester.tunnel_prefixes == custom


class TestIsTunnelInterface:
    """Test interface classification logic."""

    def test_tun_interface(self):
        tester = KillSwitchTester()
        assert tester._is_tunnel_interface("tun0") is True

    def test_wg_interface(self):
        tester = KillSwitchTester()
        assert tester._is_tunnel_interface("wg0") is True

    def test_proton_interface(self):
        tester = KillSwitchTester()
        assert tester._is_tunnel_interface("proton0") is True

    def test_eth_not_tunnel(self):
        tester = KillSwitchTester()
        assert tester._is_tunnel_interface("eth0") is False

    def test_case_insensitive(self):
        tester = KillSwitchTester()
        assert tester._is_tunnel_interface("TUN0") is True


class TestVpnTransportDetection:
    """Encrypted VPN traffic on physical adapters should not count as leaked."""

    @patch("backend.core.killswitch.sniff")
    def test_wireguard_traffic_on_physical_adapter_not_leaked(self, mock_sniff):
        """WireGuard packets (port 51820) on eth0 are tunnel transport, not leaks."""
        packets = [
            _make_packet("eth0", "192.168.1.5", "185.1.2.3", 1000.0,
                         udp_sport=12345, udp_dport=51820),
            _make_packet("eth0", "185.1.2.3", "192.168.1.5", 1000.5,
                         udp_sport=51820, udp_dport=12345),
        ]
        mock_sniff.return_value = packets

        result = KillSwitchTester(duration=10).run()

        assert result.status == "pass"
        assert result.details["tunnel_packets"] == 2
        assert result.details["leaked_packets"] == 0

    @patch("backend.core.killswitch.sniff")
    def test_openvpn_udp_traffic_not_leaked(self, mock_sniff):
        """OpenVPN UDP packets (port 1194) on physical adapter are not leaks."""
        packets = [
            _make_packet("eth0", "192.168.1.5", "185.1.2.3", 1000.0,
                         udp_sport=12345, udp_dport=1194),
        ]
        mock_sniff.return_value = packets

        result = KillSwitchTester(duration=10).run()

        assert result.status == "pass"
        assert result.details["tunnel_packets"] == 1
        assert result.details["leaked_packets"] == 0

    @patch("backend.core.killswitch.sniff")
    def test_wireguard_signature_on_nonstandard_port(self, mock_sniff):
        """WireGuard detected by protocol signature even on non-standard ports."""
        # WireGuard type 4 (Transport Data): 0x04 + 3 zero reserved bytes
        wg_payload = b"\x04\x00\x00\x00" + b"\x01\x02\x03\x04" + b"\x00" * 8
        packets = [
            _make_packet("eth0", "192.168.1.5", "185.1.2.3", 1000.0,
                         udp_sport=54321, udp_dport=8443, udp_payload=wg_payload),
        ]
        mock_sniff.return_value = packets

        result = KillSwitchTester(duration=10).run()

        assert result.status == "pass"
        assert result.details["tunnel_packets"] == 1
        assert result.details["leaked_packets"] == 0

    @patch("backend.core.killswitch.sniff")
    def test_non_vpn_traffic_still_leaked(self, mock_sniff):
        """Regular traffic on physical adapter is still counted as leaked."""
        packets = [
            _make_packet("eth0", "192.168.1.5", "8.8.8.8", 1000.0,
                         udp_sport=12345, udp_dport=443),
        ]
        mock_sniff.return_value = packets

        result = KillSwitchTester(duration=10).run()

        assert result.status == "fail"
        assert result.details["leaked_packets"] == 1

    @patch("backend.core.killswitch.sniff")
    def test_mix_vpn_transport_and_leaked(self, mock_sniff):
        """VPN transport excluded, but plaintext leaks still caught."""
        packets = [
            _make_packet("eth0", "192.168.1.5", "185.1.2.3", 1000.0,
                         udp_sport=12345, udp_dport=51820),
            _make_packet("eth0", "192.168.1.5", "8.8.8.8", 1001.0),
        ]
        mock_sniff.return_value = packets

        result = KillSwitchTester(duration=10).run()

        assert result.status == "fail"
        assert result.details["tunnel_packets"] == 1
        assert result.details["leaked_packets"] == 1


class TestPassScenario:
    """Kill switch works: all traffic stays on tunnel interfaces."""

    @patch("backend.core.killswitch.sniff")
    def test_all_traffic_on_tunnel(self, mock_sniff):
        packets = [
            _make_packet("tun0", "10.0.0.1", "93.184.216.34", 1000.0),
            _make_packet("wg0", "10.0.0.1", "1.1.1.1", 1000.5),
            _make_packet("tun0", "10.0.0.1", "8.8.8.8", 1001.0),
        ]
        mock_sniff.return_value = packets

        result = KillSwitchTester(duration=10).run()

        assert result.status == "pass"
        assert result.details["leaked_packets"] == 0
        assert result.details["tunnel_packets"] == 3
        assert result.details["time_to_block"] is None
        assert result.details["interfaces"] == {}

    @patch("backend.core.killswitch.sniff")
    def test_sniff_called_with_duration(self, mock_sniff):
        mock_sniff.return_value = [
            _make_packet("tun0", "10.0.0.1", "1.1.1.1", 1000.0),
        ]
        KillSwitchTester(duration=45).run()
        mock_sniff.assert_called_once_with(timeout=45)


class TestFailScenario:
    """Kill switch fails: traffic leaks on non-tunnel interfaces."""

    @patch("backend.core.killswitch.sniff")
    def test_leaked_packets_on_eth(self, mock_sniff):
        packets = [
            _make_packet("tun0", "10.0.0.1", "93.184.216.34", 1000.0),
            _make_packet("eth0", "192.168.1.5", "8.8.8.8", 1001.0),
            _make_packet("eth0", "192.168.1.5", "1.1.1.1", 1002.0),
        ]
        mock_sniff.return_value = packets

        result = KillSwitchTester(duration=10).run()

        assert result.status == "fail"
        assert result.details["leaked_packets"] == 2
        assert result.details["tunnel_packets"] == 1
        assert result.details["interfaces"] == {"eth0": 2}

    @patch("backend.core.killswitch.sniff")
    def test_leaked_on_multiple_interfaces(self, mock_sniff):
        packets = [
            _make_packet("eth0", "192.168.1.5", "8.8.8.8", 1000.0),
            _make_packet("wlan0", "192.168.1.5", "1.1.1.1", 1001.0),
        ]
        mock_sniff.return_value = packets

        result = KillSwitchTester(duration=10).run()

        assert result.status == "fail"
        assert result.details["leaked_packets"] == 2
        assert result.details["interfaces"] == {"eth0": 1, "wlan0": 1}


class TestWarningScenario:
    """Inconclusive: no traffic captured at all."""

    @patch("backend.core.killswitch.sniff")
    def test_no_packets_captured(self, mock_sniff):
        mock_sniff.return_value = []

        result = KillSwitchTester(duration=10).run()

        assert result.status == "warning"
        assert result.details["leaked_packets"] == 0
        assert "No traffic captured" in result.details["error"]

    @patch("backend.core.killswitch.sniff")
    def test_sniff_exception(self, mock_sniff):
        mock_sniff.side_effect = PermissionError("Operation not permitted")

        result = KillSwitchTester(duration=10).run()

        assert result.status == "warning"
        assert "Sniff failed" in result.details["error"]


class TestTimeToBlock:
    """Measure interval between first and last leaked packet."""

    @patch("backend.core.killswitch.sniff")
    def test_time_to_block_single_leak(self, mock_sniff):
        """Single leaked packet: time_to_block should be 0."""
        packets = [
            _make_packet("eth0", "192.168.1.5", "8.8.8.8", 1000.0),
        ]
        mock_sniff.return_value = packets

        result = KillSwitchTester(duration=10).run()

        assert result.status == "fail"
        assert result.details["time_to_block"] == 0.0

    @patch("backend.core.killswitch.sniff")
    def test_time_to_block_multiple_leaks(self, mock_sniff):
        """Time-to-block is the span from first to last leaked packet."""
        packets = [
            _make_packet("tun0", "10.0.0.1", "1.1.1.1", 999.0),
            _make_packet("eth0", "192.168.1.5", "8.8.8.8", 1000.0),
            _make_packet("eth0", "192.168.1.5", "8.8.4.4", 1002.5),
            _make_packet("eth0", "192.168.1.5", "1.1.1.1", 1005.0),
        ]
        mock_sniff.return_value = packets

        result = KillSwitchTester(duration=10).run()

        assert result.status == "fail"
        assert result.details["time_to_block"] == 5.0

    @patch("backend.core.killswitch.sniff")
    def test_no_time_to_block_when_no_leaks(self, mock_sniff):
        packets = [
            _make_packet("tun0", "10.0.0.1", "1.1.1.1", 1000.0),
        ]
        mock_sniff.return_value = packets

        result = KillSwitchTester(duration=10).run()

        assert result.status == "pass"
        assert result.details["time_to_block"] is None


class TestPacketExtraction:
    """Test edge cases in packet information extraction."""

    @patch("backend.core.killswitch.sniff")
    def test_packet_without_ip_layer_ignored(self, mock_sniff):
        """Non-IP packets (e.g., ARP) should be silently skipped."""
        pkt = MagicMock()
        pkt.sniffed_on = "eth0"
        pkt.time = 1000.0
        pkt.haslayer = lambda layer: False  # no IP or IPv6

        mock_sniff.return_value = [pkt]

        result = KillSwitchTester(duration=5).run()

        # No IP packets means nothing to categorise -- treated like no traffic
        # but total_packets is still 1
        assert result.status == "pass"
        assert result.details["total_packets"] == 1
        assert result.details["leaked_packets"] == 0
        assert result.details["tunnel_packets"] == 0

    @patch("backend.core.killswitch.sniff")
    def test_missing_sniffed_on_attribute(self, mock_sniff):
        """Packet without sniffed_on treated as non-tunnel (empty string)."""
        pkt = _make_packet("", "192.168.1.5", "8.8.8.8", 1000.0)
        pkt.sniffed_on = None  # override to simulate missing attribute

        mock_sniff.return_value = [pkt]

        result = KillSwitchTester(duration=5).run()

        # Empty/None iface is not a tunnel prefix, so it counts as leaked
        assert result.status == "fail"
        assert result.details["leaked_packets"] == 1
