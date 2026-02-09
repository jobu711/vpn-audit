"""Traffic Fingerprinting Module.

Captures network traffic and analyzes packet signatures to determine
whether VPN protocol traffic is distinguishable from regular HTTPS.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from scapy.all import IP, TCP, UDP, sniff

from backend.core.models import AuditResult

# Protocol signature constants
WIREGUARD_PORT = 51820
OPENVPN_UDP_PORT = 1194
HTTPS_PORT = 443

# OpenVPN magic bytes: first byte of an OpenVPN control packet
OPENVPN_OPCODES = {0x38, 0x40}  # P_CONTROL_HARD_RESET_CLIENT_V2, P_CONTROL_V1

# Typical HTTPS packet size range (TLS record layer)
HTTPS_SIZE_MIN = 40
HTTPS_SIZE_MAX = 1500

# Thresholds
DETECTION_THRESHOLD = 0.10  # 10% VPN-signature packets triggers "fail"
WARNING_THRESHOLD = 0.03    # 3% triggers "warning"


@dataclass
class CaptureConfig:
    """Configuration for packet capture."""

    count: int = 100
    timeout: int = 30
    iface: str | None = None


@dataclass
class TrafficStats:
    """Aggregated statistics from captured packets."""

    total_packets: int = 0
    wireguard_packets: int = 0
    openvpn_packets: int = 0
    https_packets: int = 0
    other_packets: int = 0
    packet_sizes: list[int] = field(default_factory=list)
    inter_arrival_times: list[float] = field(default_factory=list)


class TrafficFingerprinter:
    """Analyzes captured traffic for VPN protocol fingerprints."""

    def __init__(self, config: CaptureConfig | None = None) -> None:
        self.config = config or CaptureConfig()

    def run(self) -> AuditResult:
        """Capture packets and analyze for VPN protocol signatures."""
        packets = self._capture_packets()
        stats = self._analyze_packets(packets)
        return self._build_result(stats)

    def _capture_packets(self) -> list:
        """Capture packets using Scapy sniff."""
        kwargs: dict[str, Any] = {
            "count": self.config.count,
            "timeout": self.config.timeout,
        }
        if self.config.iface:
            kwargs["iface"] = self.config.iface
        return list(sniff(**kwargs))

    def _analyze_packets(self, packets: list) -> TrafficStats:
        """Classify each packet and compute traffic statistics."""
        stats = TrafficStats()
        prev_time: float | None = None

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue

            stats.total_packets += 1
            stats.packet_sizes.append(len(pkt))

            # Inter-arrival time
            pkt_time = float(pkt.time)
            if prev_time is not None:
                stats.inter_arrival_times.append(pkt_time - prev_time)
            prev_time = pkt_time

            # Classify packet
            if pkt.haslayer(UDP):
                udp = pkt[UDP]
                if udp.dport == WIREGUARD_PORT or udp.sport == WIREGUARD_PORT:
                    stats.wireguard_packets += 1
                elif udp.dport == OPENVPN_UDP_PORT or udp.sport == OPENVPN_UDP_PORT:
                    stats.openvpn_packets += 1
                else:
                    stats.other_packets += 1
            elif pkt.haslayer(TCP):
                tcp = pkt[TCP]
                if self._is_openvpn_tcp(pkt, tcp):
                    stats.openvpn_packets += 1
                elif tcp.dport == HTTPS_PORT or tcp.sport == HTTPS_PORT:
                    stats.https_packets += 1
                else:
                    stats.other_packets += 1
            else:
                stats.other_packets += 1

        return stats

    @staticmethod
    def _is_openvpn_tcp(pkt: Any, tcp: Any) -> bool:
        """Detect OpenVPN over TCP port 443 by checking opcode bytes."""
        if tcp.dport != HTTPS_PORT and tcp.sport != HTTPS_PORT:
            return False
        payload = bytes(tcp.payload)
        if len(payload) < 3:
            return False
        # OpenVPN over TCP prepends a 2-byte length; opcode is at byte 2
        opcode = (payload[2] >> 3) & 0x1F
        return opcode in {7, 8}  # P_CONTROL_HARD_RESET_CLIENT_V2/V3

    def _build_result(self, stats: TrafficStats) -> AuditResult:
        """Determine audit status from traffic statistics."""
        details: dict[str, Any] = {
            "total_packets": stats.total_packets,
            "wireguard_packets": stats.wireguard_packets,
            "openvpn_packets": stats.openvpn_packets,
            "https_packets": stats.https_packets,
            "other_packets": stats.other_packets,
        }

        if stats.total_packets == 0:
            return AuditResult(
                status="warning",
                details={**details, "reason": "No packets captured"},
            )

        # Size distribution stats
        if stats.packet_sizes:
            details["size_mean"] = round(statistics.mean(stats.packet_sizes), 2)
            details["size_stdev"] = (
                round(statistics.stdev(stats.packet_sizes), 2)
                if len(stats.packet_sizes) > 1
                else 0.0
            )

        # Timing stats
        if stats.inter_arrival_times:
            details["timing_mean_ms"] = round(
                statistics.mean(stats.inter_arrival_times) * 1000, 2
            )

        vpn_packets = stats.wireguard_packets + stats.openvpn_packets
        vpn_ratio = vpn_packets / stats.total_packets

        details["vpn_ratio"] = round(vpn_ratio, 4)

        if vpn_ratio >= DETECTION_THRESHOLD:
            protocols = []
            if stats.wireguard_packets:
                protocols.append("WireGuard")
            if stats.openvpn_packets:
                protocols.append("OpenVPN")
            details["reason"] = f"VPN protocol detected: {', '.join(protocols)}"
            return AuditResult(status="fail", details=details)

        if vpn_ratio >= WARNING_THRESHOLD:
            details["reason"] = "Low-level VPN signature traces detected"
            return AuditResult(status="warning", details=details)

        details["reason"] = "Traffic indistinguishable from normal HTTPS"
        return AuditResult(status="pass", details=details)
