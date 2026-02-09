"""Kill switch audit module for VPN privacy auditing."""

from typing import Optional

from scapy.all import IP, IPv6, UDP, TCP, Packet, sniff

from backend.core.interfaces import is_tunnel_interface, TUNNEL_INTERFACE_PREFIXES
from backend.core.models import AuditResult

# Ports used for encrypted VPN tunnel transport (expected on physical adapters)
_VPN_TRANSPORT_PORTS: frozenset[int] = frozenset({51820, 1194})  # WireGuard, OpenVPN


class KillSwitchTester:
    """Monitor network interfaces for non-tunnel traffic to audit VPN kill switch.

    The user manually disconnects the VPN during the monitoring window.
    This tool captures packets and reports whether any traffic escaped
    on non-VPN interfaces, measuring time-to-block if leaks occur.
    """

    def __init__(
        self,
        duration: int = 30,
        tunnel_prefixes: Optional[tuple[str, ...]] = None,
    ):
        """Initialise the kill switch tester.

        Args:
            duration: Seconds to monitor traffic after a VPN disconnect event.
            tunnel_prefixes: Interface name prefixes considered VPN tunnels.
        """
        self.duration = duration
        self.tunnel_prefixes = tunnel_prefixes or TUNNEL_INTERFACE_PREFIXES

    def _is_tunnel_interface(self, iface: str) -> bool:
        """Return True if interface name matches a known VPN tunnel prefix."""
        return is_tunnel_interface(iface, tunnel_prefixes=self.tunnel_prefixes)

    @staticmethod
    def _is_vpn_transport(packet: Packet) -> bool:
        """Return True if packet is encrypted VPN tunnel traffic.

        Encrypted VPN traffic (WireGuard, OpenVPN) naturally flows through
        the physical adapter and is not a privacy leak.  WireGuard is
        detected by protocol signature (works on any port).
        """
        if packet.haslayer(UDP):
            udp = packet[UDP]
            # Known VPN ports
            if udp.dport in _VPN_TRANSPORT_PORTS or udp.sport in _VPN_TRANSPORT_PORTS:
                return True
            # WireGuard protocol signature: msg type 1-4 + 3 reserved zero bytes
            try:
                payload = bytes(udp.payload)
            except (TypeError, AttributeError):
                payload = b""
            if (len(payload) >= 4
                    and payload[0] in (1, 2, 3, 4)
                    and payload[1:4] == b"\x00\x00\x00"):
                return True
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.dport == 1194 or tcp.sport == 1194:
                return True
        return False

    def _extract_info(self, packet: Packet) -> Optional[dict]:
        """Extract interface name, timestamp, and src/dst from a packet."""
        iface = getattr(packet, "sniffed_on", None) or ""
        ts = float(getattr(packet, "time", 0))

        src, dst = None, None
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
        elif packet.haslayer(IPv6):
            src = packet[IPv6].src
            dst = packet[IPv6].dst

        if src is None:
            return None

        return {"interface": str(iface), "time": ts, "src": src, "dst": dst}

    def run(self) -> AuditResult:
        """Run the kill switch audit: sniff all interfaces and analyse leaks.

        Returns:
            AuditResult with status pass/fail/warning and detailed metrics.
        """
        try:
            packets = sniff(timeout=self.duration)
        except Exception as exc:
            return AuditResult(
                status="warning",
                details={"error": f"Sniff failed: {exc}"},
            )

        if not packets:
            return AuditResult(
                status="warning",
                details={
                    "error": "No traffic captured during monitoring window",
                    "duration": self.duration,
                    "leaked_packets": 0,
                    "interfaces": {},
                },
            )

        # Categorise packets by interface
        leaked: list[dict] = []
        tunnel: list[dict] = []

        for pkt in packets:
            info = self._extract_info(pkt)
            if info is None:
                continue
            if self._is_tunnel_interface(info["interface"]):
                tunnel.append(info)
            elif self._is_vpn_transport(pkt):
                tunnel.append(info)
            else:
                leaked.append(info)

        # Build per-interface packet counts
        iface_counts: dict[str, int] = {}
        for info in leaked:
            iface_counts[info["interface"]] = iface_counts.get(info["interface"], 0) + 1

        # Compute time-to-block: time between first and last leaked packet
        time_to_block: Optional[float] = None
        if leaked:
            timestamps = [info["time"] for info in leaked]
            first = min(timestamps)
            last = max(timestamps)
            time_to_block = round(last - first, 4)

        details = {
            "duration": self.duration,
            "total_packets": len(packets),
            "tunnel_packets": len(tunnel),
            "leaked_packets": len(leaked),
            "interfaces": iface_counts,
            "time_to_block": time_to_block,
        }

        if leaked:
            return AuditResult(status="fail", details=details)

        return AuditResult(status="pass", details=details)
