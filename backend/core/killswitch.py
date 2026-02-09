"""Kill switch audit module for VPN privacy auditing."""

import time
from typing import Optional

from scapy.all import IP, IPv6, Packet, sniff

from backend.core.models import AuditResult

# Interfaces commonly used by VPN tunnels
TUNNEL_INTERFACE_PREFIXES = ("tun", "wg", "proton", "tap", "utun")


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
        self.duration = duration
        self.tunnel_prefixes = tunnel_prefixes or TUNNEL_INTERFACE_PREFIXES

    def _is_tunnel_interface(self, iface: str) -> bool:
        """Return True if interface name matches a known VPN tunnel prefix."""
        return iface.lower().startswith(self.tunnel_prefixes)

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
