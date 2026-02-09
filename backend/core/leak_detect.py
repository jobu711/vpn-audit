"""Leak detection module for VPN privacy auditing."""

import ipaddress
import socket
from typing import Optional

import psutil
from scapy.all import DNS, IP, sniff

from backend.core.models import AuditResult

# Default known VPN DNS resolver IPs (Proton VPN)
DEFAULT_VPN_DNS = ["10.2.0.1"]

# Interfaces commonly used by VPN tunnels
TUNNEL_INTERFACE_PREFIXES = ("tun", "wg", "proton", "tap", "utun")


class LeakDetector:
    """Detects DNS, WebRTC, and IPv6 leaks while connected to a VPN."""

    def __init__(self, vpn_dns: Optional[list[str]] = None, sniff_timeout: int = 5):
        """Initialise the leak detector.

        Args:
            vpn_dns: Whitelisted VPN DNS resolver IPs. Defaults to Proton VPN resolvers.
            sniff_timeout: Seconds to capture DNS traffic before analysis.
        """
        self.vpn_dns = vpn_dns or DEFAULT_VPN_DNS
        self.sniff_timeout = sniff_timeout

    def check_dns(self) -> AuditResult:
        """Sniff DNS traffic and flag queries sent to non-VPN resolvers."""
        try:
            packets = sniff(
                filter="udp port 53",
                timeout=self.sniff_timeout,
                count=50,
            )
        except Exception as exc:
            return AuditResult(
                status="warning",
                details={"error": f"DNS sniff failed: {exc}", "leaked_servers": []},
            )

        if not packets:
            return AuditResult(
                status="warning",
                details={"error": "No DNS packets captured", "leaked_servers": []},
            )

        leaked_servers: list[str] = []
        for pkt in packets:
            if pkt.haslayer(IP) and pkt.haslayer(DNS):
                dst = pkt[IP].dst
                if dst not in self.vpn_dns:
                    leaked_servers.append(dst)

        leaked_servers = list(set(leaked_servers))

        if leaked_servers:
            return AuditResult(
                status="fail",
                details={"leaked_servers": leaked_servers},
            )
        return AuditResult(status="pass", details={"leaked_servers": []})

    def check_webrtc(self) -> AuditResult:
        """Detect public IPs on non-tunnel interfaces that could leak via WebRTC."""
        try:
            addrs = psutil.net_if_addrs()
        except Exception as exc:
            return AuditResult(
                status="warning",
                details={"error": f"Interface query failed: {exc}", "public_ips": []},
            )

        public_ips: list[str] = []
        for iface, addr_list in addrs.items():
            if iface.lower().startswith(TUNNEL_INTERFACE_PREFIXES):
                continue
            for addr in addr_list:
                if addr.family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                try:
                    ip = ipaddress.ip_address(addr.address.split("%")[0])
                except ValueError:
                    continue
                if not ip.is_private and not ip.is_loopback and not ip.is_link_local:
                    public_ips.append(str(ip))

        public_ips = list(set(public_ips))

        if public_ips:
            return AuditResult(
                status="fail",
                details={"public_ips": public_ips},
            )
        return AuditResult(status="pass", details={"public_ips": []})

    def check_ipv6(self) -> AuditResult:
        """Detect non-link-local IPv6 addresses on non-tunnel interfaces."""
        try:
            addrs = psutil.net_if_addrs()
        except Exception as exc:
            return AuditResult(
                status="warning",
                details={"error": f"Interface query failed: {exc}", "ipv6_leaks": []},
            )

        ipv6_leaks: list[dict] = []
        for iface, addr_list in addrs.items():
            if iface.lower().startswith(TUNNEL_INTERFACE_PREFIXES):
                continue
            for addr in addr_list:
                if addr.family != socket.AF_INET6:
                    continue
                try:
                    ip = ipaddress.ip_address(addr.address.split("%")[0])
                except ValueError:
                    continue
                if not ip.is_link_local and not ip.is_loopback:
                    ipv6_leaks.append({"interface": iface, "address": str(ip)})

        if ipv6_leaks:
            return AuditResult(
                status="fail",
                details={"ipv6_leaks": ipv6_leaks},
            )
        return AuditResult(status="pass", details={"ipv6_leaks": []})

    def run(self) -> AuditResult:
        """Run all leak checks and return an aggregated result."""
        dns = self.check_dns()
        webrtc = self.check_webrtc()
        ipv6 = self.check_ipv6()

        sub_results = {"dns": dns.details, "webrtc": webrtc.details, "ipv6": ipv6.details}
        statuses = [dns.status, webrtc.status, ipv6.status]

        if "fail" in statuses:
            overall = "fail"
        elif "warning" in statuses:
            overall = "warning"
        else:
            overall = "pass"

        return AuditResult(status=overall, details=sub_results)
