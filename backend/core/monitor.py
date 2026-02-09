"""Connection monitoring module for VPN privacy auditing."""

import asyncio
import platform
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import AsyncGenerator

import psutil

from backend.core.models import AuditResult


class ConnectionMonitor:
    """Monitors network connection state: interfaces, routing, latency, bandwidth."""

    def __init__(self, ping_target: str = "8.8.8.8", poll_interval: float = 1.0):
        """Initialise the connection monitor.

        Args:
            ping_target: IP address used for latency measurements.
            poll_interval: Seconds between state snapshots when streaming.
        """
        self.ping_target = ping_target
        self.poll_interval = poll_interval
        self._prev_state: dict | None = None

    # ------------------------------------------------------------------
    # Interface polling
    # ------------------------------------------------------------------

    @staticmethod
    def get_interfaces() -> list[dict]:
        """Return a list of network interfaces with addresses and status."""
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        interfaces: list[dict] = []
        for name, addr_list in addrs.items():
            iface_stat = stats.get(name)
            is_up = iface_stat.isup if iface_stat else False

            ips: list[str] = []
            for addr in addr_list:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    ips.append(addr.address.split("%")[0])

            interfaces.append({"name": name, "is_up": is_up, "addresses": ips})

        return interfaces

    # ------------------------------------------------------------------
    # Routing table
    # ------------------------------------------------------------------

    @staticmethod
    def get_routing_table() -> list[dict]:
        """Parse the platform routing table into a list of route dicts."""
        system = platform.system()
        try:
            if system == "Windows":
                result = subprocess.run(
                    ["route", "print"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return ConnectionMonitor._parse_windows_routes(result.stdout)
            else:
                result = subprocess.run(
                    ["ip", "route"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return ConnectionMonitor._parse_linux_routes(result.stdout)
        except Exception:
            return []

    @staticmethod
    def _parse_windows_routes(output: str) -> list[dict]:
        """Parse Windows ``route print`` output into route dicts."""
        routes: list[dict] = []
        # Match lines with four dotted-quad groups + a metric number.
        # Typical line:  "  0.0.0.0          0.0.0.0     10.0.0.1     10.0.0.5     25"
        pattern = re.compile(
            r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)"
            r"\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)"
            r"\s+(\d+)",
        )
        for line in output.splitlines():
            m = pattern.match(line)
            if m:
                routes.append({
                    "destination": m.group(1),
                    "netmask": m.group(2),
                    "gateway": m.group(3),
                    "interface": m.group(4),
                    "metric": int(m.group(5)),
                })
        return routes

    @staticmethod
    def _parse_linux_routes(output: str) -> list[dict]:
        """Parse Linux ``ip route`` output into route dicts."""
        routes: list[dict] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            route: dict = {"destination": parts[0]}
            i = 1
            while i < len(parts) - 1:
                key = parts[i]
                if key in ("via", "dev", "proto", "scope", "src", "metric"):
                    route[key] = parts[i + 1]
                    i += 2
                else:
                    i += 1
            routes.append(route)
        return routes

    # ------------------------------------------------------------------
    # Latency (ping)
    # ------------------------------------------------------------------

    def measure_latency(self) -> float | None:
        """Measure round-trip latency to *ping_target* in milliseconds."""
        system = platform.system()
        count_flag = "-n" if system == "Windows" else "-c"
        try:
            result = subprocess.run(
                ["ping", count_flag, "1", "-w", "2", self.ping_target],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None
            # Windows:  "Average = 12ms" or individual "time=12ms" / "time<1ms"
            # Linux:    "time=12.3 ms"
            m = re.search(r"time[=<]([\d.]+)\s*ms", result.stdout, re.IGNORECASE)
            if m:
                return float(m.group(1))
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Bandwidth estimation
    # ------------------------------------------------------------------

    def estimate_bandwidth(self, sample_interval: float = 0.5) -> float:
        """Estimate current throughput in Mbps by sampling net_io_counters."""
        try:
            c1 = psutil.net_io_counters()
            time.sleep(sample_interval)
            c2 = psutil.net_io_counters()
            bytes_delta = (c2.bytes_sent - c1.bytes_sent) + (c2.bytes_recv - c1.bytes_recv)
            mbps = (bytes_delta * 8) / (sample_interval * 1_000_000)
            return round(mbps, 3)
        except Exception:
            return 0.0

    # ------------------------------------------------------------------
    # Snapshot / state dict
    # ------------------------------------------------------------------

    def snapshot(self) -> dict:
        """Build a full state dict of current connection info."""
        return {
            "interfaces": self.get_interfaces(),
            "routing": self.get_routing_table(),
            "latency_ms": self.measure_latency(),
            "bandwidth_mbps": self.estimate_bandwidth(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # run() -> AuditResult
    # ------------------------------------------------------------------

    def run(self) -> AuditResult:
        """Take a snapshot and return an AuditResult summarising connection state."""
        state = self.snapshot()

        active = [i for i in state["interfaces"] if i["is_up"]]
        has_routes = bool(state["routing"])
        latency_ok = state["latency_ms"] is not None

        if active and has_routes and latency_ok:
            status = "pass"
        elif not active or not has_routes:
            status = "fail"
        else:
            status = "warning"

        return AuditResult(status=status, details=state)

    # ------------------------------------------------------------------
    # async stream()
    # ------------------------------------------------------------------

    async def stream(self) -> AsyncGenerator[dict, None]:
        """Yield state dicts at approximately *poll_interval* Hz, including change events."""
        while True:
            state = self.snapshot()
            event = self._detect_changes(state)
            if event:
                state["event"] = event
            self._prev_state = state
            yield state
            await asyncio.sleep(self.poll_interval)

    def _detect_changes(self, current: dict) -> dict | None:
        """Compare *current* state against previous and return a change summary."""
        if self._prev_state is None:
            return {"type": "initial"}

        changes: dict = {}

        prev_ifaces = {i["name"]: i for i in self._prev_state.get("interfaces", [])}
        curr_ifaces = {i["name"]: i for i in current.get("interfaces", [])}

        added = set(curr_ifaces) - set(prev_ifaces)
        removed = set(prev_ifaces) - set(curr_ifaces)
        status_changed = [
            name
            for name in set(curr_ifaces) & set(prev_ifaces)
            if curr_ifaces[name]["is_up"] != prev_ifaces[name]["is_up"]
        ]

        if added:
            changes["interfaces_added"] = list(added)
        if removed:
            changes["interfaces_removed"] = list(removed)
        if status_changed:
            changes["interfaces_status_changed"] = status_changed

        prev_routes = self._prev_state.get("routing", [])
        curr_routes = current.get("routing", [])
        if prev_routes != curr_routes:
            changes["routing_changed"] = True

        if changes:
            changes["type"] = "change"
            return changes
        return None
