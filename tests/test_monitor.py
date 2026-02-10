"""Tests for the connection monitoring module."""

import asyncio
from collections import namedtuple
from unittest.mock import MagicMock, patch

import pytest

from backend.core.models import AuditResult
from backend.core.monitor import ConnectionMonitor

# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

FAKE_ADDR = namedtuple("snicaddr", ["family", "address", "netmask", "broadcast", "ptp"])
FAKE_STAT = namedtuple("snicstats", ["isup", "duplex", "speed", "mtu", "flags"])
FAKE_IO = namedtuple("snetio", [
    "bytes_sent", "bytes_recv", "packets_sent", "packets_recv",
    "errin", "errout", "dropin", "dropout",
])

# socket.AF_INET == 2
AF_INET = 2


def _make_addrs(mapping: dict) -> dict:
    """Build a psutil-style net_if_addrs dict from {name: [(family, ip)]}."""
    out = {}
    for name, entries in mapping.items():
        out[name] = [FAKE_ADDR(family=f, address=ip, netmask=None, broadcast=None, ptp=None) for f, ip in entries]
    return out


def _make_stats(mapping: dict) -> dict:
    """Build a psutil-style net_if_stats dict from {name: is_up}."""
    return {
        name: FAKE_STAT(isup=up, duplex=0, speed=0, mtu=1500, flags="")
        for name, up in mapping.items()
    }


# ---------------------------------------------------------------------------
# Interface polling
# ---------------------------------------------------------------------------


class TestGetInterfaces:
    @patch("backend.core.monitor.psutil.net_if_stats")
    @patch("backend.core.monitor.psutil.net_if_addrs")
    def test_returns_interfaces_with_addresses_and_status(self, mock_addrs, mock_stats):
        mock_addrs.return_value = _make_addrs({
            "eth0": [(AF_INET, "192.168.1.10")],
            "tun0": [(AF_INET, "10.8.0.2")],
        })
        mock_stats.return_value = _make_stats({"eth0": True, "tun0": True})

        ifaces = ConnectionMonitor.get_interfaces()

        names = {i["name"] for i in ifaces}
        assert "eth0" in names
        assert "tun0" in names
        eth0 = next(i for i in ifaces if i["name"] == "eth0")
        assert eth0["is_up"] is True
        assert "192.168.1.10" in eth0["addresses"]

    @patch("backend.core.monitor.psutil.net_if_stats")
    @patch("backend.core.monitor.psutil.net_if_addrs")
    def test_interface_down(self, mock_addrs, mock_stats):
        mock_addrs.return_value = _make_addrs({"wlan0": [(AF_INET, "192.168.0.5")]})
        mock_stats.return_value = _make_stats({"wlan0": False})

        ifaces = ConnectionMonitor.get_interfaces()

        assert ifaces[0]["is_up"] is False

    @patch("backend.core.monitor.psutil.net_if_stats")
    @patch("backend.core.monitor.psutil.net_if_addrs")
    def test_missing_stats_defaults_to_down(self, mock_addrs, mock_stats):
        mock_addrs.return_value = _make_addrs({"lo": [(AF_INET, "127.0.0.1")]})
        mock_stats.return_value = {}  # no stats for lo

        ifaces = ConnectionMonitor.get_interfaces()

        assert ifaces[0]["is_up"] is False


# ---------------------------------------------------------------------------
# Routing table parsing
# ---------------------------------------------------------------------------


WINDOWS_ROUTE_OUTPUT = """\
===========================================================================
Interface List
  6 ...00 15 5d xx xx xx ...... Ethernet
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      10.0.0.1      10.0.0.5     25
        10.0.0.0    255.255.255.0         On-link       10.0.0.5    281
===========================================================================
"""

LINUX_ROUTE_OUTPUT = """\
default via 10.0.0.1 dev eth0 proto dhcp metric 100
10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5
172.16.0.0/12 via 10.8.0.1 dev tun0
"""


class TestRoutingParsing:
    def test_parse_windows_routes(self):
        routes = ConnectionMonitor._parse_windows_routes(WINDOWS_ROUTE_OUTPUT)
        assert len(routes) >= 1
        default_route = next((r for r in routes if r["destination"] == "0.0.0.0"), None)
        assert default_route is not None
        assert default_route["gateway"] == "10.0.0.1"
        assert default_route["metric"] == 25

    def test_parse_linux_routes(self):
        routes = ConnectionMonitor._parse_linux_routes(LINUX_ROUTE_OUTPUT)
        assert len(routes) == 3
        default = next(r for r in routes if r["destination"] == "default")
        assert default["via"] == "10.0.0.1"
        assert default["dev"] == "eth0"

    def test_parse_empty_output(self):
        assert ConnectionMonitor._parse_windows_routes("") == []
        assert ConnectionMonitor._parse_linux_routes("") == []

    @patch("backend.core.monitor.platform.system", return_value="Windows")
    @patch("backend.core.monitor.subprocess.run")
    def test_get_routing_table_windows(self, mock_run, _mock_sys):
        mock_run.return_value = MagicMock(stdout=WINDOWS_ROUTE_OUTPUT, returncode=0)
        routes = ConnectionMonitor.get_routing_table()
        assert len(routes) >= 1
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0] == ["route", "print"]

    @patch("backend.core.monitor.platform.system", return_value="Linux")
    @patch("backend.core.monitor.subprocess.run")
    def test_get_routing_table_linux(self, mock_run, _mock_sys):
        mock_run.return_value = MagicMock(stdout=LINUX_ROUTE_OUTPUT, returncode=0)
        routes = ConnectionMonitor.get_routing_table()
        assert len(routes) == 3
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0] == ["ip", "route"]

    @patch("backend.core.monitor.platform.system", return_value="Windows")
    @patch("backend.core.monitor.subprocess.run", side_effect=OSError("fail"))
    def test_get_routing_table_error_returns_empty(self, _mock_run, _mock_sys):
        assert ConnectionMonitor.get_routing_table() == []


# ---------------------------------------------------------------------------
# Latency measurement
# ---------------------------------------------------------------------------


class TestLatency:
    @patch("backend.core.monitor.subprocess.run")
    def test_measure_latency_parses_time(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="Reply from 8.8.8.8: bytes=32 time=14ms TTL=117",
            returncode=0,
        )
        mon = ConnectionMonitor()
        lat = mon.measure_latency()
        assert lat == 14.0

    @patch("backend.core.monitor.subprocess.run")
    def test_measure_latency_linux_format(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=12.3 ms",
            returncode=0,
        )
        mon = ConnectionMonitor()
        assert mon.measure_latency() == 12.3

    @patch("backend.core.monitor.subprocess.run")
    def test_measure_latency_failure(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        mon = ConnectionMonitor()
        assert mon.measure_latency() is None

    @patch("backend.core.monitor.subprocess.run", side_effect=OSError("timeout"))
    def test_measure_latency_exception(self, _mock_run):
        mon = ConnectionMonitor()
        assert mon.measure_latency() is None


# ---------------------------------------------------------------------------
# Bandwidth estimation
# ---------------------------------------------------------------------------


class TestBandwidth:
    @patch("backend.core.monitor.time.sleep")
    @patch("backend.core.monitor.psutil.net_io_counters")
    def test_estimate_bandwidth(self, mock_io, mock_sleep):
        mock_io.side_effect = [
            FAKE_IO(bytes_sent=0, bytes_recv=0, packets_sent=0, packets_recv=0, errin=0, errout=0, dropin=0, dropout=0),
            FAKE_IO(bytes_sent=62500, bytes_recv=62500, packets_sent=0, packets_recv=0, errin=0, errout=0, dropin=0, dropout=0),
        ]
        mon = ConnectionMonitor()
        mbps = mon.estimate_bandwidth(sample_interval=0.5)
        # 125000 bytes in 0.5s = 250000 bytes/s = 2 Mbps
        assert mbps == 2.0
        mock_sleep.assert_called_once_with(0.5)


# ---------------------------------------------------------------------------
# snapshot() includes external_ip
# ---------------------------------------------------------------------------


class TestSnapshot:
    @patch("backend.core.monitor.psutil.net_io_counters")
    @patch("backend.core.monitor.time.sleep")
    @patch("backend.core.monitor.subprocess.run")
    @patch("backend.core.monitor.psutil.net_if_stats")
    @patch("backend.core.monitor.psutil.net_if_addrs")
    @patch("backend.core.external_ip.urllib.request.urlopen")
    def test_snapshot_includes_external_ip(self, mock_urlopen, mock_addrs, mock_stats, mock_subproc, mock_sleep, mock_io):
        import json
        resp = MagicMock()
        resp.read.return_value = json.dumps({
            "query": "1.2.3.4", "country": "US", "city": "NYC",
            "isp": "TestISP", "org": "TestOrg", "as": "AS1",
        }).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = resp

        mock_addrs.return_value = _make_addrs({"eth0": [(AF_INET, "10.0.0.1")]})
        mock_stats.return_value = _make_stats({"eth0": True})
        mock_subproc.return_value = MagicMock(stdout="", returncode=1)
        mock_io.side_effect = [
            FAKE_IO(0, 0, 0, 0, 0, 0, 0, 0),
            FAKE_IO(0, 0, 0, 0, 0, 0, 0, 0),
        ]

        mon = ConnectionMonitor()
        snap = mon.snapshot()
        assert "external_ip" in snap
        assert snap["external_ip"]["ip"] == "1.2.3.4"


# ---------------------------------------------------------------------------
# run() -> AuditResult
# ---------------------------------------------------------------------------


class TestRun:
    def _make_monitor_with_snapshot(self, snapshot: dict) -> ConnectionMonitor:
        mon = ConnectionMonitor()
        mon.snapshot = MagicMock(return_value=snapshot)
        return mon

    def test_run_pass(self):
        mon = self._make_monitor_with_snapshot({
            "interfaces": [{"name": "eth0", "is_up": True, "addresses": ["10.0.0.1"]}],
            "routing": [{"destination": "0.0.0.0"}],
            "latency_ms": 10.0,
            "bandwidth_mbps": 1.5,
            "timestamp": "2024-01-01T00:00:00+00:00",
        })
        result = mon.run()
        assert isinstance(result, AuditResult)
        assert result.status == "pass"

    def test_run_fail_no_active_interfaces(self):
        mon = self._make_monitor_with_snapshot({
            "interfaces": [{"name": "eth0", "is_up": False, "addresses": []}],
            "routing": [{"destination": "0.0.0.0"}],
            "latency_ms": None,
            "bandwidth_mbps": 0.0,
            "timestamp": "2024-01-01T00:00:00+00:00",
        })
        result = mon.run()
        assert result.status == "fail"

    def test_run_fail_no_routes(self):
        mon = self._make_monitor_with_snapshot({
            "interfaces": [{"name": "eth0", "is_up": True, "addresses": ["10.0.0.1"]}],
            "routing": [],
            "latency_ms": 10.0,
            "bandwidth_mbps": 1.5,
            "timestamp": "2024-01-01T00:00:00+00:00",
        })
        result = mon.run()
        assert result.status == "fail"

    def test_run_warning_no_latency(self):
        mon = self._make_monitor_with_snapshot({
            "interfaces": [{"name": "eth0", "is_up": True, "addresses": ["10.0.0.1"]}],
            "routing": [{"destination": "0.0.0.0"}],
            "latency_ms": None,
            "bandwidth_mbps": 0.0,
            "timestamp": "2024-01-01T00:00:00+00:00",
        })
        result = mon.run()
        assert result.status == "warning"

    def test_run_details_contain_state(self):
        state = {
            "interfaces": [{"name": "eth0", "is_up": True, "addresses": ["10.0.0.1"]}],
            "routing": [{"destination": "0.0.0.0"}],
            "latency_ms": 5.0,
            "bandwidth_mbps": 10.0,
            "timestamp": "2024-01-01T00:00:00+00:00",
        }
        mon = self._make_monitor_with_snapshot(state)
        result = mon.run()
        assert result.details == state


# ---------------------------------------------------------------------------
# async stream()
# ---------------------------------------------------------------------------


class TestStream:
    @pytest.mark.asyncio
    async def test_stream_yields_state_dicts(self):
        mon = ConnectionMonitor(poll_interval=0.0)
        state = {
            "interfaces": [{"name": "eth0", "is_up": True, "addresses": ["10.0.0.1"]}],
            "routing": [{"destination": "0.0.0.0"}],
            "latency_ms": 5.0,
            "bandwidth_mbps": 1.0,
            "timestamp": "2024-01-01T00:00:00+00:00",
        }
        mon.snapshot = MagicMock(return_value=state)

        collected: list[dict] = []
        async for item in mon.stream():
            collected.append(item)
            if len(collected) >= 3:
                break

        assert len(collected) == 3
        for item in collected:
            assert "interfaces" in item
            assert "routing" in item
            assert "timestamp" in item

    @pytest.mark.asyncio
    async def test_stream_emits_initial_event(self):
        mon = ConnectionMonitor(poll_interval=0.0)
        state = {
            "interfaces": [],
            "routing": [],
            "latency_ms": None,
            "bandwidth_mbps": 0.0,
            "timestamp": "2024-01-01T00:00:00+00:00",
        }
        mon.snapshot = MagicMock(return_value=state)

        async for item in mon.stream():
            assert item.get("event", {}).get("type") == "initial"
            break

    @pytest.mark.asyncio
    async def test_stream_detects_interface_change(self):
        mon = ConnectionMonitor(poll_interval=0.0)
        states = [
            {
                "interfaces": [{"name": "eth0", "is_up": True, "addresses": ["10.0.0.1"]}],
                "routing": [],
                "latency_ms": None,
                "bandwidth_mbps": 0.0,
                "timestamp": "t1",
            },
            {
                "interfaces": [
                    {"name": "eth0", "is_up": True, "addresses": ["10.0.0.1"]},
                    {"name": "tun0", "is_up": True, "addresses": ["10.8.0.2"]},
                ],
                "routing": [],
                "latency_ms": None,
                "bandwidth_mbps": 0.0,
                "timestamp": "t2",
            },
        ]
        call_count = 0

        def side_effect():
            nonlocal call_count
            idx = min(call_count, len(states) - 1)
            call_count += 1
            return states[idx]

        mon.snapshot = MagicMock(side_effect=side_effect)

        collected: list[dict] = []
        async for item in mon.stream():
            collected.append(item)
            if len(collected) >= 2:
                break

        second = collected[1]
        assert second.get("event", {}).get("type") == "change"
        assert "tun0" in second["event"].get("interfaces_added", [])

    @pytest.mark.asyncio
    async def test_stream_detects_interface_status_change(self):
        mon = ConnectionMonitor(poll_interval=0.0)
        states = [
            {
                "interfaces": [{"name": "eth0", "is_up": True, "addresses": ["10.0.0.1"]}],
                "routing": [],
                "latency_ms": None,
                "bandwidth_mbps": 0.0,
                "timestamp": "t1",
            },
            {
                "interfaces": [{"name": "eth0", "is_up": False, "addresses": ["10.0.0.1"]}],
                "routing": [],
                "latency_ms": None,
                "bandwidth_mbps": 0.0,
                "timestamp": "t2",
            },
        ]
        call_count = 0

        def side_effect():
            nonlocal call_count
            idx = min(call_count, len(states) - 1)
            call_count += 1
            return states[idx]

        mon.snapshot = MagicMock(side_effect=side_effect)

        collected: list[dict] = []
        async for item in mon.stream():
            collected.append(item)
            if len(collected) >= 2:
                break

        second = collected[1]
        assert second["event"]["type"] == "change"
        assert "eth0" in second["event"]["interfaces_status_changed"]
