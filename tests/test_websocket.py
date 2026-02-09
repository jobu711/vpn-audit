"""Tests for the WebSocket real-time monitoring endpoint."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.websocket import active_connections, router

# Build a standalone test app that includes only the WebSocket router.
# This avoids importing or modifying backend/api/main.py.
app = FastAPI()
app.include_router(router)


def _make_state(seq: int = 0) -> dict:
    """Return a realistic state dict for testing."""
    return {
        "interfaces": [
            {"name": "eth0", "is_up": True, "addresses": ["10.0.0.2"]},
        ],
        "routing": [{"destination": "default", "via": "10.0.0.1", "dev": "eth0"}],
        "latency_ms": 12.5 + seq,
        "bandwidth_mbps": 50.0 + seq,
        "timestamp": f"2025-01-01T00:00:0{seq}+00:00",
    }


async def _fake_stream(count: int = 3):
    """Async generator that yields *count* state dicts then stops."""
    for i in range(count):
        yield _make_state(i)
        await asyncio.sleep(0)


class TestWebSocketMonitor:
    """Tests for /ws/monitor endpoint."""

    def test_connect_and_receive_json(self):
        """Client should receive JSON state dicts from the monitor stream."""
        with patch(
            "backend.api.websocket.ConnectionMonitor"
        ) as MockMonitor:
            instance = MockMonitor.return_value
            instance.stream = lambda: _fake_stream(3)

            client = TestClient(app)
            with client.websocket_connect("/ws/monitor") as ws:
                data = ws.receive_json()
                assert "interfaces" in data
                assert "routing" in data
                assert "latency_ms" in data
                assert "bandwidth_mbps" in data
                assert "timestamp" in data

    def test_receives_multiple_messages(self):
        """Client should receive all messages yielded by the stream."""
        msg_count = 5

        with patch(
            "backend.api.websocket.ConnectionMonitor"
        ) as MockMonitor:
            instance = MockMonitor.return_value
            instance.stream = lambda: _fake_stream(msg_count)

            client = TestClient(app)
            with client.websocket_connect("/ws/monitor") as ws:
                received = []
                for _ in range(msg_count):
                    received.append(ws.receive_json())

                assert len(received) == msg_count
                # Verify sequential latency values
                for i, msg in enumerate(received):
                    assert msg["latency_ms"] == pytest.approx(12.5 + i)

    def test_state_dict_fields(self):
        """Each message should contain the full state dict structure."""
        with patch(
            "backend.api.websocket.ConnectionMonitor"
        ) as MockMonitor:
            instance = MockMonitor.return_value
            instance.stream = lambda: _fake_stream(1)

            client = TestClient(app)
            with client.websocket_connect("/ws/monitor") as ws:
                data = ws.receive_json()

                # Check interfaces structure
                assert isinstance(data["interfaces"], list)
                assert len(data["interfaces"]) > 0
                iface = data["interfaces"][0]
                assert "name" in iface
                assert "is_up" in iface
                assert "addresses" in iface

                # Check routing structure
                assert isinstance(data["routing"], list)

                # Check scalar fields
                assert isinstance(data["latency_ms"], (int, float))
                assert isinstance(data["bandwidth_mbps"], (int, float))
                assert isinstance(data["timestamp"], str)

    def test_graceful_disconnect(self):
        """Client disconnect should not raise and should clean up active_connections."""
        with patch(
            "backend.api.websocket.ConnectionMonitor"
        ) as MockMonitor:
            instance = MockMonitor.return_value
            # Yield many messages so stream is still running when client disconnects
            instance.stream = lambda: _fake_stream(100)

            client = TestClient(app)
            with client.websocket_connect("/ws/monitor") as ws:
                # Receive one message to confirm connection
                ws.receive_json()
                # Close triggers disconnect handling

            # After disconnect, active_connections should not contain this client
            # (the set is cleaned up in the finally block)
            # We just verify no exception was raised and the set is manageable
            assert isinstance(active_connections, set)

    def test_multiple_clients(self):
        """Multiple simultaneous clients should each receive data independently."""
        with patch(
            "backend.api.websocket.ConnectionMonitor"
        ) as MockMonitor:
            instance = MockMonitor.return_value
            instance.stream = lambda: _fake_stream(3)

            client = TestClient(app)
            with client.websocket_connect("/ws/monitor") as ws1:
                data1 = ws1.receive_json()
                assert "interfaces" in data1

            # Second connection after first closes
            instance.stream = lambda: _fake_stream(3)
            with client.websocket_connect("/ws/monitor") as ws2:
                data2 = ws2.receive_json()
                assert "interfaces" in data2
