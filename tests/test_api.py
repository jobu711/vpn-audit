"""Integration tests for REST API routes."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from backend.api.routes import _results, router
from backend.core.models import AuditResult

# Build a standalone test app that includes the router.
app = FastAPI()
app.include_router(router)


@pytest.fixture(autouse=True)
def clear_results():
    """Clear in-memory results between tests."""
    _results.clear()
    yield
    _results.clear()


@pytest.fixture
async def client():
    """Async test client for the router-only test app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---- Helpers ----

def _make_result(status="pass", details=None):
    """Create an AuditResult for mocking."""
    return AuditResult(status=status, details=details or {}, timestamp="2024-01-01T00:00:00+00:00")


# ---- POST /api/audit/leaks ----

@pytest.mark.asyncio
async def test_audit_leaks_returns_result(client):
    """POST /api/audit/leaks should return an AuditResult dict."""
    mock_result = _make_result("pass", {"dns": {}, "webrtc": {}, "ipv6": {}})
    with patch("backend.api.routes.LeakDetector") as MockCls:
        MockCls.return_value.run.return_value = mock_result
        response = await client.post("/api/audit/leaks")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "pass"
    assert "details" in data
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_audit_leaks_stores_result(client):
    """POST /api/audit/leaks should persist the result in _results."""
    mock_result = _make_result("fail", {"leaked_servers": ["8.8.8.8"]})
    with patch("backend.api.routes.LeakDetector") as MockCls:
        MockCls.return_value.run.return_value = mock_result
        await client.post("/api/audit/leaks")

    assert "leaks" in _results
    assert _results["leaks"]["status"] == "fail"


@pytest.mark.asyncio
async def test_audit_leaks_error_returns_500(client):
    """POST /api/audit/leaks should return 500 when module raises."""
    with patch("backend.api.routes.LeakDetector") as MockCls:
        MockCls.return_value.run.side_effect = RuntimeError("sniff failed")
        response = await client.post("/api/audit/leaks")

    assert response.status_code == 500
    assert "error" in response.json()


# ---- POST /api/audit/fingerprint ----

@pytest.mark.asyncio
async def test_audit_fingerprint_returns_result(client):
    """POST /api/audit/fingerprint should return an AuditResult dict."""
    mock_result = _make_result("warning", {"total_packets": 0, "reason": "No packets captured"})
    with patch("backend.api.routes.TrafficFingerprinter") as MockCls:
        MockCls.return_value.run.return_value = mock_result
        response = await client.post("/api/audit/fingerprint")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "warning"
    assert "details" in data


@pytest.mark.asyncio
async def test_audit_fingerprint_error_returns_500(client):
    """POST /api/audit/fingerprint should return 500 on error."""
    with patch("backend.api.routes.TrafficFingerprinter") as MockCls:
        MockCls.return_value.run.side_effect = RuntimeError("capture error")
        response = await client.post("/api/audit/fingerprint")

    assert response.status_code == 500
    assert "error" in response.json()


# ---- POST /api/audit/killswitch ----

@pytest.mark.asyncio
async def test_audit_killswitch_returns_result(client):
    """POST /api/audit/killswitch should return an AuditResult dict."""
    mock_result = _make_result("pass", {"leaked_packets": 0, "duration": 30})
    with patch("backend.api.routes.KillSwitchTester") as MockCls:
        MockCls.return_value.run.return_value = mock_result
        response = await client.post("/api/audit/killswitch")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "pass"
    assert "details" in data


@pytest.mark.asyncio
async def test_audit_killswitch_error_returns_500(client):
    """POST /api/audit/killswitch should return 500 on error."""
    with patch("backend.api.routes.KillSwitchTester") as MockCls:
        MockCls.return_value.run.side_effect = RuntimeError("permission denied")
        response = await client.post("/api/audit/killswitch")

    assert response.status_code == 500
    assert "error" in response.json()


# ---- POST /api/audit/full ----

@pytest.mark.asyncio
async def test_audit_full_runs_all_modules(client):
    """POST /api/audit/full should invoke all three audit modules."""
    leak_result = _make_result("pass", {"dns": {}})
    fp_result = _make_result("pass", {"total_packets": 50})
    ks_result = _make_result("pass", {"leaked_packets": 0})

    with (
        patch("backend.api.routes.LeakDetector") as MockLeak,
        patch("backend.api.routes.TrafficFingerprinter") as MockFP,
        patch("backend.api.routes.KillSwitchTester") as MockKS,
    ):
        MockLeak.return_value.run.return_value = leak_result
        MockFP.return_value.run.return_value = fp_result
        MockKS.return_value.run.return_value = ks_result

        response = await client.post("/api/audit/full")

    assert response.status_code == 200
    data = response.json()
    assert "leaks" in data
    assert "fingerprint" in data
    assert "killswitch" in data
    assert data["leaks"]["status"] == "pass"
    assert data["fingerprint"]["status"] == "pass"
    assert data["killswitch"]["status"] == "pass"


@pytest.mark.asyncio
async def test_audit_full_stores_individual_results(client):
    """POST /api/audit/full should store each module result individually."""
    leak_result = _make_result("fail", {"leaked_servers": ["1.1.1.1"]})
    fp_result = _make_result("pass", {"total_packets": 10})
    ks_result = _make_result("warning", {"leaked_packets": 1})

    with (
        patch("backend.api.routes.LeakDetector") as MockLeak,
        patch("backend.api.routes.TrafficFingerprinter") as MockFP,
        patch("backend.api.routes.KillSwitchTester") as MockKS,
    ):
        MockLeak.return_value.run.return_value = leak_result
        MockFP.return_value.run.return_value = fp_result
        MockKS.return_value.run.return_value = ks_result

        await client.post("/api/audit/full")

    assert _results["leaks"]["status"] == "fail"
    assert _results["fingerprint"]["status"] == "pass"
    assert _results["killswitch"]["status"] == "warning"
    assert "full" in _results


@pytest.mark.asyncio
async def test_audit_full_error_returns_500(client):
    """POST /api/audit/full should return 500 if any module raises."""
    with patch("backend.api.routes.LeakDetector") as MockLeak:
        MockLeak.return_value.run.side_effect = RuntimeError("total failure")
        response = await client.post("/api/audit/full")

    assert response.status_code == 500
    assert "error" in response.json()


# ---- GET /api/external-ip ----

@pytest.mark.asyncio
async def test_external_ip_returns_result(client):
    """GET /api/external-ip should return external IP info dict."""
    mock_data = {
        "ip": "185.159.157.1",
        "country": "Switzerland",
        "city": "Zurich",
        "isp": "Proton AG",
        "org": "Proton VPN",
        "vpn_masked": True,
        "status": "ok",
        "timestamp": "2024-01-01T00:00:00+00:00",
    }
    with patch("backend.api.routes._ip_checker") as mock_checker:
        mock_checker.lookup.return_value = mock_data
        response = await client.get("/api/external-ip")

    assert response.status_code == 200
    data = response.json()
    assert data["ip"] == "185.159.157.1"
    assert data["vpn_masked"] is True
    assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_external_ip_error_returns_500(client):
    """GET /api/external-ip should return 500 when checker raises."""
    with patch("backend.api.routes._ip_checker") as mock_checker:
        mock_checker.lookup.side_effect = RuntimeError("network error")
        response = await client.get("/api/external-ip")

    assert response.status_code == 500
    assert "error" in response.json()


# ---- GET /api/status ----

@pytest.mark.asyncio
async def test_status_returns_snapshot(client):
    """GET /api/status should return a connection snapshot dict."""
    snapshot_data = {
        "interfaces": [{"name": "eth0", "is_up": True, "addresses": ["192.168.1.10"]}],
        "routing": [],
        "latency_ms": 12.5,
        "bandwidth_mbps": 100.0,
        "timestamp": "2024-01-01T00:00:00+00:00",
    }
    with patch("backend.api.routes.ConnectionMonitor") as MockCls:
        MockCls.return_value.snapshot = AsyncMock(return_value=snapshot_data)
        response = await client.get("/api/status")

    assert response.status_code == 200
    data = response.json()
    assert "interfaces" in data
    assert "latency_ms" in data
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_status_error_returns_500(client):
    """GET /api/status should return 500 when monitor raises."""
    with patch("backend.api.routes.ConnectionMonitor") as MockCls:
        MockCls.return_value.snapshot = AsyncMock(side_effect=RuntimeError("psutil error"))
        response = await client.get("/api/status")

    assert response.status_code == 500
    assert "error" in response.json()


# ---- GET /api/results ----

@pytest.mark.asyncio
async def test_results_empty_initially(client):
    """GET /api/results should return empty dict when no audits have run."""
    response = await client.get("/api/results")
    assert response.status_code == 200
    assert response.json() == {}


@pytest.mark.asyncio
async def test_results_returns_stored_data(client):
    """GET /api/results should return previously stored audit results."""
    mock_result = _make_result("pass", {"dns": {}, "webrtc": {}, "ipv6": {}})
    with patch("backend.api.routes.LeakDetector") as MockCls:
        MockCls.return_value.run.return_value = mock_result
        await client.post("/api/audit/leaks")

    response = await client.get("/api/results")
    assert response.status_code == 200
    data = response.json()
    assert "leaks" in data
    assert data["leaks"]["status"] == "pass"
