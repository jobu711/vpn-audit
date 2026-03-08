---
created: 2026-03-07T23:56:33Z
last_updated: 2026-03-07T23:56:33Z
version: 1.0
author: Claude Code PM System
---

# Project Structure

## Directory Layout

```
vpn_audit/
├── backend/
│   ├── __init__.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── main.py            # FastAPI app setup, static file mount, health check
│   │   ├── routes.py          # REST endpoints, in-memory _results storage
│   │   └── websocket.py       # WebSocket /ws/monitor endpoint (~1 Hz)
│   └── core/
│       ├── __init__.py
│       ├── models.py           # AuditResult dataclass (pass/fail/warning)
│       ├── interfaces.py       # Shared cross-platform tunnel interface classification
│       ├── leak_detect.py      # LeakDetector: DNS, WebRTC, IPv6
│       ├── fingerprint.py      # TrafficFingerprinter: WireGuard/OpenVPN/HTTPS
│       ├── killswitch.py       # KillSwitchTester: non-tunnel traffic capture
│       ├── monitor.py          # ConnectionMonitor: interfaces, routing, latency, bandwidth
│       └── external_ip.py      # ExternalIPChecker: ip-api.com lookup with VPN masking
├── frontend/
│   ├── index.html              # Two-panel dashboard layout
│   ├── css/style.css           # Dark theme, CSS Grid, responsive
│   └── js/app.js               # WebSocket client, fetch-based audit controls
├── tests/
│   ├── __init__.py
│   ├── conftest.py             # Shared async client fixture
│   ├── test_api.py             # REST endpoint tests
│   ├── test_external_ip.py     # External IP module tests
│   ├── test_fingerprint.py     # Fingerprinting tests
│   ├── test_health.py          # Health endpoint test
│   ├── test_interfaces.py      # Interface classification tests
│   ├── test_killswitch.py      # Kill switch tests
│   ├── test_leak_detect.py     # Leak detection tests
│   ├── test_monitor.py         # Connection monitor tests
│   └── test_websocket.py       # WebSocket tests
├── requirements.txt            # Python dependencies
├── pyproject.toml              # pytest config (asyncio_mode = "auto")
├── run.bat                     # Windows launcher (venv, deps, admin check)
├── CLAUDE.md                   # Project instructions for Claude Code
└── README.md                   # Project documentation
```

## Key Patterns

- **One module per concern** in `backend/core/` — each has a main class and a `run()` method returning `AuditResult`
- **Shared interface classification** in `interfaces.py` — used by leak_detect, killswitch, and monitor
- **Static file serving** — frontend mounted at `/` in main.py (must be last mount)
- **Test mirroring** — each `backend/core/{module}.py` has a corresponding `tests/test_{module}.py`
