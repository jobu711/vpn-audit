# VPN Privacy Audit Suite

A real-time VPN privacy auditing tool built for Proton VPN. It detects DNS/WebRTC/IPv6 leaks, fingerprints VPN traffic patterns, tests kill switch effectiveness, and monitors connection state -- all from a single web dashboard.

## Features

- **Leak Detection** -- Sniff DNS traffic for non-VPN resolver queries, scan interfaces for public IPs exposed via WebRTC, and flag non-link-local IPv6 addresses on non-tunnel interfaces.
- **Traffic Fingerprinting** -- Capture and classify packets to determine whether VPN protocol traffic (WireGuard, OpenVPN) is distinguishable from normal HTTPS.
- **Kill Switch Testing** -- Monitor all interfaces during a manual VPN disconnect to verify no traffic escapes outside the tunnel, with time-to-block measurement.
- **Live Connection Monitor** -- Stream interface status, routing tables, latency, and bandwidth in real time over WebSocket with automatic change-event detection.
- **Web Dashboard** -- Dark-themed two-panel UI with SVG ring gauges, live event log, and one-click audit controls.

## Architecture

```
backend/
  api/
    main.py          # FastAPI app, static file mount, health check
    routes.py        # REST endpoints for audit operations
    websocket.py     # WebSocket endpoint for live monitoring
  core/
    models.py        # AuditResult dataclass
    leak_detect.py   # LeakDetector  (DNS, WebRTC, IPv6)
    fingerprint.py   # TrafficFingerprinter (packet classification)
    monitor.py       # ConnectionMonitor (interfaces, routing, latency)
    killswitch.py    # KillSwitchTester (non-tunnel traffic capture)
frontend/
  index.html         # Two-panel dashboard layout
  css/style.css      # Dark theme, CSS Grid, responsive
  js/app.js          # WebSocket client, fetch-based audit controls
```

The **backend** is a FastAPI application with four core modules that use Scapy for packet capture and psutil for system introspection. The **frontend** is a vanilla JavaScript single-page dashboard served as static files by the same server.

## Quick Start

### Prerequisites

- Python 3.10+
- Admin/root privileges (required by Scapy for raw packet capture)

### Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Start the server
python -m uvicorn backend.api.main:app --reload
```

Open `http://localhost:8000` in your browser.

> **Note:** Scapy requires elevated privileges to capture packets. On Linux/macOS run the server with `sudo`. On Windows, run your terminal as Administrator.

## API Reference

| Method | Endpoint               | Description                              |
|--------|------------------------|------------------------------------------|
| GET    | `/api/health`          | Health check                             |
| POST   | `/api/audit/leaks`     | Run DNS, WebRTC, and IPv6 leak detection |
| POST   | `/api/audit/fingerprint` | Run traffic fingerprinting analysis    |
| POST   | `/api/audit/killswitch`  | Run kill switch effectiveness test     |
| POST   | `/api/audit/full`      | Run all audit modules sequentially       |
| GET    | `/api/status`          | Current connection status snapshot       |
| GET    | `/api/results`         | Latest stored audit results              |
| WS     | `/ws/monitor`          | Real-time connection monitoring stream   |

## Dashboard

The dashboard is split into two panels:

- **Left panel -- Live Connection Monitor:** Displays latency and bandwidth as animated SVG ring gauges, lists network interfaces with up/down status, shows the routing table, and maintains a scrolling event log of connection changes.
- **Right panel -- Audit Controls:** Four cards (Leak Detection, Traffic Fingerprinting, Kill Switch, Full Audit) each with a run button and inline result display showing pass/fail/warning status with detail payloads.

<!-- Screenshot placeholder: place a screenshot at screenshot.png and uncomment the line below -->
<!-- ![Dashboard](screenshot.png) -->

## Testing

```bash
python -m pytest tests/ -v
```

Tests use `httpx.AsyncClient` with `ASGITransport` to exercise the FastAPI app without a running server. Core module tests patch Scapy and psutil to run without elevated privileges.

## Tech Stack

- **Python 3.10+** -- runtime
- **FastAPI** -- async web framework and WebSocket support
- **Uvicorn** -- ASGI server
- **Scapy** -- raw packet capture and protocol analysis
- **psutil** -- network interface and I/O counter introspection
- **Vanilla JavaScript** -- dashboard UI with no build step

## License

MIT -- see the [LICENSE](LICENSE) file for details.
