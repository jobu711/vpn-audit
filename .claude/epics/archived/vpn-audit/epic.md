---
name: vpn-audit
status: completed
created: 2026-02-09T15:26:00Z
progress: 100%
prd: .claude/prds/vpn-audit.md
updated: 2026-02-09T16:19:22Z
github: https://github.com/jobu711/vpn-audit/issues/1
---

# Epic: VPN Privacy Audit Suite

## Overview

Build a local Python VPN privacy audit suite with a FastAPI backend, WebSocket-powered real-time monitoring, and a two-panel web dashboard. The core engine consists of four independent audit modules (leak detection, traffic fingerprinting, connection monitoring, kill switch testing) exposed via REST API and rendered through a clean portfolio-quality frontend.

## Architecture Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Web framework | **FastAPI** | Async-native, built-in WebSocket support, auto-generated API docs — eliminates need for separate WebSocket library |
| Packet capture | **Scapy** | Python-native, cross-platform, well-documented for security tooling |
| Real-time comms | **FastAPI WebSocket** | Built into FastAPI, no additional dependency needed |
| Session storage | **In-memory dict** | Portfolio project, no persistence needed — avoids SQLite complexity |
| Frontend | **Vanilla HTML/CSS/JS** | No build step, no framework overhead — keeps it simple and portfolio-readable |
| Dashboard layout | **CSS Grid two-panel** | Left panel for live monitoring, right panel for test results |

## Technical Approach

### Core Engine (`backend/core/`)
Four independent modules, each exposing a consistent interface:
- `run()` → executes the audit and returns structured results
- Returns `AuditResult` dataclass: `{status: pass|fail|warning, details: dict, timestamp: str}`

**Leak Detection** (`leak_detect.py`):
- DNS: Use Scapy to sniff DNS packets, resolve via system resolver, compare against known Proton VPN DNS IPs
- WebRTC: Query local network interfaces for public-facing IPs that shouldn't be visible under VPN
- IPv6: Check for IPv6 connectivity/traffic on non-tunnel interfaces

**Traffic Fingerprinting** (`fingerprint.py`):
- Capture sample of packets on active interface
- Analyze packet sizes, timing patterns, and port usage
- Match against known VPN protocol signatures (WireGuard: UDP 51820, OpenVPN: UDP 1194/TCP 443)
- Report whether traffic is distinguishable from regular HTTPS

**Connection Monitor** (`monitor.py`):
- Poll network interfaces via `psutil` for IP addresses, interface status
- Track routing table via platform commands (`route print` on Windows, `ip route` on Linux)
- Measure latency via ICMP ping, bandwidth via throughput sampling
- Emit state changes as events for WebSocket broadcast

**Kill Switch Tester** (`killswitch.py`):
- Monitor traffic on all interfaces during a controlled VPN disconnect window
- Detect any non-tunnel traffic that escapes during reconnection
- Measure time-to-block after disconnect signal
- Note: Actual VPN disconnect is manual (user-triggered) — tool monitors and reports

### Backend API (`backend/api/`)
FastAPI app with:
- `POST /api/audit/leaks` — run leak detection
- `POST /api/audit/fingerprint` — run traffic fingerprinting
- `POST /api/audit/killswitch` — run kill switch test
- `POST /api/audit/full` — run all audit modules
- `GET /api/status` — current connection status and interface info
- `GET /api/results` — latest audit results
- `WS /ws/monitor` — real-time connection monitoring stream

### Frontend (`frontend/`)
Single-page dashboard:
- `index.html` — two-panel grid layout
- `css/style.css` — dark theme, professional design with status colors (green/red/yellow)
- `js/app.js` — WebSocket client, API calls, DOM updates
- Left panel: live connection status, IP info, bandwidth/latency gauges
- Right panel: audit test cards with trigger buttons and pass/fail/warning results

## Implementation Strategy

Build bottom-up: core modules first, then API layer, then dashboard. Each task is independently testable.

**Phase 1 — Foundation:** Project scaffolding, dependencies, FastAPI app skeleton
**Phase 2 — Core Modules:** Implement all four audit modules with unit tests
**Phase 3 — API Layer:** REST endpoints and WebSocket, integration tests
**Phase 4 — Dashboard:** Frontend with live monitoring and test triggering
**Phase 5 — Polish:** README, screenshots, end-to-end validation against Proton VPN

## Task Breakdown Preview

- [ ] **Task 1: Project scaffolding & dependencies** — Directory structure, `requirements.txt`, FastAPI app skeleton with health check, `pytest` setup
- [ ] **Task 2: Leak detection module** — DNS/WebRTC/IPv6 leak detection in `leak_detect.py` with unit tests
- [ ] **Task 3: Traffic fingerprinting module** — Packet capture and protocol signature analysis in `fingerprint.py` with unit tests
- [ ] **Task 4: Connection monitoring module** — Real-time interface/IP/latency monitoring in `monitor.py` with unit tests
- [ ] **Task 5: Kill switch audit module** — Traffic leak detection during VPN disconnect in `killswitch.py` with unit tests
- [ ] **Task 6: REST API endpoints** — All `/api/*` routes wired to core modules, integration tests
- [ ] **Task 7: WebSocket real-time monitoring** — `/ws/monitor` endpoint streaming connection state, integration test
- [ ] **Task 8: Web dashboard** — Two-panel HTML/CSS/JS dashboard with live monitoring and test controls
- [ ] **Task 9: Documentation & polish** — README with setup instructions, screenshots, final validation against Proton VPN

## Dependencies

### External Libraries
- `fastapi` + `uvicorn` — web server and API
- `scapy` — packet capture and analysis
- `psutil` — network interface and system monitoring
- `pytest` + `pytest-asyncio` — testing

### Runtime Requirements
- Python 3.10+
- Admin/root privileges (for Scapy packet capture)
- Active VPN connection (for meaningful test results)
- Proton VPN (primary validation target)

## Success Criteria (Technical)

1. `pytest` passes with >80% coverage on core modules
2. All API endpoints return correct JSON structure and status codes
3. WebSocket streams connection updates at ≥1Hz
4. Dashboard renders two-panel layout and updates in real-time
5. Leak detection correctly flags DNS leaks when tested without VPN
6. Kill switch monitor detects traffic during simulated disconnect window
7. Full audit suite completes in <3 minutes
8. Clean code with docstrings on all public functions

## Estimated Effort

| Task | Estimate |
|------|----------|
| Project scaffolding | Small |
| Leak detection module | Medium |
| Traffic fingerprinting | Medium |
| Connection monitoring | Medium |
| Kill switch audit | Medium |
| REST API endpoints | Small-Medium |
| WebSocket monitoring | Small |
| Web dashboard | Medium-Large |
| Documentation & polish | Small |
| **Total** | **~9 tasks** |

Critical path: Tasks 1 → 2-5 (parallel) → 6-7 → 8 → 9

## Tasks Created
- [ ] #2 - Project Scaffolding & Dependencies (parallel: false)
- [ ] #3 - Leak Detection Module (parallel: true)
- [ ] #5 - Traffic Fingerprinting Module (parallel: true)
- [ ] #6 - Connection Monitoring Module (parallel: true)
- [ ] #8 - Kill Switch Audit Module (parallel: true)
- [ ] #10 - REST API Endpoints (parallel: false)
- [ ] #4 - WebSocket Real-Time Monitoring (parallel: true)
- [ ] #7 - Web Dashboard (parallel: false)
- [ ] #9 - Documentation & Polish (parallel: false)

Total tasks: 9
Parallel tasks: 5
Sequential tasks: 4
Estimated total effort: 32-45 hours
