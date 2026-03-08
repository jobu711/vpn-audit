---
name: vpn-audit
description: Local Python-based VPN privacy audit suite with web dashboard for leak detection, traffic analysis, connection monitoring, and kill switch testing
status: backlog
created: 2026-02-09T15:21:31Z
---

# PRD: VPN Privacy Audit Suite

## Executive Summary

A local Python-based VPN privacy audit suite with a polished web dashboard. The tool audits VPN connection privacy by detecting DNS/WebRTC/IPv6 leaks, analyzing traffic fingerprints, monitoring connections in real-time, and testing kill switch reliability. Designed as a cybersecurity portfolio project demonstrating practical security tool-building skills.

The primary test target is Proton VPN, with an architecture that supports other VPN providers.

## Problem Statement

VPN users trust their provider to protect all network traffic, but VPNs can fail silently — DNS queries leak to ISP resolvers, WebRTC exposes real IPs, IPv6 traffic bypasses the tunnel, and kill switches don't always activate fast enough. Existing leak-test tools are typically browser-based, one-shot checks that don't provide continuous monitoring or test kill switch behavior under real disconnection scenarios.

This tool addresses that gap by providing a local, comprehensive audit suite that tests a VPN connection across multiple failure modes and presents results through a professional dashboard.

## User Stories

### US-1: Run a Full VPN Audit
**As a** security-conscious user,
**I want to** run a comprehensive audit of my active VPN connection,
**So that** I can verify my VPN is properly protecting my privacy.

**Acceptance Criteria:**
- User starts the tool and sees a dashboard with real-time connection status
- All four audit modules (leak detection, traffic fingerprinting, connection monitoring, kill switch) can be triggered from the dashboard
- Results are displayed with clear pass/fail/warning indicators
- A summary report is generated after all tests complete

### US-2: Detect DNS/WebRTC/IPv6 Leaks
**As a** user running a VPN,
**I want to** detect if my DNS queries, WebRTC connections, or IPv6 traffic leak outside the VPN tunnel,
**So that** I can identify and fix privacy exposures.

**Acceptance Criteria:**
- DNS leak test compares resolver IPs against expected VPN provider resolvers
- WebRTC leak test detects browser IP exposure via WebRTC
- IPv6 leak test identifies IPv6 traffic bypassing the VPN tunnel
- Each test produces a clear pass/fail result with details

### US-3: Monitor Connection in Real-Time
**As a** user,
**I want to** see live monitoring of my network interfaces, IP addresses, and connection state,
**So that** I can observe VPN behavior over time.

**Acceptance Criteria:**
- Dashboard left panel shows live connection data via WebSocket
- Displays active network interfaces, current IP, and connection state
- Tracks IP address changes and routing table modifications
- Shows bandwidth and latency metrics

### US-4: Test Kill Switch Reliability
**As a** user who relies on a VPN kill switch,
**I want to** test whether the kill switch activates properly during VPN disconnection,
**So that** I know my traffic won't leak during reconnection windows.

**Acceptance Criteria:**
- Tool simulates VPN disconnection scenarios
- Monitors for traffic leaks during the reconnection window
- Reports kill switch response time
- Provides actionable pass/fail result

### US-5: Analyze Traffic Fingerprint
**As a** privacy-conscious user,
**I want to** know if my VPN traffic is distinguishable from regular traffic,
**So that** I understand my exposure to traffic fingerprinting.

**Acceptance Criteria:**
- Analyzes traffic patterns to detect VPN protocol signatures
- Reports whether VPN traffic is distinguishable from regular traffic
- Identifies protocol-level metadata exposure

## Requirements

### Functional Requirements

#### FR-1: Leak Detection Module
- DNS leak detection: capture DNS queries and compare resolver IPs against VPN provider expectations
- WebRTC leak detection: detect local/public IP exposure via WebRTC mechanisms
- IPv6 leak detection: identify IPv6 traffic that bypasses the VPN tunnel
- Each test returns structured results (pass/fail/warning + details)

#### FR-2: Traffic Fingerprinting Module
- Capture and analyze traffic patterns on the active interface
- Detect VPN protocol signatures (OpenVPN, WireGuard, IPSec)
- Assess whether VPN traffic is distinguishable from regular HTTPS traffic
- Report on protocol-level metadata exposure

#### FR-3: Connection Monitoring Module
- Real-time monitoring of active network interfaces
- Track connection state changes (connected, disconnected, reconnecting)
- Log IP address changes and routing table modifications
- Measure and display bandwidth and latency metrics
- Push updates to dashboard via WebSocket

#### FR-4: Kill Switch Audit Module
- Simulate VPN disconnection scenarios
- Monitor all interfaces for traffic leaks during reconnection window
- Measure kill switch response time (time from disconnect to traffic block)
- Report reliability as pass/fail with timing data

#### FR-5: REST API
- Endpoints to trigger each audit module independently
- Endpoint to run full audit suite
- Endpoints to retrieve latest results and connection status
- WebSocket endpoint for real-time monitoring data

#### FR-6: Web Dashboard
- Two-panel layout: live monitoring (left) + test results (right)
- Real-time data updates via WebSocket
- Visual indicators for pass/fail/warning states
- Clean, professional design suitable for portfolio presentation
- Responsive enough to work on common screen sizes

### Non-Functional Requirements

#### NFR-1: Performance
- Dashboard loads within 3 seconds on localhost
- WebSocket updates at least every 1 second for live monitoring
- Individual audit tests complete within 30 seconds each
- Full audit suite completes within 3 minutes

#### NFR-2: Security
- Runs entirely locally — no external data collection or transmission
- No sensitive data persisted to disk beyond the current session (unless user opts in)
- Packet capture scoped to audit purposes only
- Requires appropriate privileges for packet capture (admin/root)

#### NFR-3: Compatibility
- Python 3.10+
- Windows primary support, Linux secondary
- Works with Proton VPN as primary target
- Architecture supports other VPN providers without code changes

#### NFR-4: Code Quality
- Clean, well-documented code suitable for portfolio review
- Unit tests for core detection logic
- Integration tests for API endpoints
- Comprehensive README with setup instructions and screenshots

## Success Criteria

1. Dashboard loads and displays real-time connection status
2. All four audit modules produce meaningful results against Proton VPN
3. Leak detection correctly identifies known leak scenarios (DNS, WebRTC, IPv6)
4. Kill switch test provides actionable pass/fail results with response timing
5. Traffic fingerprinting reports on protocol visibility
6. Code is clean, documented, and demonstrates security awareness
7. README provides clear setup and usage instructions with screenshots

## Constraints & Assumptions

### Constraints
- **Language:** Python 3.10+ for all backend logic
- **Execution:** Local only — no cloud services, no external data collection
- **Platform:** Windows primary, Linux secondary
- **Purpose:** Portfolio/educational — not a production security tool
- **Privileges:** Packet capture requires admin/root access

### Assumptions
- User has Python 3.10+ installed
- User has admin/root privileges for packet capture
- User has an active VPN connection to test against
- Proton VPN is available for primary testing
- Network interfaces are accessible via standard Python libraries (Scapy)

## Out of Scope

- Mobile platform support
- Cloud-hosted or SaaS deployment
- Automated VPN provider comparison or recommendation
- VPN client management (connecting/disconnecting VPN)
- Historical audit data persistence across sessions
- Multi-user support or authentication
- Browser extension for WebRTC testing (server-side detection only)
- Support for enterprise VPN solutions (Cisco AnyConnect, Palo Alto GlobalProtect)

## Dependencies

### Technical Dependencies
- **Python 3.10+** — runtime
- **Flask or FastAPI** — web framework and REST API
- **Scapy** — packet capture and network analysis
- **WebSocket library** (e.g., python-socketio or websockets) — real-time dashboard updates
- **SQLite or in-memory store** — session data storage
- **Modern CSS** — dashboard styling (no heavy frameworks required)

### Development Dependencies
- **pytest** — unit and integration testing
- **Proton VPN** — primary test target for validation
- **Admin/root access** — required for packet capture during development and testing

## Technical Notes

### Architecture
```
vpn-audit/
├── backend/
│   ├── app.py              # Flask/FastAPI entry point
│   ├── api/                # REST API routes
│   ├── core/
│   │   ├── leak_detect.py  # DNS/WebRTC/IPv6 leak detection
│   │   ├── fingerprint.py  # Traffic fingerprinting
│   │   ├── monitor.py      # Connection monitoring
│   │   └── killswitch.py   # Kill switch testing
│   └── websocket/          # WebSocket handlers
├── frontend/
│   ├── index.html          # Dashboard
│   ├── css/
│   └── js/
├── tests/
│   ├── unit/
│   └── integration/
├── requirements.txt
└── README.md
```

### Key Design Decisions
- Scapy for packet capture (cross-platform, Python-native)
- WebSocket for real-time monitoring (low-latency push updates)
- Two-panel dashboard layout (monitoring + results side by side)
- Modular core engine (each audit type is an independent module)
