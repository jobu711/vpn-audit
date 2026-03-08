# VPN Privacy Audit Suite

## What This Is

A local Python-based VPN privacy audit suite with a polished web dashboard. The tool audits VPN connection privacy by detecting leaks, analyzing traffic patterns, monitoring connections, and testing kill switch behavior. Designed as a cybersecurity portfolio project that demonstrates practical tool-building skills.

## Core Value

Accurately detect when a VPN fails to protect user privacy — through DNS/WebRTC/IPv6 leak detection, traffic fingerprinting, real-time connection monitoring, and kill switch reliability testing.

## Architecture Overview

- **Backend:** Python (Flask or FastAPI) serving a REST API and WebSocket connections
- **Frontend:** Web dashboard with two-panel layout (live monitoring + test results)
- **Core Engine:** Python modules for packet capture, leak detection, traffic analysis
- **Execution Model:** Runs locally on the user's machine, tests their actual VPN connection

## Active Requirements

### Leak Detection
- DNS leak detection (compare DNS resolver IPs against VPN provider expectations)
- WebRTC leak detection (detect browser IP exposure via WebRTC)
- IPv6 leak detection (identify IPv6 traffic bypassing VPN tunnel)

### Traffic Fingerprinting
- Analyze traffic patterns to detect VPN protocol signatures
- Identify if VPN traffic is distinguishable from regular traffic
- Report on protocol-level metadata exposure

### Connection Monitoring
- Real-time monitoring of active network interfaces
- Track connection state changes (connected, disconnected, reconnecting)
- Log IP address changes and routing table modifications
- Display bandwidth and latency metrics

### Kill Switch Auditing
- Test kill switch behavior by simulating VPN disconnection scenarios
- Verify no traffic leaks during VPN reconnection windows
- Report on kill switch response time and reliability

### Dashboard
- Two-panel web interface: live monitoring (left) + test results (right)
- Real-time data updates via WebSocket
- Visual indicators for pass/fail/warning states
- Clean, professional design suitable for portfolio presentation

### Documentation & Testing
- Comprehensive README with setup instructions and screenshots
- Unit tests for core detection logic
- Integration tests for API endpoints

## Constraints

- **Language:** Python 3.10+
- **Execution:** Local only (no cloud services, no external data collection)
- **Primary Test Target:** Proton VPN (but architecture should support other providers)
- **Platform:** Windows primary, Linux secondary
- **Purpose:** Portfolio/educational — not a production security tool

## Success Criteria

1. Dashboard loads and displays real-time connection status
2. All four audit modules produce meaningful results against Proton VPN
3. Leak detection correctly identifies known leak scenarios
4. Kill switch test provides actionable pass/fail results
5. Code is clean, documented, and demonstrates security awareness
6. README provides clear setup and usage instructions

## Tech Stack Preferences

- Python for all backend logic
- Lightweight web framework (Flask/FastAPI)
- Scapy or similar for packet capture
- Modern CSS for dashboard (no heavy frameworks required)
- SQLite or in-memory storage for session data
