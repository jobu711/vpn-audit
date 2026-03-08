---
created: 2026-03-07T23:56:33Z
last_updated: 2026-03-07T23:56:33Z
version: 1.0
author: Claude Code PM System
---

# System Patterns

## Architecture Style

Modular monolith — single FastAPI process serving both REST API and static frontend. Core audit modules are independent classes with a uniform `run() -> AuditResult` interface.

## Key Design Patterns

### Uniform Result Model
All core modules return `AuditResult(status, details, timestamp)` where status is `pass`, `fail`, or `warning`. This provides a consistent contract between core modules, API routes, and the frontend.

### In-Memory Storage
Audit results are stored in a module-level `_results` dict in `routes.py`. No database — the tool is session-based and results reset on restart.

### Shared Interface Classification
`interfaces.py` provides `is_tunnel_interface()` used by leak_detect, killswitch, and monitor to consistently identify VPN tunnel interfaces across platforms. Windows uses NPF GUID resolution; Linux/macOS uses prefix matching.

### WebSocket Change Detection
`monitor.py` streams connection state at ~1 Hz but only emits events when state actually changes. The WebSocket handler in `websocket.py` relays these to all connected clients.

### Cache-on-Read
`ExternalIPChecker` caches ip-api.com responses with a configurable TTL (default 30s) to avoid rate limiting and reduce latency.

### Pattern-Based VPN Detection
VPN masking detection uses string pattern matching against ISP/org fields from ip-api.com, checking against a list of known VPN provider names and hosting companies.

## Data Flow

```
Browser → REST POST /api/audit/* → routes.py → core module.run() → AuditResult → JSON response
Browser → WS /ws/monitor → websocket.py → monitor.stream() → state dicts → JSON frames
```

## Testing Strategy

- All external dependencies (Scapy sniff, psutil, subprocess) are mocked in tests
- Tests exercise real business logic (protocol detection, leak classification, routing parsing)
- Async test client via httpx ASGITransport — no running server needed
- 146 tests across 9 test files
