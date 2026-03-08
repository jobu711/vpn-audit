---
created: 2026-03-07T23:56:33Z
last_updated: 2026-03-07T23:56:33Z
version: 1.0
author: Claude Code PM System
---

# Tech Context

## Runtime

- **Python 3.10+** (user running 3.13.12)
- **OS:** Windows 11 Pro (cross-platform support for Linux/macOS)

## Dependencies (requirements.txt)

| Package | Version | Purpose |
|---------|---------|---------|
| fastapi | >=0.100.0 | Async web framework, REST + WebSocket |
| uvicorn | >=0.23.0 | ASGI server |
| websockets | >=11.0 | WebSocket protocol support |
| scapy | >=2.5.0 | Raw packet capture and protocol analysis |
| psutil | >=5.9.0 | Network interface and I/O counter introspection |
| pytest | >=7.4.0 | Test framework |
| pytest-asyncio | >=0.21.0 | Async test support |
| httpx | >=0.24.0 | Async HTTP client for testing |

## Development Tools

- **Testing:** pytest with `asyncio_mode = "auto"` (pyproject.toml)
- **Test client:** httpx.AsyncClient with ASGITransport (no running server needed)
- **Launcher:** run.bat (Windows) — handles venv creation, dependency install, admin check

## External Services

- **ip-api.com** — Free IP geolocation API (no key required), 30s cache TTL
- No other external service dependencies

## Platform-Specific Behavior

- **Windows:** NPF GUID resolution for network interface names, `route print` for routing table
- **Linux/macOS:** Prefix matching for tunnel interfaces (tun/wg/proton/tap/utun), `ip route` for routing table
- **Admin required:** Scapy needs elevated privileges for raw packet capture on all platforms
