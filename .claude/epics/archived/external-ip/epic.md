---
name: external-ip
status: backlog
created: 2026-02-10T12:22:28Z
progress: 0%
prd: .claude/prds/external-ip.md
github: https://github.com/jobu711/vpn-audit/issues/16
---

# Epic: external-ip

## Overview

Add external IP geolocation display and VPN masking verification to the dashboard. A new core module queries ip-api.com, caches results to respect rate limits, and exposes data via REST and the existing WebSocket stream. A new dashboard widget renders IP, location, ISP, and masking status.

## Architecture Decisions

- **Single free API (ip-api.com)** — No API key needed, returns IP + geo + ISP in one JSON call. Free tier allows 45 req/min.
- **Cache with TTL** — Cache the API response for ~30 seconds to stay well under rate limits while still providing periodic updates. The WebSocket monitor polls at 1 Hz but will serve cached data for external IP.
- **Integrate into existing WebSocket stream** — Add an `external_ip` field to the monitor snapshot dict rather than creating a separate WebSocket endpoint. This keeps the frontend simple and leverages existing infrastructure.
- **Heuristic VPN detection** — Compare the ISP/org field from the API against known VPN provider names (starting with Proton). Simple string matching, not authoritative.
- **No new dependencies** — Use Python's built-in `urllib.request` to call the API (already in stdlib), avoiding a new `requests`/`httpx` runtime dependency.

## Technical Approach

### Backend (`backend/core/external_ip.py`)
- `ExternalIPChecker` class with `lookup()` method
- Internal TTL cache (default 30s) to avoid hammering the API
- Returns dict: `{ip, country, city, isp, org, vpn_masked, status}`
- VPN masking check: compare ISP/org against configurable VPN provider patterns
- `run()` method returning `AuditResult` for consistency with other modules

### API Integration (`backend/api/routes.py`)
- `GET /api/external-ip` — On-demand lookup endpoint, same pattern as existing audit routes

### WebSocket Integration (`backend/core/monitor.py`)
- Add `external_ip` field to `snapshot()` output using cached lookup
- No change to polling interval — external IP data is served from cache

### Frontend (`frontend/index.html` + `frontend/js/app.js`)
- New widget card in the left monitor panel showing: IP address, country + city, ISP, VPN masking status badge
- Updated `handleMonitorUpdate()` to populate the widget from WebSocket data
- Color-coded status: green (masked), red (exposed), yellow (unknown)

## Task Breakdown Preview
- [ ] #17: Core external IP module with caching and VPN masking check
- [ ] #18: REST endpoint and WebSocket integration
- [ ] #19: Frontend dashboard widget
- [ ] #20: Tests for external IP module and API endpoint

## Dependencies

- **External:** ip-api.com free tier (HTTP, no auth)
- **Internal:** Existing `ConnectionMonitor`, `AuditResult`, WebSocket stream, dashboard layout

## Success Criteria (Technical)

- `GET /api/external-ip` returns IP, geo, ISP, and masking status
- WebSocket stream includes `external_ip` field with cached data
- Dashboard widget renders and auto-updates
- API response cached for 30s (verified by test)
- All new code has test coverage with mocked HTTP calls
- Existing test suite passes without modification

## Estimated Effort

- 4 tasks, each small and focused
- Core module and tests are the bulk of the work
- Frontend widget follows existing card patterns
- No infrastructure or deployment changes needed
