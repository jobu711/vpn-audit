---
name: v1.1.0-reliability-and-polish
status: backlog
created: 2026-03-08T00:46:02Z
progress: 0%
prd: .claude/prds/v1.1.0-reliability-and-polish.md
updated: 2026-03-08T00:52:01Z
github: https://github.com/jobu711/vpn-audit/issues/21
---

# Epic: v1.1.0 — Reliability & Polish

## Overview

Four backend + frontend improvements that harden the VPN Audit Suite: multi-API external IP fallback with cache fix, async audit execution to keep the dashboard responsive, per-interface bandwidth to detect split-tunnel leaks, and structured result rendering to replace raw JSON output.

## Architecture Decisions

- **Executor-based async wrapping** (Option B from PRD): Synchronous audit code and monitor helpers run via `run_in_executor(None, ...)` rather than rewriting them as async. This minimizes changes and avoids modifying the Scapy/psutil interface layer.
- **Module-level singleton** for `ExternalIPChecker` in `routes.py` to fix cache bypass bug. The `ConnectionMonitor` keeps its own instance.
- **No new files**: All rendering functions stay in `app.js`, all backend changes in existing modules.
- **No new dependencies**: Everything uses stdlib + existing deps (urllib, asyncio, psutil).

## Technical Approach

### Backend Changes

**`backend/core/external_ip.py`**
- Add ordered fallback API list: ip-api.com → ipinfo.io → ifconfig.me
- Normalize responses to common schema with `source` field
- Return cached result (status: "cached") when all APIs fail but cache exists

**`backend/api/routes.py`**
- Module-level `ExternalIPChecker()` singleton replaces per-request instantiation
- Wrap `LeakDetector().run()`, `TrafficFingerprinter().run()`, `KillSwitchTester().run()` in `run_in_executor`
- `/api/audit/full` runs all three sequentially in executor (Scapy not thread-safe)

**`backend/core/monitor.py`**
- `estimate_bandwidth()`: use `psutil.net_io_counters(pernic=True)`, compute per-interface deltas, return both aggregate and per-interface dict
- `snapshot()` wraps `estimate_bandwidth()`, `measure_latency()`, `get_routing_table()` via `run_in_executor` (becomes async)
- `stream()` already async — just awaits the now-async `snapshot()`

### Frontend Changes

**`frontend/js/app.js`**
- Replace `renderSingleResult` JSON dump with three module-specific renderers:
  - `renderLeakResult()`: 3-row table (DNS/WebRTC/IPv6) with pass/fail badges and detail expansion
  - `renderFingerprintResult()`: protocol breakdown table with % bars, VPN ratio color coding, verdict
  - `renderKillswitchResult()`: summary row + per-interface breakdown when leaks detected
- Per-interface bandwidth display in interface list items, with warning highlight on non-tunnel traffic >0.1 Mbps
- Full audit card dispatches to individual renderers

**`frontend/css/style.css`**
- Badge classes using existing CSS vars (`--color-pass`, `--color-fail`, `--color-warning`)
- Result table compact styling, bandwidth indicator styles

## Implementation Strategy

- **Order**: F1 → F4 → F3 → F2 (backend fixes first, frontend polish last)
- **All features are independent** — can be developed and merged separately
- **Testing**: Each task includes its own tests using existing mock patterns
- **Risk mitigation**: Executor wrapping is the safest async approach; no Scapy internals changed

## Task Breakdown Preview

- [ ] Task 1: External IP fallback chain + singleton cache fix (F1)
- [ ] Task 2: Async audit execution + async monitor helpers (F4)
- [ ] Task 3: Per-interface bandwidth — backend + frontend (F3)
- [ ] Task 4: Structured audit result rendering (F2)

## Dependencies

- **External**: ip-api.com, ipinfo.io, ifconfig.me (all free, no auth required)
- **Internal**: Existing `ExternalIPChecker`, `ConnectionMonitor`, `AuditResult` model, WebSocket infrastructure, dashboard layout
- **Prerequisite**: None — all features build on v1.0.0 codebase

## Success Criteria (Technical)

- `GET /api/external-ip` returns valid data when ip-api.com is unreachable
- Cache hit verified by mock call count (two calls within 30s = one HTTP request)
- 30s fingerprint audit does not freeze WebSocket monitor
- Per-interface bandwidth visible in dashboard, non-tunnel traffic flagged
- All three audit cards render structured tables (no raw JSON)
- `python -m pytest tests/ -v` passes with no regressions
- No new dependencies introduced

## Estimated Effort

- **Task 1** (External IP): Small — ~50 lines backend + tests
- **Task 2** (Async fixes): Medium — routes.py executor wrapping + monitor.py async snapshot
- **Task 3** (Per-interface BW): Medium — backend delta calculation + frontend display
- **Task 4** (Structured render): Medium — 3 render functions + CSS styling
- **Critical path**: Tasks are independent; Task 2 (async) is highest-risk due to event loop interaction

## Tasks Created

- [ ] #22 - External IP fallback chain + singleton cache fix (parallel: true, conflicts: #23)
- [ ] #23 - Async audit execution and async monitor helpers (parallel: true, conflicts: #22, #24)
- [ ] #24 - Per-interface bandwidth monitoring (parallel: true, conflicts: #23, #25)
- [ ] #25 - Structured audit result rendering (parallel: true, conflicts: #24)

Total tasks: 4
Parallel tasks: 4 (all independent, but coordinate on shared files)
Sequential tasks: 0
Recommended order: #22 → #23 → #24 → #25
Estimated total effort: 15-21 hours
