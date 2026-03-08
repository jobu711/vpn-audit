# Research: reliability-and-polish

## PRD Summary

Four focused improvements for v1.1.0:
1. **External IP Fallback + Cache Fix** — Add ipinfo.io/ifconfig.me fallbacks; fix cache bug where `routes.py` instantiates a fresh `ExternalIPChecker` per request
2. **Structured Result Rendering** — Replace `JSON.stringify` in audit cards with per-module tables and severity badges
3. **Per-Interface Bandwidth** — Change `psutil.net_io_counters()` to `pernic=True` to reveal split-tunneling leaks
4. **Async Execution Fixes** — Wrap blocking `sniff()`/`subprocess.run()`/`time.sleep()` calls in `run_in_executor` to stop freezing the event loop

## Relevant Existing Modules

| Module | Role in PRD |
|--------|-------------|
| `backend/core/external_ip.py` | F1: Add fallback API chain, `source` field, improve error resilience |
| `backend/api/routes.py` | F1: Singleton `ExternalIPChecker`; F4: `run_in_executor` wrapping for all audit endpoints |
| `backend/core/monitor.py` | F3: `pernic=True` bandwidth; F4: Fix blocking `time.sleep(0.5)` and `subprocess.run()` |
| `backend/core/interfaces.py` | F3: `is_tunnel_interface()` needed for bandwidth flagging (not currently imported by monitor.py) |
| `frontend/js/app.js` | F2: Replace `renderSingleResult()` JSON dump; F3: Handle `bandwidth_per_interface` dict |
| `frontend/css/style.css` | F2: Add result table styles, per-field badges |
| `frontend/index.html` | No changes expected (existing DOM structure sufficient) |

## Existing Patterns to Reuse

### Error handling pattern (routes.py)
All route handlers use `try/except Exception` returning `JSONResponse(status_code=500, content={"error": str(exc)})`. New executor-wrapped handlers should preserve this pattern.

### Module-level singleton pattern (routes.py)
`_results: dict[str, dict] = {}` is already a module-level singleton. The `ExternalIPChecker` singleton should follow the same pattern: `_ip_checker = ExternalIPChecker()` at module scope.

### HTTP call pattern (external_ip.py)
`urllib.request.Request` + `urlopen` with context manager — lines 52-54. The fallback chain replicates this pattern per URL.

### CSS status variables (style.css)
`--color-pass` (#4caf50), `--color-fail` (#f44336), `--color-warning` (#ff9800) and their `-bg` variants. `.result-status.pass/fail/warning` badge classes exist and can be reused for per-field indicators.

### Frontend sub-result pattern (app.js)
`renderFullResult()` already renders structured sub-results with label + status badge (`.sub-result` / `.sub-result-label` / `.sub-result-status`). This is the template for per-field rendering in structured results.

### Async sleep pattern (monitor.py)
`await asyncio.sleep(self.poll_interval)` at line 220 — model for converting `time.sleep` calls.

## Existing Code to Extend

### `backend/core/external_ip.py`
- Line 25: `_API_URL` is a single string — needs to become a list of `(url, parser)` tuples
- Lines 51-84: `lookup()` has one try/except — needs a for-loop over fallback URLs with per-URL try/except
- Lines 60-68: Result dict lacks `source` field — add it
- Lines 82-83: Cache writes error results too — consider returning stale cache on all-fail instead

### `backend/api/routes.py`
- Line 86: `checker = ExternalIPChecker()` inside handler — promote to line ~17: `_ip_checker = ExternalIPChecker()`
- Lines 21-79: All audit handlers call `.run()` synchronously — wrap each in `await asyncio.get_event_loop().run_in_executor(None, ...)`
- Line 98: `ConnectionMonitor()` also instantiated per request — secondary singleton candidate

### `backend/core/monitor.py`
- Lines 161-162: `psutil.net_io_counters()` — change to `pernic=True`, compute per-interface deltas
- Line 163: `time.sleep(sample_interval)` — wrap in executor or restructure
- Line 181: `snapshot()` return dict — add `bandwidth_per_interface` field
- Need to `from backend.core.interfaces import is_tunnel_interface` — currently not imported

### `frontend/js/app.js`
- Lines 375-402: `renderSingleResult()` — replace JSON dump with dispatch to per-module renderers
- Lines 199-206: `updateGauges()` bandwidth section — needs to handle new `bandwidth_per_interface` dict
- Lines 212-235: `updateInterfaces()` — add per-interface bandwidth indicator

## Potential Conflicts

### 1. ExternalIPChecker singleton breaks test mocks (CRITICAL)
**Current test pattern** (`test_api.py` lines 214, 228):
```python
with patch("backend.api.routes.ExternalIPChecker") as MockCls:
    MockCls.return_value.lookup.return_value = mock_data
```
This patches the class at the import path. With a module-level singleton `_ip_checker = ExternalIPChecker()`, the instance is created at import time before the patch takes effect.

**Mitigation:** Change tests to patch the instance directly:
```python
with patch("backend.api.routes._ip_checker") as mock_checker:
    mock_checker.lookup.return_value = mock_data
```

### 2. `net_io_counters(pernic=True)` changes return type
**Current mock** (`test_monitor.py` lines 203-213): Returns flat `FAKE_IO` namedtuples.
With `pernic=True`, psutil returns `dict[str, snetio]`.

**Mitigation:** Update `side_effect` to return `{"eth0": FAKE_IO(...), "lo": FAKE_IO(...)}` dicts.

### 3. `bandwidth_mbps` type change risks frontend breakage
**Current:** `data.bandwidth_mbps` is a `float`. Frontend calls `.toFixed(1)` on it.
**After F3:** Must keep `bandwidth_mbps` as a float (aggregate sum) for backward compatibility. Add `bandwidth_per_interface` as a new dict field.

**Mitigation:** Compute aggregate sum in `estimate_bandwidth()` and return both. The WebSocket payload adds a new field without changing the existing one.

### 4. Structured rendering must handle all detail shapes
Each module returns different `details` keys:
- Leaks: `{dns: {leaked_servers}, webrtc: {public_ips}, ipv6: {ipv6_leaks}}`
- Fingerprint: `{total_packets, wireguard_packets, openvpn_packets, https_packets, other_packets, vpn_ratio, reason, ...}`
- Killswitch: `{duration, total_packets, tunnel_packets, leaked_packets, interfaces, time_to_block}`

**Mitigation:** `renderSingleResult()` needs to detect the module type (check for `dns` key → leaks, `wireguard_packets` key → fingerprint, `tunnel_packets` key → killswitch) and dispatch to per-module renderers.

### 5. `time.sleep` mock in bandwidth tests
`test_monitor.py` asserts `mock_sleep.assert_called_once_with(0.5)`. If `time.sleep` is replaced with executor-based approach, this assertion breaks.

**Mitigation:** If bandwidth computation stays synchronous but is called via executor, `time.sleep` stays and the mock still works. Only needs updating if the approach changes to `asyncio.sleep`.

## Open Questions

1. **ipinfo.io response normalization:** ipinfo.io returns `{ip, city, region, country, org, ...}` — no `isp` field. How to extract ISP from the `org` field (format: `"AS15169 Google LLC"`)? Need to strip AS prefix.

2. **ifconfig.me response format:** `/all.json` returns `{ip_addr, remote_host, user_agent, port, method, encoding, mime, via, forwarded}` — no geo/ISP data at all. This can only serve as an IP-only fallback. Should VPN masking detection be skipped for this source?

3. **Executor wrapping granularity for `/api/audit/full`:** Should the three sequential audit calls each run in separate executor calls (allowing interleaving), or should the entire full-audit be a single executor call? Single is simpler; separate allows better concurrency but risks Scapy conflicts.

4. **Per-interface bandwidth threshold for warnings:** PRD says >0.1 Mbps on non-tunnel interfaces gets flagged. Is 0.1 Mbps the right threshold? Background system traffic (Windows Update, telemetry) may trigger false positives.

## Recommended Architecture

### F1: External IP Fallback
```python
_FALLBACK_APIS = [
    {"url": "http://ip-api.com/json/?fields=query,country,city,isp,org,as",
     "parser": _parse_ip_api},
    {"url": "https://ipinfo.io/json",
     "parser": _parse_ipinfo},
    {"url": "https://ifconfig.me/all.json",
     "parser": _parse_ifconfig},
]
```
Each parser normalizes to the common schema. `lookup()` iterates the list, returning on first success. Module-level singleton in `routes.py`: `_ip_checker = ExternalIPChecker()`.

### F2: Structured Rendering
Add three new functions in `app.js`:
- `renderLeaksResult(el, data)` — 3-row table (DNS/WebRTC/IPv6) with badges
- `renderFingerprintResult(el, data)` — protocol bar + stats
- `renderKillswitchResult(el, data)` — summary + interface breakdown

`renderSingleResult()` dispatches based on detail keys present:
```javascript
if (data.details && data.details.dns !== undefined) renderLeaksResult(el, data);
else if (data.details && data.details.wireguard_packets !== undefined) renderFingerprintResult(el, data);
else if (data.details && data.details.tunnel_packets !== undefined) renderKillswitchResult(el, data);
else renderGenericResult(el, data);  // fallback to current JSON
```

### F3: Per-Interface Bandwidth
`estimate_bandwidth()` returns `{"total": float, "per_interface": dict}`. `snapshot()` spreads this into `bandwidth_mbps` (total) and `bandwidth_per_interface` (dict). Frontend `updateInterfaces()` annotates each interface item with its bandwidth.

### F4: Async Fixes
Minimal-change approach using `asyncio.to_thread()` (Python 3.9+):
```python
@router.post("/audit/leaks")
async def audit_leaks():
    detector = LeakDetector()
    result = await asyncio.to_thread(detector.run)
    ...
```
`estimate_bandwidth()` stays synchronous but is called from `snapshot()` which is itself called via `await asyncio.to_thread(self.snapshot)` in `stream()`.

## Test Strategy Preview

### Existing patterns to follow
- Mock at module import path: `@patch("backend.core.external_ip.urllib.request.urlopen")`
- Named namedtuples for psutil mocks: `FAKE_IO`, `FAKE_ADDR`, `FAKE_STAT`
- `_mock_urlopen()` helper returns context-manager-compatible MagicMock
- `asyncio_mode = "auto"` in pyproject.toml — `@pytest.mark.asyncio` on async tests

### New tests needed

| Feature | File | Tests |
|---------|------|-------|
| F1 | `tests/test_external_ip.py` | `test_fallback_on_primary_failure`, `test_fallback_on_timeout`, `test_all_apis_fail_returns_cached`, `test_all_apis_fail_no_cache_returns_error`, `test_source_field_present` |
| F1 | `tests/test_api.py` | Update `test_external_ip_*` to patch `_ip_checker` instance instead of class |
| F3 | `tests/test_monitor.py` | Update `TestBandwidth` mocks to return pernic dict, add `test_bandwidth_per_interface`, `test_bandwidth_flags_non_tunnel` |
| F4 | `tests/test_api.py` | Verify response format unchanged after executor wrapping (existing tests sufficient if mock patterns updated) |

### Tests that MUST be updated
1. `test_api.py` lines 214, 228: `ExternalIPChecker` mock path changes
2. `test_monitor.py` lines 203-213: `net_io_counters` mock return shape changes
3. `test_monitor.py` lines 221-250: `TestSnapshot` bandwidth mock shape changes

## Estimated Complexity

**Medium (M)** — 4 features, each individually small (S), but collectively touching 7+ files across backend and frontend with test updates. No architectural rewrites. No new dependencies. Estimated at 6-8 focused implementation issues.

Justification:
- F1 (External IP): S — add fallback loop + singleton, ~50 lines changed
- F2 (Structured Render): M — three new render functions + CSS, ~150 lines JS + ~50 lines CSS
- F3 (Per-Interface BW): S — `pernic=True` + frontend display, ~30 lines backend + ~30 lines frontend
- F4 (Async Fixes): S-M — `asyncio.to_thread` wrapping, straightforward but touches async flow, ~20 lines
- Test updates: S — mock path changes, ~30 lines across 2 files
