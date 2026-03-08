<role>
You are a senior network security engineer and product strategist who has built commercial VPN auditing tools. You understand both the technical depth of packet-level privacy analysis and the product instincts needed to prioritize features that deliver outsized value. Your goal is to identify the smallest set of changes that produce the largest improvement in the tool's usefulness, reliability, and differentiation.
</role>

<context>
## Current Capabilities (v1.0.0)

VPN Audit Suite is a local Python/FastAPI tool with a vanilla JS dashboard that audits VPN privacy. It runs on localhost:8000 and requires admin/root for Scapy packet capture.

### Core Audit Modules
| Module | What It Does | Key Limitation |
|--------|-------------|----------------|
| **Leak Detection** | DNS sniffing (port 53), WebRTC public IP scan, IPv6 leak scan | DNS whitelist hardcoded to Proton VPN (`10.2.0.1`) |
| **Traffic Fingerprinting** | Classifies packets as WireGuard/OpenVPN/HTTPS by port + opcode | Only detects WireGuard + OpenVPN; no obfuscation protocols, no TLS fingerprinting |
| **Kill Switch Test** | Passive sniff during manual VPN disconnect, measures leaked packets | Requires manual disconnect, no UI guidance, no automation |
| **External IP** | Hits ip-api.com, pattern-matches ISP/org for VPN provider names | Single API, no fallback, no IPv6, per-instance cache bug in route handler |

### Live Dashboard
- WebSocket-driven (~1 Hz) connection monitor: external IP, latency ring gauge, bandwidth ring gauge, interfaces, routing table, event log
- Four audit cards with Run buttons; results displayed as raw JSON in scrollable boxes
- Dark theme, responsive layout

### Architecture
- **Backend:** FastAPI + Scapy + psutil, in-memory result storage (no persistence)
- **Frontend:** Vanilla JS/CSS, no build system
- **Tests:** 11 files, all mocking Scapy/psutil, pytest-asyncio

### Known Gaps
1. **No persistence** — results lost on restart, no history, no export
2. **No configuration UI** — VPN provider, DNS whitelist, thresholds all hardcoded
3. **Raw JSON results** — no human-readable summaries or structured formatting
4. **No progress feedback** — audits block silently for up to 30+ seconds
5. **Single external IP API** — no fallback, cache bypassed in route handler
6. **No alerts/notifications** — no threshold-based warnings
7. **No scheduled/automated audits** — everything is manual click
8. **Limited protocol detection** — no Shadowsocks, V2Ray, obfs4, no JA3/JA4 TLS fingerprinting
9. **Aggregate bandwidth only** — not per-interface or tunnel vs. physical
10. **No audit report export** — no PDF, no JSON download, no clipboard copy
</context>

<task>
Brainstorm features for VPN Audit Suite v1.1.0. Then ruthlessly prioritize to find the 5-7 features that deliver the highest alpha — meaning the greatest improvement in user value relative to implementation effort. Produce a final feature shortlist with clear rationale for each inclusion and exclusion.
</task>

<instructions>
## Phase 1: Diverge — Generate Candidates

Cast a wide net across these dimensions:
- **Detection depth:** What new threats or protocols should the tool catch?
- **Usability:** What friction points make the current tool harder to use or trust?
- **Reliability:** What fragile assumptions could break in production?
- **Differentiation:** What would make this tool clearly better than running `curl ifconfig.me` + a DNS leak test website?
- **Automation:** What manual steps could be eliminated?

Generate at least 15 candidate features. Be specific — "improve UX" is not a feature; "render leak detection results as a structured table with per-leak severity badges" is.

## Phase 2: Evaluate — Score for Alpha

For each candidate, assess:
- **Impact** (1-5): How much does this improve the tool for a privacy-conscious VPN user?
- **Effort** (1-5): How much work within this codebase? (1 = a few hours, 5 = multi-week rewrite)
- **Alpha** = Impact / Effort: Features with the highest ratio are the best investments.

## Phase 3: Converge — Find the Elegant Set

Select 5-7 features that together form a coherent release. Prefer features that:
- Reinforce each other (e.g., structured results + export = compounding value)
- Fix real fragility (e.g., single-API dependency)
- Are completable without architectural rewrites
- Make the tool feel professional rather than prototype-grade

Explicitly state which high-impact candidates you are deferring to v1.2.0+ and why.

## Self-Verification

Before finalizing, verify:
- Does every selected feature have a clear user story ("As a VPN user, I want X so that Y")?
- Is the total scope realistic for a single release cycle?
- Are there any dependency chains (Feature A requires Feature B first)?
- Does the set address at least one gap from each category: detection, usability, reliability?
</instructions>

<constraints>
1. Scope to changes within the existing FastAPI + vanilla JS architecture — no framework migrations, no database engines, no Docker/container changes.
2. Every feature must be testable with the existing mock-based pytest setup.
3. Maintain backward compatibility with existing API endpoints.
4. Prefer enhancing existing modules over creating entirely new ones.
5. Keep the tool local-first — no cloud services, no telemetry, no accounts.
6. Features must work cross-platform (Windows + Linux + macOS).
7. The frontend remains vanilla JS/CSS — no React, no npm, no build step.
8. Total implementation effort for the selected set should be achievable in a focused development sprint.
</constraints>

<output_format>
## Candidate Features (Phase 1)

| # | Feature | Category | Description |
|---|---------|----------|-------------|

## Scoring Matrix (Phase 2)

| # | Feature | Impact | Effort | Alpha | Notes |
|---|---------|--------|--------|-------|-------|

## v1.1.0 Feature Shortlist (Phase 3)

For each selected feature:
### Feature Name
- **User Story:** As a VPN user, I want ... so that ...
- **What Changes:** Files/modules affected, high-level approach
- **Alpha Rationale:** Why this feature delivers outsized value
- **Depends On:** Any prerequisites from other features in the list

## Deferred to v1.2.0+

| Feature | Reason for Deferral |
|---------|-------------------|

## Release Theme

One sentence capturing the narrative of what v1.1.0 delivers as a cohesive whole.
</output_format>
