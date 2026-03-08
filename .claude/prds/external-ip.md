---
name: external-ip
description: External IP display with geolocation and VPN masking verification
status: backlog
created: 2026-02-10T12:20:58Z
---

# PRD: external-ip

## Executive Summary

Add external IP visibility to the VPN Audit Suite. The feature fetches the user's public IP address via a free API, displays geolocation and ISP information, and verifies that the VPN is properly masking the real IP. Data streams to a new dashboard widget via the existing WebSocket infrastructure.

## Problem Statement

Users currently see DNS/IPv6 leak results and kill switch status but have no direct visibility into their public-facing IP address. Without knowing their external IP, ISP, and apparent location, users cannot quickly verify whether their VPN is actually masking their identity. This is the most fundamental VPN check and is currently missing.

## User Stories

### US-1: View current external IP
**As a** VPN user
**I want to** see my current public IP address on the dashboard
**So that** I can verify it belongs to my VPN provider, not my ISP

**Acceptance Criteria:**
- Dashboard displays current external IPv4 address
- IP updates automatically via periodic polling
- Clear visual indicator when IP does not match VPN provider

### US-2: See geolocation and ISP info
**As a** VPN user
**I want to** see the country, city, and ISP associated with my public IP
**So that** I can confirm the VPN exit node location matches expectations

**Acceptance Criteria:**
- Dashboard shows country, city, and ISP/org name
- Country displayed with flag or code for quick recognition
- Info updates alongside the IP on each poll cycle

### US-3: Detect IP masking failure
**As a** VPN user
**I want to** be alerted if my real IP is exposed
**So that** I can take action before my privacy is compromised

**Acceptance Criteria:**
- Compares external IP against known VPN provider ranges or previous baseline
- Visual warning (red/yellow status) when IP appears to belong to user's ISP
- Status integrates with existing audit result model

## Requirements

### Functional Requirements

1. **External IP lookup** — Query a public API (e.g., ip-api.com) to retrieve:
   - Public IP address (IPv4)
   - Country and city
   - ISP / organization name
   - AS number (optional)

2. **Periodic polling** — Auto-refresh external IP data at a configurable interval (~10-30s) via the existing WebSocket stream.

3. **Dashboard widget** — New card on the frontend displaying:
   - Current external IP
   - Geo info (country, city)
   - ISP name
   - VPN masking status (good / warning)

4. **REST endpoint** — `GET /api/external-ip` for on-demand lookup, returning the same data as the WebSocket stream.

5. **VPN masking check** — Compare the external IP's ISP/org against the configured VPN provider to determine if masking is active.

### Non-Functional Requirements

- **Latency:** API lookup should complete in < 2 seconds
- **Rate limits:** Respect the free-tier rate limits of the chosen API (ip-api.com allows 45 req/min)
- **Fallback:** Gracefully handle API unavailability (show "unavailable" rather than crash)
- **Privacy:** No IP data is stored persistently or sent anywhere except the chosen lookup API

## Success Criteria

- External IP and geo info display correctly on the dashboard
- Widget auto-updates at the configured polling interval
- VPN masking status correctly identifies VPN vs ISP IPs
- All new code covered by tests (mocking the external API)
- No regressions in existing test suite

## Constraints & Assumptions

- Assumes internet connectivity for the external API call
- Free-tier API (ip-api.com) is sufficient; no API key needed for basic usage
- IPv4 only for initial implementation
- VPN provider detection is heuristic (ISP name matching), not authoritative

## Out of Scope

- IPv6 external IP lookup (handled separately by leak detection)
- Historical IP logging or timeline
- Multiple simultaneous VPN connection tracking
- Paid/premium IP geolocation APIs
- Tor exit node detection

## Dependencies

- External: ip-api.com (or equivalent free IP geolocation API)
- Internal: Existing WebSocket infrastructure (`backend/api/websocket.py`)
- Internal: Existing dashboard layout (`frontend/index.html`, `frontend/js/app.js`)
- Internal: `AuditResult` model (`backend/core/models.py`)
