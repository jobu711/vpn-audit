---
created: 2026-03-07T23:56:33Z
last_updated: 2026-03-07T23:56:33Z
version: 1.0
author: Claude Code PM System
---

# Product Context

## User Personas

### Primary: Privacy-Conscious VPN User
- Uses Proton VPN for daily browsing
- Wants proof their VPN isn't leaking
- Technical enough to run a local tool but prefers a GUI over CLI
- Needs clear pass/fail answers, not raw packet dumps

### Secondary: Network Security Enthusiast
- Evaluating VPN configurations
- Wants detailed protocol fingerprinting data
- Comfortable with technical details in results

## Core Use Cases

1. **Quick Privacy Check** — Run full audit to verify no leaks are occurring
2. **Leak Investigation** — Run specific leak detection (DNS/WebRTC/IPv6) when suspicious
3. **Kill Switch Verification** — Test that disconnecting VPN blocks all traffic
4. **Traffic Analysis** — Check if VPN protocol is distinguishable from HTTPS
5. **Live Monitoring** — Watch connection state in real time during VPN changes

## User Experience

- Open browser to localhost:8000
- Left panel shows live connection state (always running)
- Right panel has one-click audit buttons
- Results show immediately as pass (green) / fail (red) / warning (yellow)
- External IP widget shows whether IP is masked by VPN

## Key Requirements

- Must run locally (no data leaves the machine except ip-api.com lookup)
- Must work with VPN connected and disconnected
- Admin privileges required (Scapy needs raw socket access)
- Results are session-only (no persistent storage)
