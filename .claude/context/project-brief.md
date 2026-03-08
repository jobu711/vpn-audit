---
created: 2026-03-07T23:56:33Z
last_updated: 2026-03-07T23:56:33Z
version: 1.0
author: Claude Code PM System
---

# Project Brief

## What It Does

VPN Privacy Audit Suite — a local network security tool that audits VPN privacy in real time. It detects leaks, fingerprints VPN traffic, tests kill switch reliability, and monitors connection state from a single web dashboard.

## Why It Exists

VPN users need confidence that their privacy is actually protected. This tool provides concrete, packet-level verification that a VPN is working correctly — not just connected, but actually masking traffic, preventing leaks, and blocking non-tunnel traffic on disconnect.

## Target Users

- Privacy-conscious VPN users (primarily Proton VPN)
- Network security enthusiasts
- Developers auditing VPN configurations

## Success Criteria

- Detect DNS, WebRTC, and IPv6 leaks with zero false negatives
- Accurately fingerprint WireGuard/OpenVPN protocol traffic
- Verify kill switch blocks all non-tunnel traffic within seconds
- Provide real-time connection monitoring via WebSocket
- Run entirely locally with no external dependencies beyond ip-api.com for IP geolocation

## Scope

- Single-user local tool (not a hosted service)
- Defaults to Proton VPN but patterns are configurable
- Cross-platform: Windows, Linux, macOS
- Requires admin/root for Scapy packet capture
