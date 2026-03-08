---
created: 2026-03-07T23:56:33Z
last_updated: 2026-03-07T23:56:33Z
version: 1.0
author: Claude Code PM System
---

# Project Overview

## Current State

Fully functional MVP. All core audit modules implemented and tested. Web dashboard operational with live monitoring.

## Features

### Leak Detection (complete)
- DNS leak detection — sniffs for non-VPN resolver queries
- WebRTC leak detection — scans interfaces for exposed public IPs
- IPv6 leak detection — flags non-link-local IPv6 on non-tunnel interfaces

### Traffic Fingerprinting (complete)
- WireGuard protocol detection (UDP port 51820 + packet signatures)
- OpenVPN detection (UDP 1194 + TCP 443 with opcode headers)
- HTTPS classification for remaining traffic
- VPN-to-total ratio analysis

### Kill Switch Testing (complete)
- Captures traffic on all interfaces during VPN disconnect
- Detects leaked packets on non-tunnel interfaces
- Measures time-to-block after tunnel drops
- Filters out VPN transport traffic (not actual leaks)

### Connection Monitor (complete)
- Real-time interface status, routing tables, latency, bandwidth
- WebSocket streaming at ~1 Hz with change detection
- External IP geolocation with VPN masking detection

### Web Dashboard (complete)
- Dark-themed two-panel layout
- SVG ring gauges for latency/bandwidth
- Live event log, one-click audit controls
- External IP widget with masked/exposed status

## Integration Points

- ip-api.com — external IP geolocation lookup (30s cache TTL)
- System network stack — Scapy for packet capture, psutil for interface info
- OS routing table — parsed from `route print` (Windows) or `ip route` (Linux)
