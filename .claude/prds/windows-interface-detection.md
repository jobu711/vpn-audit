---
name: windows-interface-detection
description: Fix VPN tunnel interface detection on Windows where Scapy reports NPF device GUIDs instead of friendly names
status: in-progress
created: 2026-02-09T17:09:30Z
updated: 2026-02-09T17:09:30Z
---

# Windows Interface Detection

## Problem

On Windows, Scapy reports network interfaces using NPF device paths (e.g., `\Device\NPF_{GUID}`) rather than friendly names like `tun0` or `wg0`. The current tunnel detection logic uses prefix matching against Linux/macOS interface names, causing **all interfaces on Windows to be classified as non-tunnel**. This produces false positive "fail" results for kill switch, WebRTC, and IPv6 leak audits.

## Affected Modules

- `backend/core/killswitch.py` — `TUNNEL_INTERFACE_PREFIXES` and `_is_tunnel_interface()`
- `backend/core/leak_detect.py` — duplicate `TUNNEL_INTERFACE_PREFIXES` and inline `startswith()` checks

## Requirements

1. **Centralize tunnel interface detection** — Extract `TUNNEL_INTERFACE_PREFIXES` and classification logic into a shared utility so it's defined once
2. **Windows interface resolution** — On Windows, resolve NPF device GUIDs to friendly names (or match against known VPN adapter descriptions) before classifying
3. **Cross-platform correctness** — Maintain existing behavior on Linux/macOS while adding Windows support
4. **Tests** — Add Windows-specific test cases for interface classification (mocked, no real hardware needed)

## Success Criteria

- Kill switch audit correctly identifies ProtonVPN/WireGuard/OpenVPN tunnel interfaces on Windows
- Leak detection (WebRTC, IPv6) correctly skips VPN tunnel interfaces on Windows
- No duplicate constant definitions across modules
- All existing tests continue to pass
- New tests cover Windows NPF GUID interface names
