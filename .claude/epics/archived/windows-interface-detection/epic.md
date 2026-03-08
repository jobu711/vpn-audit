---
name: windows-interface-detection
description: Fix VPN tunnel interface detection on Windows where Scapy reports NPF device GUIDs instead of friendly names
status: completed
created: 2026-02-09T17:09:30Z
updated: 2026-02-09T17:32:32Z
completed: 2026-02-09T17:32:32Z
prd: windows-interface-detection
github: 11
---

# Windows Interface Detection

Fix VPN tunnel interface detection across all audit modules to work correctly on Windows, where Scapy and psutil report interfaces using NPF device GUIDs rather than friendly names.

## Background

The VPN audit tool classifies network interfaces as "tunnel" or "non-tunnel" by checking if the interface name starts with known prefixes (`tun`, `wg`, `proton`, `tap`, `utun`). On Linux/macOS this works correctly, but on Windows:

- Scapy reports interfaces as `\Device\NPF_{GUID}`
- psutil may report friendly names like `Ethernet`, `Wi-Fi`, or VPN adapter descriptions
- Neither format matches the Unix-style prefix list

This causes all three audit modules (kill switch, WebRTC leak, IPv6 leak) to misclassify VPN tunnel traffic as leaked traffic, producing false positive failures.

## Scope

1. Create a shared interface classification utility
2. Add Windows-specific interface resolution (GUID → friendly name / description matching)
3. Update killswitch.py and leak_detect.py to use the shared utility
4. Add cross-platform tests
