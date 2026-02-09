"""Shared interface classification utility for VPN tunnel detection.

Centralises VPN tunnel interface identification with cross-platform support.
On Linux/macOS, interfaces use friendly names (e.g. ``tun0``, ``wg0``) so a
simple prefix check suffices.  On Windows, Scapy reports interfaces as
``\\Device\\NPF_{GUID}`` paths, which must be resolved to adapter
descriptions via Scapy's ``get_windows_if_list()`` before matching against
known VPN adapter keywords.

Usage::

    from backend.core.interfaces import is_tunnel_interface, TUNNEL_INTERFACE_PREFIXES
"""

import logging
import platform
from typing import Optional

logger = logging.getLogger(__name__)

# ---- Single source of truth for tunnel interface prefixes ----
TUNNEL_INTERFACE_PREFIXES: tuple[str, ...] = (
    "tun",
    "wg",
    "proton",
    "tap",
    "utun",
)

# Substrings matched against Windows adapter descriptions / friendly names
WINDOWS_VPN_ADAPTER_KEYWORDS: tuple[str, ...] = (
    "tap-windows",
    "wintun",
    "wireguard",
    "protonvpn",
    "proton vpn",
    "openvpn",
    "nordlynx",
    "mullvad",
)


def _build_windows_guid_map() -> dict[str, str]:
    """Build a mapping from NPF-style GUIDs to lowercase adapter descriptions.

    Uses Scapy's ``get_windows_if_list()`` which returns a list of dicts
    containing ``name``, ``description``, ``guid``, etc.

    Returns:
        Dict mapping uppercased GUID strings (e.g. ``{ABC-...}``) to their
        lowercase adapter description.  Returns an empty dict if the
        lookup is unavailable or fails.
    """
    try:
        from scapy.arch.windows import get_windows_if_list  # type: ignore[import-untyped]

        guid_map: dict[str, str] = {}
        for iface_info in get_windows_if_list():
            guid = iface_info.get("guid", "")
            description = iface_info.get("description", "")
            name = iface_info.get("name", "")
            # Store both description and friendly name so either can match
            combined = f"{description} {name}".lower()
            if guid:
                guid_map[guid.upper()] = combined
        return guid_map
    except Exception:
        logger.debug("Failed to build Windows GUID map via Scapy", exc_info=True)
        return {}


def _extract_guid(iface: str) -> Optional[str]:
    """Extract the ``{GUID}`` portion from an NPF device path.

    Args:
        iface: An interface identifier, potentially of the form
            ``\\Device\\NPF_{xxxxxxxx-...}``.

    Returns:
        The uppercased GUID including braces, or ``None`` if the string
        does not contain an NPF GUID.
    """
    npf_marker = "NPF_"
    idx = iface.upper().find(npf_marker)
    if idx == -1:
        return None
    # The GUID starts right after "NPF_"
    guid_start = idx + len(npf_marker)
    guid = iface[guid_start:]
    # Ensure it looks like a GUID wrapped in braces
    if guid.startswith("{") and "}" in guid:
        guid = guid[: guid.index("}") + 1]
        return guid.upper()
    return None


def is_tunnel_interface(
    iface: str,
    tunnel_prefixes: Optional[tuple[str, ...]] = None,
) -> bool:
    """Determine whether *iface* represents a VPN tunnel interface.

    On Linux and macOS the check is a simple prefix match against known
    tunnel interface name prefixes (``tun``, ``wg``, ``tap``, etc.).

    On Windows, Scapy often reports interface names as NPF device paths
    (``\\Device\\NPF_{GUID}``).  In that case the function resolves the
    GUID to an adapter description using Scapy's Windows interface list
    and checks whether the description contains any known VPN adapter
    keyword.

    Args:
        iface: Interface name as reported by the capture library.
        tunnel_prefixes: Override the default prefix tuple (useful for
            testing or backward compatibility).  When ``None`` the
            module-level :data:`TUNNEL_INTERFACE_PREFIXES` is used.

    Returns:
        ``True`` if the interface is identified as a VPN tunnel.
    """
    prefixes = tunnel_prefixes if tunnel_prefixes is not None else TUNNEL_INTERFACE_PREFIXES

    # Fast path: prefix matching works on all platforms
    if iface.lower().startswith(prefixes):
        return True

    # On non-Windows platforms, prefix matching is all we need
    if platform.system() != "Windows":
        return False

    # --- Windows-specific NPF GUID resolution ---
    guid = _extract_guid(iface)
    if guid is None:
        # Not an NPF path and prefix didn't match -- not a tunnel
        return False

    guid_map = _build_windows_guid_map()
    if not guid_map:
        # Scapy lookup unavailable; cannot resolve -- fall back to False
        logger.debug(
            "Cannot resolve NPF GUID %s: Scapy Windows interface list unavailable",
            guid,
        )
        return False

    description = guid_map.get(guid, "")
    if not description:
        logger.debug("GUID %s not found in Scapy interface list", guid)
        return False

    return any(keyword in description for keyword in WINDOWS_VPN_ADAPTER_KEYWORDS)
