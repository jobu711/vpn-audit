"""Tests for the shared interface classification utility."""

from unittest.mock import patch

import pytest

from backend.core.interfaces import (
    TUNNEL_INTERFACE_PREFIXES,
    WINDOWS_VPN_ADAPTER_KEYWORDS,
    _build_windows_guid_map,
    _extract_guid,
    is_tunnel_interface,
)


# ===== Prefix matching tests (Linux/macOS behaviour) =====


class TestPrefixMatching:
    """Tests for prefix-based tunnel detection on all platforms."""

    def test_tun_interface(self):
        assert is_tunnel_interface("tun0") is True

    def test_wg_interface(self):
        assert is_tunnel_interface("wg0") is True

    def test_proton_interface(self):
        assert is_tunnel_interface("proton0") is True

    def test_tap_interface(self):
        assert is_tunnel_interface("tap0") is True

    def test_utun_interface(self):
        assert is_tunnel_interface("utun3") is True

    def test_eth_not_tunnel(self):
        assert is_tunnel_interface("eth0") is False

    def test_wlan_not_tunnel(self):
        assert is_tunnel_interface("wlan0") is False

    def test_case_insensitive(self):
        assert is_tunnel_interface("TUN0") is True

    def test_case_insensitive_mixed(self):
        assert is_tunnel_interface("Wg0") is True

    def test_empty_string(self):
        assert is_tunnel_interface("") is False

    def test_custom_prefixes(self):
        assert is_tunnel_interface("vpn0", tunnel_prefixes=("vpn",)) is True

    def test_custom_prefixes_rejects_default(self):
        assert is_tunnel_interface("tun0", tunnel_prefixes=("vpn",)) is False


# ===== GUID extraction tests =====


class TestExtractGuid:
    """Tests for _extract_guid helper."""

    def test_extracts_guid_from_npf_path(self):
        result = _extract_guid(
            r"\Device\NPF_{4AC43B83-4AEC-4561-8D59-C5DD960F5E43}"
        )
        assert result == "{4AC43B83-4AEC-4561-8D59-C5DD960F5E43}"

    def test_returns_none_for_non_npf(self):
        assert _extract_guid("eth0") is None

    def test_returns_none_for_empty(self):
        assert _extract_guid("") is None

    def test_case_insensitive_npf(self):
        result = _extract_guid(r"\Device\npf_{ABC-123}")
        assert result is not None


# ===== Windows GUID resolution tests =====


class TestWindowsGuidResolution:
    """Tests for Windows-specific NPF GUID resolution in is_tunnel_interface."""

    @patch("backend.core.interfaces.platform.system", return_value="Windows")
    @patch("backend.core.interfaces._build_windows_guid_map")
    def test_npf_guid_resolves_to_vpn_adapter(self, mock_map, mock_sys):
        mock_map.return_value = {
            "{4AC43B83-4AEC-4561-8D59-C5DD960F5E43}": "wintun userspace tunnel"
        }
        result = is_tunnel_interface(
            r"\Device\NPF_{4AC43B83-4AEC-4561-8D59-C5DD960F5E43}"
        )
        assert result is True

    @patch("backend.core.interfaces.platform.system", return_value="Windows")
    @patch("backend.core.interfaces._build_windows_guid_map")
    def test_npf_guid_resolves_to_physical_adapter(self, mock_map, mock_sys):
        mock_map.return_value = {
            "{4AC43B83-4AEC-4561-8D59-C5DD960F5E43}": "intel(r) ethernet connection"
        }
        result = is_tunnel_interface(
            r"\Device\NPF_{4AC43B83-4AEC-4561-8D59-C5DD960F5E43}"
        )
        assert result is False

    @patch("backend.core.interfaces.platform.system", return_value="Windows")
    @patch("backend.core.interfaces._build_windows_guid_map")
    def test_npf_guid_not_found_in_map(self, mock_map, mock_sys):
        mock_map.return_value = {}
        result = is_tunnel_interface(r"\Device\NPF_{UNKNOWN-GUID}")
        assert result is False

    @patch("backend.core.interfaces.platform.system", return_value="Windows")
    @patch("backend.core.interfaces._build_windows_guid_map")
    def test_windows_fallback_when_guid_map_empty(self, mock_map, mock_sys):
        mock_map.return_value = {}
        result = is_tunnel_interface(r"\Device\NPF_{UNKNOWN-GUID}")
        assert result is False

    @patch("backend.core.interfaces.platform.system", return_value="Windows")
    @patch("backend.core.interfaces._build_windows_guid_map")
    def test_protonvpn_adapter_detected(self, mock_map, mock_sys):
        mock_map.return_value = {
            "{ABCD-1234}": "protonvpn tap adapter v9"
        }
        result = is_tunnel_interface(r"\Device\NPF_{ABCD-1234}")
        assert result is True

    @patch("backend.core.interfaces.platform.system", return_value="Windows")
    @patch("backend.core.interfaces._build_windows_guid_map")
    def test_wireguard_adapter_detected(self, mock_map, mock_sys):
        mock_map.return_value = {
            "{ABCD-1234}": "wireguard tunnel"
        }
        result = is_tunnel_interface(r"\Device\NPF_{ABCD-1234}")
        assert result is True

    @patch("backend.core.interfaces.platform.system", return_value="Linux")
    def test_non_windows_ignores_npf_path(self, mock_sys):
        result = is_tunnel_interface(r"\Device\NPF_{SOME-GUID}")
        assert result is False
