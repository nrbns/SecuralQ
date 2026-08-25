"""SOC connector tools — Wazuh SIEM, XDR, TheHive, inventory sync in tool runner."""

from __future__ import annotations

import asyncio

from app.tools.registry import SOC_PACK_TOOLS, TOOL_CATALOG, is_available, list_tools_status
from app.tools.runner import parse_tool_request


def test_soc_pack_tools_registered():
    for tid in SOC_PACK_TOOLS:
        assert tid in TOOL_CATALOG
        assert TOOL_CATALOG[tid].needs_target is False


def test_parse_wazuh_and_siem_aliases():
    ids = parse_tool_request("run wazuh sync and inventory", include_heavy=True)
    assert "siem_sync" in ids
    assert "inventory_sync" in ids


def test_parse_xdr_sync_alias():
    ids = parse_tool_request("sync xdr from crowdstrike", include_heavy=True)
    assert "xdr_sync" in ids


def test_list_tools_exposes_soc_pack():
    if hasattr(list_tools_status, "_cache"):
        list_tools_status._cache = None
    payload = list_tools_status()
    assert "soc_pack" in payload
    assert set(payload["soc_pack"]) == set(SOC_PACK_TOOLS)


def test_siem_sync_tool_when_not_configured():
    assert is_available("inventory_sync") is True


def test_siem_sync_runner_not_configured():
    from app.tools.runner import _tool_siem_sync

    out = asyncio.run(_tool_siem_sync("local"))
    if not out.get("ok"):
        assert "not configured" in (out.get("error") or "").lower()
