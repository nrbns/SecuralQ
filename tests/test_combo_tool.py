"""Integrated VA tool is the single PT pack entry."""

from app.tools.registry import PT_PACK_TOOLS, TOOL_CATALOG, is_available


def test_pt_pack_is_single_combo_tool():
    assert PT_PACK_TOOLS == ("combo_assessment",)
    assert "combo_assessment" in TOOL_CATALOG
    assert is_available("combo_assessment") is True
