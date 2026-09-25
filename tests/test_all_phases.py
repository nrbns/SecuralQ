"""Prove world-class Phases 1–5 are lab-complete (ops leftovers honest)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_all_phases_lab(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.db import init_schema
    from app.phase_board import all_phases_board
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    board = all_phases_board()
    assert board["ok"] is True
    assert board["all_lab"] is True
    ids = {p["id"] for p in board["phases"]}
    assert ids == {
        "phase1_trustworthy",
        "phase2_powerful",
        "phase3_operational",
        "phase4_enterprise",
        "phase5_differentiated",
    }
    assert all(p["status"] == "lab" for p in board["phases"])


def test_toxic_and_service_impact(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user
    from app.db import init_schema
    from app.enterprise import create_asset
    from app.service_impact import services_affected_by_vuln
    from app.tenancy import ensure_tenant_schema
    from app.toxic_combos import compute_toxic_combinations

    init_schema()
    ensure_tenant_schema()
    u = register_user("phase_user", "password123")
    create_asset(
        u.id,
        name="edge-gw.example.com",
        asset_type="server",
        business_criticality="high",
        service_accounts="payments-api",
    )
    toxic = compute_toxic_combinations(u.id)
    assert toxic["ok"] is True
    assert "internet_facing_high_vuln" in toxic.get("supported_kinds") or "public_risky_port" in toxic.get(
        "supported_kinds"
    )
    impact = services_affected_by_vuln(u.id)
    assert impact["ok"] is True


def test_mssp_white_label_and_central_soc(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user
    from app.commercial_ext import create_org
    from app.db import init_schema
    from app.mssp import central_soc_summary, link_child, set_white_label
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    u = register_user("mssp_admin", "password123")
    parent = create_org(u.id, name="MSSP Parent")
    child = create_org(u.id, name="Customer A")
    link_child(parent["id"], child["id"], actor_user_id=u.id)
    wl = set_white_label(parent["id"], name="Contoso SOC", accent="#0a7")
    assert wl["white_label"]["enabled"] is True
    assert wl["delegated_admin"] is True
    soc = central_soc_summary(parent["id"])
    assert soc["customers"] == 1
