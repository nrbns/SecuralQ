"""CMMC assessment layer — objectives, methods, POA&M policy, SPRS prep."""

from __future__ import annotations

import importlib

from tests._http_test_utils import configure_isolated_settings


def _uid(monkeypatch, tmp_path, name="cmmc_user"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(name, "password123", role="admin")
    u, _ = login(name, "password123")
    return u.id


def test_seed_objectives_and_control_assessment(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "cmmc_obj")
    from app.cmmc import (
        get_control_assessment,
        list_objectives,
        seed_objectives_for_framework,
        set_objective_status,
    )

    out = seed_objectives_for_framework("cmmc_l2")
    assert out["ok"] is True
    assert out["seeded"] >= 330  # 110 * 3
    objs = list_objectives("cmmc_l2", control_id="AC.L2-3.1.1")
    assert len(objs) == 3
    methods = {o["method"] for o in objs}
    assert methods == {"examine", "interview", "test"}

    set_objective_status(uid, objs[0]["id"], status="met", reviewer="alice")
    set_objective_status(uid, objs[1]["id"], status="met", reviewer="alice")
    set_objective_status(uid, objs[2]["id"], status="not_met", reviewer="alice")
    detail = get_control_assessment(uid, "cmmc_l2", "AC.L2-3.1.1")
    assert detail["rollup_status"] == "not_met"
    assert detail["counts"]["met"] == 2
    assert detail["counts"]["not_met"] == 1
    assert "poam_policy" in detail


def test_poam_policy_blocks_ineligible_control(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "cmmc_poam")
    from app.cmmc import open_poam_item, poam_policy_for_control
    from app.controls.catalog import list_framework_controls

    # Find a control with poam_eligible=false
    blocked = None
    allowed = None
    for c in list_framework_controls("cmmc_l2"):
        elig = (c.raw or {}).get("poam_eligible")
        if elig is False and blocked is None:
            blocked = c.id
        if elig is True and allowed is None:
            allowed = c.id
        if blocked and allowed:
            break
    assert blocked and allowed
    pol = poam_policy_for_control("cmmc_l2", blocked)
    assert pol["poam_permitted_for_control"] is False
    import pytest

    with pytest.raises(ValueError, match="not permitted"):
        open_poam_item(
            uid,
            framework_id="cmmc_l2",
            control_id=blocked,
            weakness="gap",
            owner="owner",
        )
    item = open_poam_item(
        uid,
        framework_id="cmmc_l2",
        control_id=allowed,
        weakness="Missing MFA on CUI workstation",
        owner="sec-ops",
    )
    assert item["status"] == "open"
    assert item.get("due_at")


def test_method_evidence_and_sprs_prep(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "cmmc_meth")
    from app.cmmc import (
        record_method_evidence,
        seed_objectives_for_framework,
        sprs_preparation_snapshot,
        upsert_cui_program,
    )

    seed_objectives_for_framework("cmmc_l2")
    ev = record_method_evidence(
        uid,
        framework_id="cmmc_l2",
        control_id="AC.L2-3.1.1",
        method="examine",
        title="Access control policy",
        detail={"document": "AC-Policy-v3.pdf"},
        result="pass",
        reviewer="auditor",
    )
    assert ev.get("method") == "examine"
    assert ev.get("evidence_id")

    prog = upsert_cui_program(
        uid,
        name="CUI Enclave A",
        boundary_notes="Isolated VLAN + SPA firewall",
        categories=["CUI", "FCI"],
        data_flows=[{"from": "endpoint", "to": "file-share", "data": "CUI"}],
    )
    assert prog["name"] == "CUI Enclave A"

    snap = sprs_preparation_snapshot(uid, framework_id="cmmc_l2")
    assert snap["ok"] is True
    assert snap["requirement_counts"]["total"] == 110
    assert "disclaimer" in snap
    assert "SPRS" in snap["disclaimer"]
    assert snap["framework"]["version"]


def test_cmmc_api_smoke(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("cmmc_api", "password123", role="admin")
    _, token = login("cmmc_api", "password123")
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post("/api/cmmc/objectives/seed?framework_id=cmmc_l2", headers=headers)
    assert r.status_code == 200, r.text
    r2 = client.get(
        "/api/cmmc/controls/AC.L2-3.1.1/assessment?framework_id=cmmc_l2",
        headers=headers,
    )
    assert r2.status_code == 200
    body = r2.json()
    assert body["ok"] is True
    assert len(body["objectives"]) == 3
    r3 = client.get("/api/cmmc/sprs-preparation?framework_id=cmmc_l2", headers=headers)
    assert r3.status_code == 200
    assert r3.json()["requirement_counts"]["total"] == 110
    r4 = client.get("/api/cmmc/version?framework_id=cmmc_l2", headers=headers)
    assert r4.status_code == 200
    assert "status_note" in r4.json()
