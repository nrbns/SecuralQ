"""Unit tests for app.services.remediation — Remediation Plans, the
persisted snapshot layer on top of the Risk Reduction Simulator.

Function-level (not HTTP), following the pattern in tests/test_attack_graph.py.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="remediation_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def _seed_vuln_group(uid, *, cve="CVE-2024-1111", severity="critical", cvss=9.8, n_assets=1, asset_type="web", business_criticality=""):
    """Creates n_assets assets sharing one open vulnerability with the same
    CVE (so they all group under one simulator group_key), returns
    (group_key, asset_ids)."""
    from app.enterprise import create_asset, create_vulnerability

    asset_ids = []
    for i in range(n_assets):
        a = create_asset(uid, f"HOST-{i}", asset_type=asset_type, business_criticality=business_criticality)
        asset_ids.append(a["id"])
        create_vulnerability(
            uid,
            {
                "asset_id": a["id"],
                "asset_name": f"HOST-{i}",
                "title": "Apache RCE",
                "cve": cve,
                "severity": severity,
                "cvss": cvss,
                "status": "open",
            },
        )
    return f"cve:{cve}", asset_ids


def test_create_plan_snapshots_a_real_simulator_group(tmp_path, monkeypatch):
    from app.services.remediation import create_plan

    uid = _setup(monkeypatch, tmp_path)
    group_key, asset_ids = _seed_vuln_group(uid, n_assets=2)

    plan = create_plan(uid, group_key)
    assert plan["status"] == "draft"
    assert plan["group_key"] == group_key
    assert plan["cve"] == "CVE-2024-1111"
    assert plan["vulns_removed"] == 2
    assert plan["assets_affected"] == 2
    assert plan["kev"] in (0, 1)
    assert plan["explanation"]
    assert "2 asset" in plan["explanation"]
    assert plan["disruption_band"] in ("low", "medium", "high")


def test_create_plan_rejects_unknown_or_already_resolved_group(tmp_path, monkeypatch):
    from app.services.remediation import create_plan

    uid = _setup(monkeypatch, tmp_path)
    try:
        create_plan(uid, "cve:CVE-9999-0000")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_disruption_band_high_for_business_critical_asset(tmp_path, monkeypatch):
    from app.services.remediation import create_plan

    uid = _setup(monkeypatch, tmp_path)
    group_key, _ = _seed_vuln_group(uid, cve="CVE-2024-2222", n_assets=1, business_criticality="critical")

    plan = create_plan(uid, group_key)
    assert plan["disruption_band"] == "high"
    assert plan["business_critical_assets"] == 1
    assert "business-critical" in plan["explanation"]


def test_disruption_band_low_for_small_non_critical_group(tmp_path, monkeypatch):
    from app.services.remediation import create_plan

    uid = _setup(monkeypatch, tmp_path)
    group_key, _ = _seed_vuln_group(uid, cve="CVE-2024-3333", n_assets=1)

    plan = create_plan(uid, group_key)
    # no agent online -> agent_patchable_assets is 0, so this is NOT "low"
    # (low requires patchable >= affected) -- it should fall to "medium" and
    # the explanation must say manual remediation is needed, not claim
    # automation that doesn't exist.
    assert plan["agent_patchable_assets"] == 0
    assert plan["disruption_band"] == "medium"
    assert "manual remediation" in plan["explanation"]


def test_approve_then_link_campaign_moves_plan_to_executing(tmp_path, monkeypatch):
    from app.agents import create_campaign, enroll_agent
    from app.services.remediation import approve_plan, create_plan, link_campaign

    uid = _setup(monkeypatch, tmp_path)
    group_key, _ = _seed_vuln_group(uid, cve="CVE-2024-4444")

    plan = create_plan(uid, group_key)
    approved = approve_plan(uid, plan["id"])
    assert approved["status"] == "approved"
    assert approved["approved_by"] == uid

    agent = enroll_agent(uid, name="test-agent")
    campaign = create_campaign(uid, name="test campaign", manager="apt", package="apache2", agent_ids=[agent["agent_id"]])
    linked = link_campaign(uid, plan["id"], campaign["id"])
    assert linked["status"] == "executing"
    assert linked["campaign_id"] == campaign["id"]


def test_link_campaign_requires_approved_status(tmp_path, monkeypatch):
    from app.agents import create_campaign, enroll_agent
    from app.services.remediation import create_plan, link_campaign

    uid = _setup(monkeypatch, tmp_path)
    group_key, _ = _seed_vuln_group(uid, cve="CVE-2024-5555")
    plan = create_plan(uid, group_key)
    agent = enroll_agent(uid, name="test-agent")
    campaign = create_campaign(uid, name="test campaign", manager="apt", package="apache2", agent_ids=[agent["agent_id"]])

    try:
        link_campaign(uid, plan["id"], campaign["id"])
        assert False, "expected ValueError -- plan is still draft"
    except ValueError:
        pass


def test_remeasure_plan_records_real_current_risk(tmp_path, monkeypatch):
    from app.services.remediation import approve_plan, create_plan, remeasure_plan
    from app.services.risk_priority import compute_org_risk_score

    uid = _setup(monkeypatch, tmp_path)
    group_key, _ = _seed_vuln_group(uid, cve="CVE-2024-6666")
    plan = create_plan(uid, group_key)
    approve_plan(uid, plan["id"])

    measured = remeasure_plan(uid, plan["id"])
    assert measured["status"] == "measured"
    current = compute_org_risk_score(uid)
    assert measured["risk_after"] == current["score"]


def test_reject_plan(tmp_path, monkeypatch):
    from app.services.remediation import create_plan, reject_plan

    uid = _setup(monkeypatch, tmp_path)
    group_key, _ = _seed_vuln_group(uid, cve="CVE-2024-7777")
    plan = create_plan(uid, group_key)
    rejected = reject_plan(uid, plan["id"])
    assert rejected["status"] == "rejected"


def test_list_and_delete_plans_scoped_to_owning_user(tmp_path, monkeypatch):
    from app.auth import login, register_user
    from app.services.remediation import create_plan, delete_plan, list_plans

    uid = _setup(monkeypatch, tmp_path, username="remediation_owner_a")
    register_user("remediation_owner_b", "password123", role="admin")
    uid_b, _ = login("remediation_owner_b", "password123")

    group_key, _ = _seed_vuln_group(uid, cve="CVE-2024-8888")
    plan = create_plan(uid, group_key)

    assert len(list_plans(uid)) == 1
    assert len(list_plans(uid_b.id)) == 0

    # user B cannot delete user A's plan
    assert delete_plan(uid_b.id, plan["id"]) is False
    assert delete_plan(uid, plan["id"]) is True
    assert list_plans(uid) == []


def test_multiple_plans_are_independently_comparable(tmp_path, monkeypatch):
    from app.services.remediation import create_plan, list_plans

    uid = _setup(monkeypatch, tmp_path)
    key_a, _ = _seed_vuln_group(uid, cve="CVE-2024-9001", n_assets=1)
    key_b, _ = _seed_vuln_group(uid, cve="CVE-2024-9002", n_assets=3, business_criticality="high")

    plan_a = create_plan(uid, key_a)
    plan_b = create_plan(uid, key_b)

    plans = {p["id"]: p for p in list_plans(uid)}
    assert plan_a["id"] in plans and plan_b["id"] in plans
    assert plans[plan_b["id"]]["assets_affected"] == 3
    assert plans[plan_b["id"]]["disruption_band"] == "high"
