"""HTTP-layer tests for GET /api/risk/priority (app/risk_api.py) — the
"what to fix first" ranking built on app.services.risk_priority.

Pattern follows tests/test_delete_routes_http.py: a real FastAPI TestClient
wrapping just the router(s) under test, register_user()/login() for a real
bearer token, threading through the real user.id (not the username) since
create_asset()/create_vulnerability() key rows by user.id.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _reload_db(monkeypatch, data_dir):
    return configure_isolated_settings(monkeypatch, data_dir)


def _client_and_token(tmp_path, monkeypatch, username="risk_tester"):
    """Returns (client, bearer_token, real_user_id)."""
    _reload_db(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.risk_api import router as risk_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(risk_router)
    client = TestClient(test_app)
    return client, token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_priority_list_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/risk/priority")
    assert res.status_code == 401


def test_priority_list_empty_when_no_open_findings(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/risk/priority", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["total_open"] == 0
    assert body["items"] == []


def test_priority_list_ranks_critical_asset_above_low_criticality(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability

    crit_asset = create_asset(uid, "prod-db", asset_type="server", criticality="critical")
    low_asset = create_asset(uid, "test-vm", asset_type="server", criticality="low")

    v_high = create_vulnerability(
        uid,
        {
            "asset_id": crit_asset["id"],
            "asset_name": "prod-db",
            "title": "Outdated OpenSSL",
            "severity": "high",
            "cvss": 7.5,
            "status": "open",
        },
    )
    v_low = create_vulnerability(
        uid,
        {
            "asset_id": low_asset["id"],
            "asset_name": "test-vm",
            "title": "Outdated OpenSSL",
            "severity": "high",
            "cvss": 7.5,
            "status": "open",
        },
    )

    res = client.get("/api/risk/priority", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["total_open"] == 2
    items = body["items"]
    assert len(items) == 2
    ids_in_order = [i["vuln_id"] for i in items]
    assert ids_in_order.index(v_high["id"]) < ids_in_order.index(v_low["id"])
    # every item carries the same explainable shape compute_risk_score produces
    for item in items:
        assert "score" in item and "band" in item and "factors" in item
        assert isinstance(item["reasons"], list) and item["reasons"]


def test_priority_list_excludes_resolved_findings(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability

    asset = create_asset(uid, "host-1")
    create_vulnerability(
        uid,
        {"asset_id": asset["id"], "asset_name": "host-1", "title": "Fixed already", "severity": "high", "status": "resolved"},
    )
    open_v = create_vulnerability(
        uid,
        {"asset_id": asset["id"], "asset_name": "host-1", "title": "Still open", "severity": "medium", "status": "open"},
    )

    res = client.get("/api/risk/priority", headers=_auth(token))
    body = res.json()
    assert body["total_open"] == 1
    assert body["items"][0]["vuln_id"] == open_v["id"]


def test_priority_list_respects_limit(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability

    asset = create_asset(uid, "host-many")
    for i in range(5):
        create_vulnerability(
            uid,
            {"asset_id": asset["id"], "asset_name": "host-many", "title": f"Finding {i}", "severity": "medium", "status": "open"},
        )

    res = client.get("/api/risk/priority?limit=2", headers=_auth(token))
    body = res.json()
    assert body["total_open"] == 5
    assert len(body["items"]) == 2


def test_priority_list_scoped_to_owning_user(tmp_path, monkeypatch):
    client, token_a, uid_a = _client_and_token(tmp_path, monkeypatch, username="risk_owner_a")
    from app.auth import login, register_user
    from app.enterprise import create_asset, create_vulnerability

    register_user("risk_owner_b", "password123", role="admin")
    _u_b, token_b = login("risk_owner_b", "password123")

    asset = create_asset(uid_a, "a-only-host")
    create_vulnerability(
        uid_a,
        {"asset_id": asset["id"], "asset_name": "a-only-host", "title": "A's finding", "severity": "high", "status": "open"},
    )

    res_a = client.get("/api/risk/priority", headers=_auth(token_a))
    assert res_a.json()["total_open"] == 1

    res_b = client.get("/api/risk/priority", headers=_auth(token_b))
    assert res_b.json()["total_open"] == 0


# ---------------------------------------------------------------------------
# /api/risk/organizational-score — single headline exposure number
# ---------------------------------------------------------------------------


def test_org_score_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/risk/organizational-score")
    assert res.status_code == 401


def test_org_score_zero_when_no_open_findings(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/risk/organizational-score", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["score"] == 0.0
    assert body["total_open"] == 0
    assert body["kev_count"] == 0
    assert body["critical_high_count"] == 0


def test_org_score_is_mean_of_open_finding_scores(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability
    from app.services.risk_priority import _scored_open_items

    asset = create_asset(uid, "org-score-host", asset_type="server", criticality="medium")
    create_vulnerability(
        uid,
        {"asset_id": asset["id"], "asset_name": "org-score-host", "title": "Finding A", "severity": "high", "cvss": 8.0, "status": "open"},
    )
    create_vulnerability(
        uid,
        {"asset_id": asset["id"], "asset_name": "org-score-host", "title": "Finding B", "severity": "low", "cvss": 2.0, "status": "open"},
    )

    res = client.get("/api/risk/organizational-score", headers=_auth(token))
    body = res.json()
    assert body["total_open"] == 2

    # cross-check against the shared scoring helper directly — the endpoint
    # must be a real mean of the same per-finding scores, not a fabricated number
    scored = _scored_open_items(uid)
    expected = round(sum(i["score"] for i in scored) / len(scored), 1)
    assert body["score"] == expected


def test_org_score_scoped_to_owning_user(tmp_path, monkeypatch):
    client, token_a, uid_a = _client_and_token(tmp_path, monkeypatch, username="org_score_owner_a")
    from app.auth import login, register_user
    from app.enterprise import create_asset, create_vulnerability

    register_user("org_score_owner_b", "password123", role="admin")
    _u_b, token_b = login("org_score_owner_b", "password123")

    asset = create_asset(uid_a, "a-only-host-2")
    create_vulnerability(
        uid_a,
        {"asset_id": asset["id"], "asset_name": "a-only-host-2", "title": "A's finding", "severity": "critical", "cvss": 9.5, "status": "open"},
    )

    res_a = client.get("/api/risk/organizational-score", headers=_auth(token_a))
    assert res_a.json()["total_open"] == 1
    assert res_a.json()["score"] > 0

    res_b = client.get("/api/risk/organizational-score", headers=_auth(token_b))
    assert res_b.json()["total_open"] == 0
    assert res_b.json()["score"] == 0.0


# ---------------------------------------------------------------------------
# /api/risk/simulate — Risk Reduction Simulator (grouped what-if)
# ---------------------------------------------------------------------------


def test_simulate_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/risk/simulate")
    assert res.status_code == 401


def test_simulate_empty_when_no_open_findings(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/risk/simulate", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["baseline_score"] == 0.0
    assert body["groups"] == []
    assert body["top3_combined_reduction_pct"] == 0.0


def test_simulate_groups_by_exact_cve_and_estimates_reduction(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability

    asset_a = create_asset(uid, "sim-host-a", asset_type="domain", criticality="critical")
    asset_b = create_asset(uid, "sim-host-b", asset_type="server", criticality="low")

    # two findings sharing the same CVE across two assets -> one group
    create_vulnerability(
        uid,
        {
            "asset_id": asset_a["id"], "asset_name": "sim-host-a", "title": "Log4Shell",
            "cve": "CVE-2021-44228", "severity": "critical", "cvss": 10.0, "status": "open",
        },
    )
    create_vulnerability(
        uid,
        {
            "asset_id": asset_b["id"], "asset_name": "sim-host-b", "title": "Log4Shell",
            "cve": "CVE-2021-44228", "severity": "critical", "cvss": 10.0, "status": "open",
        },
    )
    # a lower-severity, unrelated finding — should form its own group
    create_vulnerability(
        uid,
        {"asset_id": asset_b["id"], "asset_name": "sim-host-b", "title": "Minor issue", "severity": "low", "cvss": 2.0, "status": "open"},
    )

    res = client.get("/api/risk/simulate", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["total_open"] == 3
    assert body["baseline_score"] > 0

    groups = body["groups"]
    assert len(groups) == 2
    cve_group = next(g for g in groups if g["cve"] == "CVE-2021-44228")
    assert cve_group["vulns_removed"] == 2
    assert cve_group["assets_affected"] == 2
    assert cve_group["internet_exposed_assets"] == 1  # only sim-host-a is a "domain" (public) asset
    assert cve_group["critical_high_count"] == 2
    # removing the highest-severity, most-affecting group must show the
    # largest (or tied-largest) estimated reduction, ranked first
    assert groups[0]["estimated_risk_reduction_pct"] >= groups[1]["estimated_risk_reduction_pct"]
    assert groups[0]["cve"] == "CVE-2021-44228"

    # top3 headline is real: fixing everything scored (<=3 groups here) should
    # reduce the baseline to zero since there are only 2 groups total
    assert body["top3_combined_reduction_pct"] == 100.0
    assert "Log4Shell" in body["top3_group_titles"]


def test_simulate_reports_real_attack_paths_disrupted(tmp_path, monkeypatch):
    """attack_paths_disrupted is a real recomputation over app.services.
    attack_graph, not a fabricated number — a finding on an asset with no
    path from Internet (not exposed, nothing declared/inferred connecting
    to it) must disrupt zero paths, since none exist to disrupt."""
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability

    asset = create_asset(uid, "no-attack-path-host", asset_type="server", criticality="medium")
    create_vulnerability(
        uid,
        {"asset_id": asset["id"], "asset_name": "no-attack-path-host", "title": "Some finding", "severity": "high", "cvss": 7.0, "status": "open"},
    )
    res = client.get("/api/risk/simulate", headers=_auth(token))
    body = res.json()
    assert "total_attack_paths" in body
    assert "business_critical_attack_paths" in body
    assert body["total_attack_paths"] == 0
    for g in body["groups"]:
        assert g["attack_paths_disrupted"] == 0
        assert g["business_critical_paths_disrupted"] == 0


def test_simulate_attack_paths_disrupted_reflects_real_graph(tmp_path, monkeypatch):
    """The killer-feature case: a vulnerability on an internet-exposed web
    asset that connects (declared) to a business-critical database must
    show attack_paths_disrupted >= 2 (the direct path AND the path through
    to the database) and business_critical_paths_disrupted >= 1."""
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_asset_dependency, create_vulnerability

    web = create_asset(uid, "WEB-01", asset_type="web", criticality="medium")
    db = create_asset(uid, "DB-01", asset_type="database", criticality="high", business_criticality="critical")
    create_vulnerability(
        uid,
        {"asset_id": web["id"], "asset_name": "WEB-01", "title": "Apache RCE", "cve": "CVE-2024-9999", "severity": "critical", "cvss": 9.8, "status": "open"},
    )
    create_asset_dependency(uid, web["id"], db["id"], relationship="connects_to")

    res = client.get("/api/risk/simulate", headers=_auth(token))
    body = res.json()
    assert body["total_attack_paths"] >= 2
    assert body["business_critical_attack_paths"] >= 1
    group = next(g for g in body["groups"] if g["cve"] == "CVE-2024-9999")
    assert group["attack_paths_disrupted"] >= 2
    assert group["business_critical_paths_disrupted"] >= 1


# ---------------------------------------------------------------------------
# /api/risk/attack-graph and /api/risk/attack-paths
# ---------------------------------------------------------------------------


def test_attack_graph_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/risk/attack-graph")
    assert res.status_code == 401


def test_attack_graph_empty_state(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/risk/attack-graph", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["total_assets"] == 0
    assert any(n["type"] == "internet" for n in body["nodes"])


def test_attack_graph_reflects_real_assets_and_edges(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset

    create_asset(uid, "WEB-01", asset_type="web")
    res = client.get("/api/risk/attack-graph", headers=_auth(token))
    body = res.json()
    assert body["total_assets"] == 1
    web_node = next(n for n in body["nodes"] if n["type"] == "application")
    assert web_node["exposed"] is True
    assert any(e["type"] == "exposed_to" for e in body["edges"])


def test_attack_paths_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/risk/attack-paths")
    assert res.status_code == 401


def test_attack_paths_empty_when_nothing_exposed(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/risk/attack-paths", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["total_paths"] == 0
    assert body["paths"] == []


def test_attack_paths_reports_real_route(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability

    web = create_asset(uid, "WEB-01", asset_type="web", criticality="high")
    create_vulnerability(
        uid,
        {"asset_id": web["id"], "asset_name": "WEB-01", "title": "Apache RCE", "cve": "CVE-2024-7777", "severity": "critical", "cvss": 9.8, "status": "open"},
    )
    res = client.get("/api/risk/attack-paths", headers=_auth(token))
    body = res.json()
    assert body["total_paths"] == 1
    path = body["paths"][0]
    assert path["target_asset"]["label"] == "WEB-01"
    assert path["worst_vulnerability"]["cve"] == "CVE-2024-7777"
    assert path["risk_score"] > 0


def test_attack_paths_respects_max_depth_param(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_asset_dependency, create_vulnerability

    web = create_asset(uid, "WEB-01", asset_type="web")
    mid = create_asset(uid, "MID-01", asset_type="server")
    db = create_asset(uid, "DB-01", asset_type="database")
    create_vulnerability(uid, {"asset_id": web["id"], "asset_name": "WEB-01", "title": "RCE", "severity": "critical", "cvss": 9.0, "status": "open"})
    create_asset_dependency(uid, web["id"], mid["id"])
    create_asset_dependency(uid, mid["id"], db["id"])

    shallow = client.get("/api/risk/attack-paths?max_depth=1", headers=_auth(token)).json()
    assert not any(p["target_asset"]["label"] == "DB-01" for p in shallow["paths"])

    full = client.get("/api/risk/attack-paths?max_depth=4", headers=_auth(token)).json()
    assert any(p["target_asset"]["label"] == "DB-01" for p in full["paths"])


def test_simulate_respects_limit(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability

    asset = create_asset(uid, "sim-limit-host")
    for i in range(5):
        create_vulnerability(
            uid,
            {
                "asset_id": asset["id"], "asset_name": "sim-limit-host", "title": f"Distinct finding {i}",
                "cve": f"CVE-2024-{1000 + i}", "severity": "medium", "cvss": 5.0, "status": "open",
            },
        )

    res = client.get("/api/risk/simulate?limit=2", headers=_auth(token))
    body = res.json()
    assert body["total_open"] == 5
    assert len(body["groups"]) == 2


# ---------------------------------------------------------------------------
# Risk Engine hardening — compensating_controls (agent monitoring) and
# business_criticality (distinct from asset_criticality) wired into the
# actual priority list, not just the standalone scoring function.
# ---------------------------------------------------------------------------


def test_priority_list_ranks_business_critical_low_infra_asset_higher(tmp_path, monkeypatch):
    """The canonical divergence case: a low-criticality box holding a
    business-critical function must outrank an identical low-criticality
    box with no elevated business function."""
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability

    plain_low = create_asset(uid, "forgotten-test-box", asset_type="server", criticality="low")
    biz_critical_low = create_asset(
        uid, "forgotten-db-box", asset_type="server", criticality="low", business_criticality="critical"
    )

    v_plain = create_vulnerability(
        uid,
        {"asset_id": plain_low["id"], "asset_name": "forgotten-test-box", "title": "Outdated OpenSSL", "severity": "high", "cvss": 7.5, "status": "open"},
    )
    v_biz = create_vulnerability(
        uid,
        {"asset_id": biz_critical_low["id"], "asset_name": "forgotten-db-box", "title": "Outdated OpenSSL", "severity": "high", "cvss": 7.5, "status": "open"},
    )

    res = client.get("/api/risk/priority", headers=_auth(token))
    items = {i["vuln_id"]: i for i in res.json()["items"]}
    assert items[v_biz["id"]]["score"] > items[v_plain["id"]]["score"]
    assert "business function" in " ".join(items[v_biz["id"]]["reasons"]).lower()


def test_priority_list_lowers_score_for_actively_monitored_asset(tmp_path, monkeypatch):
    """A finding on an asset with a currently-online SecuraIQ agent (a real
    compensating control — active monitoring) must score lower than an
    identical finding on an unmonitored asset."""
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.agents import enroll_agent, checkin
    from app.enterprise import create_asset, create_vulnerability

    unmonitored_asset = create_asset(uid, "unmonitored-host", asset_type="server", criticality="high")

    enrolled = enroll_agent(uid, name="monitored-host")
    agent_id = enrolled["agent_id"]
    ci = checkin(agent_id, {"hostname": "monitored-host", "os": "linux"})
    monitored_asset_id = ci["asset_id"]
    # give the monitored asset the same technical criticality so the only
    # difference between the two findings is monitoring coverage
    from app.enterprise import update_asset

    update_asset(uid, monitored_asset_id, {"criticality": "high"})

    v_unmonitored = create_vulnerability(
        uid,
        {"asset_id": unmonitored_asset["id"], "asset_name": "unmonitored-host", "title": "Vulnerable curl", "severity": "high", "cvss": 8.0, "status": "open"},
    )
    v_monitored = create_vulnerability(
        uid,
        {"asset_id": monitored_asset_id, "asset_name": "monitored-host", "title": "Vulnerable curl", "severity": "high", "cvss": 8.0, "status": "open"},
    )

    res = client.get("/api/risk/priority", headers=_auth(token))
    items = {i["vuln_id"]: i for i in res.json()["items"]}
    assert items[v_monitored["id"]]["score"] < items[v_unmonitored["id"]]["score"]
    assert items[v_monitored["id"]]["factors"]["compensating_controls"] > 0
    assert items[v_unmonitored["id"]]["factors"]["compensating_controls"] == 0
    assert any("monitoring" in r.lower() for r in items[v_monitored["id"]]["reasons"])


def test_priority_list_host_control_pass_lowers_score_vs_fail(tmp_path, monkeypatch):
    """Phase 6 — live host PASS raises compensating_controls vs FAIL on the
    same monitored asset shape. UNKNOWN is never invented as PASS."""
    client, token, uid = _client_and_token(tmp_path, monkeypatch, username="host_risk_prio")
    from app.agents import checkin, enroll_agent
    from app.enterprise import create_vulnerability, update_asset

    enrolled_pass = enroll_agent(uid, name="host-pass")
    enrolled_fail = enroll_agent(uid, name="host-fail")
    enrolled_unk = enroll_agent(uid, name="host-unk")

    good = {
        "hostname": "host-pass",
        "os": "linux",
        "firewall_status": {"collected": True, "enabled": True, "backend": "ufw"},
        "disk_encryption_status": {"collected": True, "encrypted": True, "backend": "luks"},
        "ssh_config": {"collected": True, "settings": {"PermitRootLogin": "no"}},
        "defender_status": {"collected": False, "reason": "not Windows"},
    }
    bad = {
        "hostname": "host-fail",
        "os": "linux",
        "firewall_status": {"collected": True, "enabled": False, "backend": "ufw"},
        "disk_encryption_status": {"collected": True, "encrypted": False, "backend": "none"},
        "ssh_config": {"collected": True, "settings": {"PermitRootLogin": "yes"}},
        "defender_status": {"collected": False, "reason": "not Windows"},
    }
    unk = {
        "hostname": "host-unk",
        "os": "linux",
        # no host telemetry keys — all UNKNOWN
    }

    aid_pass = checkin(enrolled_pass["agent_id"], good)["asset_id"]
    aid_fail = checkin(enrolled_fail["agent_id"], bad)["asset_id"]
    aid_unk = checkin(enrolled_unk["agent_id"], unk)["asset_id"]
    for aid in (aid_pass, aid_fail, aid_unk):
        update_asset(uid, aid, {"criticality": "high"})

    v_pass = create_vulnerability(
        uid,
        {
            "asset_id": aid_pass,
            "asset_name": "host-pass",
            "title": "Vulnerable curl",
            "severity": "high",
            "cvss": 8.0,
            "status": "open",
        },
    )
    v_fail = create_vulnerability(
        uid,
        {
            "asset_id": aid_fail,
            "asset_name": "host-fail",
            "title": "Vulnerable curl",
            "severity": "high",
            "cvss": 8.0,
            "status": "open",
        },
    )
    v_unk = create_vulnerability(
        uid,
        {
            "asset_id": aid_unk,
            "asset_name": "host-unk",
            "title": "Vulnerable curl",
            "severity": "high",
            "cvss": 8.0,
            "status": "open",
        },
    )

    res = client.get("/api/risk/priority", headers=_auth(token))
    assert res.status_code == 200, res.text
    items = {i["vuln_id"]: i for i in res.json()["items"]}

    assert items[v_pass["id"]]["compensating_controls"] > items[v_unk["id"]]["compensating_controls"]
    assert items[v_fail["id"]]["compensating_controls"] < items[v_unk["id"]]["compensating_controls"]
    assert items[v_pass["id"]]["score"] < items[v_fail["id"]]["score"]
    assert any("host_firewall PASS" in r for r in items[v_pass["id"]]["reasons"])
    assert any("host_firewall FAIL" in r for r in items[v_fail["id"]]["reasons"])
    assert any("host_disk_encryption FAIL" in r for r in items[v_fail["id"]]["reasons"])
    # UNKNOWN must not claim host PASS offset
    assert not any("PASS" in r and "host_" in r for r in items[v_unk["id"]]["reasons"])


# ---------------------------------------------------------------------------
# CMMC/CUI scope-aware business-criticality floor (Sprint 7-adjacent, per
# app.cmmc_scoping). cmmc_asset_category is a self-reported classification —
# these tests only check the honest, deterministic floor logic in
# app.services.risk_priority, not that SecuraIQ verified CUI presence.
# ---------------------------------------------------------------------------


def test_priority_list_ranks_cui_scoped_low_infra_asset_higher(tmp_path, monkeypatch):
    """A low-criticality box the user has self-classified as a CUI Asset (or
    SPA) must outrank an identical low-criticality box with no CMMC scope —
    the CUI boundary's own definition treats it as a critical business
    function even though nobody separately set business_criticality."""
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability

    plain_low = create_asset(uid, "unscoped-test-box", asset_type="server", criticality="low")
    cui_low = create_asset(
        uid, "cui-scoped-box", asset_type="server", criticality="low", cmmc_asset_category="cui_asset"
    )

    v_plain = create_vulnerability(
        uid,
        {"asset_id": plain_low["id"], "asset_name": "unscoped-test-box", "title": "Outdated OpenSSL", "severity": "high", "cvss": 7.5, "status": "open"},
    )
    v_cui = create_vulnerability(
        uid,
        {"asset_id": cui_low["id"], "asset_name": "cui-scoped-box", "title": "Outdated OpenSSL", "severity": "high", "cvss": 7.5, "status": "open"},
    )

    res = client.get("/api/risk/priority", headers=_auth(token))
    items = {i["vuln_id"]: i for i in res.json()["items"]}
    assert items[v_cui["id"]]["score"] > items[v_plain["id"]]["score"]
    assert items[v_cui["id"]]["cmmc_scope"] == "cui_asset"
    assert items[v_cui["id"]]["cmmc_floor_applied"] is True
    assert "cmmc scope" in " ".join(items[v_cui["id"]]["reasons"]).lower()
    assert items[v_plain["id"]]["cmmc_scope"] == ""
    assert items[v_plain["id"]]["cmmc_floor_applied"] is False


def test_priority_list_cui_floor_never_lowers_an_already_critical_asset(tmp_path, monkeypatch):
    """The floor only raises a low business_criticality up to "high" for
    CMMC-in-scope assets — it must never override an asset the user already
    marked "critical"."""
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability

    already_critical = create_asset(
        uid,
        "already-critical-cui-box",
        asset_type="server",
        criticality="low",
        business_criticality="critical",
        cmmc_asset_category="spa",
    )
    v = create_vulnerability(
        uid,
        {"asset_id": already_critical["id"], "asset_name": "already-critical-cui-box", "title": "Outdated OpenSSL", "severity": "high", "cvss": 7.5, "status": "open"},
    )

    res = client.get("/api/risk/priority", headers=_auth(token))
    item = next(i for i in res.json()["items"] if i["vuln_id"] == v["id"])
    assert item["business_criticality"] == "critical"
    assert item["cmmc_floor_applied"] is False
    assert item["cmmc_scope"] == "spa"


def test_priority_list_out_of_scope_asset_gets_no_cui_floor(tmp_path, monkeypatch):
    """out_of_scope is a real CMMC classification too (declared as NOT in
    the CUI boundary) — it must not trigger the floor, unlike cui_asset/spa."""
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability

    asset = create_asset(
        uid, "out-of-scope-box", asset_type="server", criticality="low", cmmc_asset_category="out_of_scope"
    )
    v = create_vulnerability(
        uid,
        {"asset_id": asset["id"], "asset_name": "out-of-scope-box", "title": "Outdated OpenSSL", "severity": "high", "cvss": 7.5, "status": "open"},
    )

    res = client.get("/api/risk/priority", headers=_auth(token))
    item = next(i for i in res.json()["items"] if i["vuln_id"] == v["id"])
    assert item["cmmc_scope"] == "out_of_scope"
    assert item["cmmc_floor_applied"] is False
    assert item["business_criticality"] == "low"
