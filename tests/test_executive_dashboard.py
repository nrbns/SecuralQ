"""Unit tests for app.services.executive_dashboard -- the management-facing
view, separate from the technical SOC page. Every number must be real or
explicitly None/empty when there isn't enough data; nothing here should be
fabricated to fill a gap.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="exec_dashboard_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def test_empty_state_reports_none_rather_than_fabricated_numbers(tmp_path, monkeypatch):
    from app.services.executive_dashboard import compute_executive_dashboard

    uid = _setup(monkeypatch, tmp_path)
    result = compute_executive_dashboard(uid)

    assert result["security_exposure"]["current_score"] == 0.0
    assert result["security_exposure"]["change_pct"] is None  # < 2 history points
    assert result["critical_findings"]["critical"] == 0
    assert result["critical_findings"]["change_since_earliest_snapshot"] is None
    assert result["patch_compliance"]["pct"] is None  # no software inventory at all
    assert result["mean_remediation_time"]["mean_days"] is None  # nothing resolved yet
    assert result["mean_remediation_time"]["sample_size"] == 0
    assert result["verified_remediation"]["verified_pct"] is None  # nothing executed yet
    assert result["active_campaigns"] == 0
    assert result["top_remaining_risks"] == []
    assert result["active_threats"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    assert result["asset_health"] == {"healthy": 0, "at_risk": 0, "compromised": 0, "offline": 0, "total": 0}
    assert result["ai_priority_queue"] == []


def test_dashboard_reflects_real_open_findings_and_risk(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_vulnerability
    from app.services.executive_dashboard import compute_executive_dashboard

    uid = _setup(monkeypatch, tmp_path)
    a = create_asset(uid, "WEB-01", asset_type="web", business_criticality="critical")
    create_vulnerability(
        uid,
        {"asset_id": a["id"], "asset_name": "WEB-01", "title": "Apache RCE", "cve": "CVE-2024-1111", "severity": "critical", "cvss": 9.8, "status": "open"},
    )

    result = compute_executive_dashboard(uid)
    assert result["security_exposure"]["current_score"] > 0
    assert result["critical_findings"]["critical"] == 1
    assert result["critical_findings"]["critical_high"] == 1
    assert len(result["top_remaining_risks"]) == 1
    assert result["top_remaining_risks"][0]["cve"] == "CVE-2024-1111"


def test_mean_remediation_time_only_counts_resolved_findings(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_vulnerability
    from app.db import get_conn, now
    from app.services.executive_dashboard import compute_executive_dashboard

    uid = _setup(monkeypatch, tmp_path)
    a = create_asset(uid, "WEB-01", asset_type="web")
    v = create_vulnerability(
        uid,
        {"asset_id": a["id"], "asset_name": "WEB-01", "title": "Old bug", "cve": "CVE-2024-2222", "severity": "high", "cvss": 7.0, "status": "open"},
    )
    # simulate it having been open for 3 real days before resolution, then resolve it
    c = get_conn()
    created = now() - 3 * 86400
    c.execute("UPDATE vulnerabilities SET created_at = ? WHERE id = ?", (created, v["id"]))
    c.commit()
    c.execute("UPDATE vulnerabilities SET status = 'resolved', updated_at = ? WHERE id = ?", (now(), v["id"]))
    c.commit()

    result = compute_executive_dashboard(uid)
    assert result["mean_remediation_time"]["sample_size"] == 1
    assert 2.9 <= result["mean_remediation_time"]["mean_days"] <= 3.1


def test_patch_compliance_pct_from_real_software_inventory(tmp_path, monkeypatch):
    from app.db import get_conn, new_id, now
    from app.software.models import ensure_schema as ensure_software_schema
    from app.services.executive_dashboard import compute_executive_dashboard

    uid = _setup(monkeypatch, tmp_path)
    ensure_software_schema()
    c = get_conn()
    ts = now()
    for i in range(4):
        pid = new_id()
        c.execute(
            "INSERT INTO software_products (id, user_id, name, normalized_name, canonical_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (pid, uid, f"pkg-{i}", f"pkg-{i}", f"pkg-{i}", ts, ts),
        )
        iid = new_id()
        c.execute(
            "INSERT INTO software_installations (id, user_id, asset_id, asset_name, software_product_id, version, first_seen, last_seen, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (iid, uid, "asset-x", "asset-x", pid, "1.0", ts, ts, ts),
        )
        status = "up_to_date" if i < 3 else "update_available"
        c.execute(
            "INSERT INTO patch_status (id, user_id, software_installation_id, status, target_version, version_source, reason, checked_at) VALUES (?,?,?,?,?,?,?,?)",
            (new_id(), uid, iid, status, "", "", "", ts),
        )
    c.commit()

    result = compute_executive_dashboard(uid)
    assert result["patch_compliance"]["total"] == 4
    assert result["patch_compliance"]["up_to_date"] == 3
    assert result["patch_compliance"]["pct"] == 75.0


def test_verified_remediation_and_active_campaigns_from_real_campaign_activity(tmp_path, monkeypatch):
    from app.agents import (
        approve_command,
        create_campaign,
        enroll_agent,
        list_pending_commands,
        record_command_verification,
        report_command_result,
    )
    from app.services.executive_dashboard import compute_executive_dashboard

    uid = _setup(monkeypatch, tmp_path)
    agent = enroll_agent(uid, name="exec-dash-agent")
    campaign = create_campaign(uid, name="exec dash campaign", manager="apt", package="apache2", agent_ids=[agent["agent_id"]])

    result_before = compute_executive_dashboard(uid)
    assert result_before["active_campaigns"] == 1
    assert result_before["verified_remediation"]["verified_pct"] is None  # nothing done yet

    # approve, execute, and verify the single command this campaign created
    pending = list_pending_commands(uid)
    cmd = next(c for c in pending if c["campaign_id"] == campaign["id"])
    approve_command(uid, agent["agent_id"], cmd["id"], approver_id=uid)
    report_command_result(agent["agent_id"], cmd["id"], status="done", result={"output": "ok"})
    record_command_verification(cmd["id"], verified=True)

    result_after = compute_executive_dashboard(uid)
    assert result_after["verified_remediation"]["total_done"] == 1
    assert result_after["verified_remediation"]["verified"] == 1
    assert result_after["verified_remediation"]["verified_pct"] == 100.0


# --- active threats, asset health, AI priority queue (Command Center rebuild) -


def test_active_threats_counts_only_active_by_severity(tmp_path, monkeypatch):
    from app.agents import enroll_agent, record_threat_detections
    from app.services.executive_dashboard import compute_executive_dashboard

    uid = _setup(monkeypatch, tmp_path)
    agent = enroll_agent(uid, name="threat-dash-agent")
    record_threat_detections(
        agent["agent_id"],
        [
            {"severity": "critical", "category": "ransomware", "title": "Ransomware indicator", "target": "/var/x"},
            {"severity": "medium", "category": "behavioral", "title": "Odd process", "target": "/tmp/y"},
        ],
    )

    result = compute_executive_dashboard(uid)
    assert result["active_threats"]["critical"] == 1
    assert result["active_threats"]["medium"] == 1
    assert result["active_threats"]["total"] == 2


def test_asset_health_categorizes_by_real_signals(tmp_path, monkeypatch):
    from app.agents import enroll_agent, record_threat_detections
    from app.enterprise import create_asset, create_vulnerability
    from app.services.executive_dashboard import compute_executive_dashboard

    uid = _setup(monkeypatch, tmp_path)

    healthy = create_asset(uid, "HEALTHY-01", asset_type="web")

    at_risk = create_asset(uid, "ATRISK-01", asset_type="web")
    create_vulnerability(
        uid, {"asset_id": at_risk["id"], "asset_name": "ATRISK-01", "title": "Old bug", "severity": "high", "status": "open"}
    )

    compromised = create_asset(uid, "COMPROMISED-01", asset_type="web")
    agent = enroll_agent(uid, name="compromised-agent")
    # link the agent to the compromised asset directly (bypassing the
    # hostname-matching heuristic in checkin() -- this test only cares
    # about asset_health reading agent.asset_id correctly)
    from app.db import get_conn

    c = get_conn()
    c.execute("UPDATE securaiq_agents SET asset_id = ? WHERE id = ?", (compromised["id"], agent["agent_id"]))
    c.commit()
    record_threat_detections(
        agent["agent_id"], [{"severity": "critical", "category": "ransomware", "title": "Active ransomware", "target": "/x"}]
    )

    result = compute_executive_dashboard(uid)
    health = result["asset_health"]
    assert health["total"] == 3
    assert health["compromised"] == 1
    assert health["at_risk"] == 1
    assert health["healthy"] == 1
    _ = healthy


def test_ai_priority_queue_ranks_and_enriches_with_attack_paths(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_vulnerability
    from app.services.executive_dashboard import compute_executive_dashboard

    uid = _setup(monkeypatch, tmp_path)
    a = create_asset(uid, "PRIORITY-01", asset_type="web", business_criticality="critical")
    create_vulnerability(
        uid,
        {"asset_id": a["id"], "asset_name": "PRIORITY-01", "title": "Apache RCE", "cve": "CVE-2024-9999", "severity": "critical", "cvss": 9.8, "status": "open"},
    )

    result = compute_executive_dashboard(uid)
    queue = result["ai_priority_queue"]
    assert len(queue) == 1
    item = queue[0]
    assert item["cve"] == "CVE-2024-9999"
    assert item["group_key"] == "cve:CVE-2024-9999"
    assert "verified_attack_paths_disrupted" in item
    assert item["asset_names"] == ["PRIORITY-01"]
    assert item["estimated_risk_reduction_pct"] >= 0
