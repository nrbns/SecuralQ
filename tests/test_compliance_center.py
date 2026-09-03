"""Tests for app.services.compliance_center -- Compliance Center and Audit
Center aggregates. Every number here must be traceable to a real
gap_assessments/evidence_links/securaiq_exceptions row; the tests assert
that un-assessed frameworks are excluded from the percentage rather than
silently scored 0%.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="compliance_center_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def test_compliance_overview_empty_account_has_no_scored_frameworks(tmp_path, monkeypatch):
    from app.services.compliance_center import compliance_overview

    uid = _setup(monkeypatch, tmp_path)
    overview = compliance_overview(uid)
    assert overview["overall_compliance_percent"] is None
    assert overview["frameworks_assessed"] == 0
    assert overview["frameworks_total"] > 0  # catalog still lists all frameworks
    assert all(not f["assessed"] for f in overview["frameworks"])


def test_compliance_overview_reflects_real_assessment(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis
    from app.services.compliance_center import compliance_overview

    uid = _setup(monkeypatch, tmp_path)
    run_gap_analysis(framework_id="cis_controls", evidence="", user_id=uid, title="t")

    overview = compliance_overview(uid)
    assert overview["frameworks_assessed"] == 1
    assert overview["overall_compliance_percent"] is not None
    cis = next(f for f in overview["frameworks"] if f["framework_id"] == "cis_controls")
    assert cis["assessed"] is True
    assert cis["assessment_id"]
    assert cis["live_tested_controls"] > 0  # CIS-1, CIS-7 are mapped


def test_compliance_overview_uses_latest_assessment_per_framework(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis
    from app.services.compliance_center import compliance_overview

    uid = _setup(monkeypatch, tmp_path)
    run_gap_analysis(framework_id="cis_controls", evidence="", user_id=uid, title="first")
    second = run_gap_analysis(framework_id="cis_controls", evidence="access control policy", user_id=uid, title="second")

    overview = compliance_overview(uid)
    cis = next(f for f in overview["frameworks"] if f["framework_id"] == "cis_controls")
    assert cis["assessment_id"] == second["id"]


def test_compliance_overview_includes_exception_summary(tmp_path, monkeypatch):
    from app.db import now
    from app.services.compliance_center import compliance_overview
    from app.services.exceptions import create_exception

    uid = _setup(monkeypatch, tmp_path)
    create_exception(
        uid,
        title="X",
        reason="y",
        risk_accepted="z",
        owner="ciso@example.com",
        expiry=now() + 10 * 86400,
    )
    overview = compliance_overview(uid)
    assert overview["exceptions"]["total"] == 1


def test_audit_center_overview_empty_account(tmp_path, monkeypatch):
    from app.services.compliance_center import audit_center_overview

    uid = _setup(monkeypatch, tmp_path)
    overview = audit_center_overview(uid)
    assert overview["assessments_included"] == 0
    assert overview["totals"]["controls_total"] == 0


def test_audit_center_overview_reflects_real_assessment(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis
    from app.services.compliance_center import audit_center_overview

    uid = _setup(monkeypatch, tmp_path)
    run_gap_analysis(framework_id="cis_controls", evidence="", user_id=uid, title="t")

    overview = audit_center_overview(uid)
    assert overview["assessments_included"] == 1
    cis = next(f for f in overview["frameworks"] if f["framework_id"] == "cis_controls")
    assert cis["controls_total"] > 0
    assert cis["failing"] > 0  # no pasted evidence -> everything scored missing
    assert cis["evidence_supplied"] == 0  # no evidence links created


def test_audit_center_overview_evidence_supplied_counts_accepted_links(tmp_path, monkeypatch):
    from app.commercial_ext import link_evidence
    from app.gap_analysis import run_gap_analysis
    from app.services.compliance_center import audit_center_overview

    uid = _setup(monkeypatch, tmp_path)
    assessment = run_gap_analysis(framework_id="cis_controls", evidence="", user_id=uid, title="t")
    cis1 = next(r for r in assessment["results"] if r["control_id"] == "CIS-1")

    from app.db import get_conn, new_id, now

    # Insert a minimal files row directly (mirrors how uploads are stored) so
    # link_evidence's file-ownership check passes without exercising the
    # full upload pipeline, which is out of scope for this aggregate test.
    fid = new_id()
    c = get_conn()
    c.execute(
        "INSERT INTO files (id, user_id, filename, stored_path, size_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (fid, uid, "policy.pdf", "/tmp/policy.pdf", 10, now()),
    )
    c.commit()
    link_evidence(uid, file_id=fid, control_id=cis1["control_id"], status="accepted")

    overview = audit_center_overview(uid)
    cis = next(f for f in overview["frameworks"] if f["framework_id"] == "cis_controls")
    assert cis["evidence_supplied"] == 1
    assert cis["evidence_missing"] == cis["controls_total"] - 1
