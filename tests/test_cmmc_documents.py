"""Tests for app.services.cmmc_documents -- SSP / POA&M generation and the
SPRS score preview. Every assertion checks that the document reflects real
assessment/evidence/remediation data rather than fabricated placeholder text.
"""

from __future__ import annotations

import pytest

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="cmmc_doc_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def test_ssp_raises_for_unknown_assessment(tmp_path, monkeypatch):
    from app.services.cmmc_documents import generate_ssp_markdown

    _setup(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        generate_ssp_markdown("local", "does-not-exist")


def test_ssp_no_fabrication_when_nothing_configured(tmp_path, monkeypatch):
    """No org profile, no assets, no evidence -- the SSP must say so plainly,
    never invent an org name or an implementation narrative."""
    from app.gap_analysis import run_gap_analysis
    from app.services.cmmc_documents import generate_ssp_markdown

    uid = _setup(monkeypatch, tmp_path)
    assessment = run_gap_analysis(framework_id="cmmc_l2", evidence="", user_id=uid, title="t")

    md = generate_ssp_markdown(uid, assessment["id"])
    assert "System Security Plan" in md
    assert "not a certified SSP" in md
    assert "no organization profile configured" in md
    assert "no assets have been registered yet" in md
    assert "not yet documented" in md
    # All 110 controls should appear, grouped by domain
    assert "AC.L2-3.1.1" in md
    assert "SI.L2-3.14.7" in md


def test_ssp_reflects_real_org_and_evidence(tmp_path, monkeypatch):
    from app.commercial_ext import create_org, link_evidence
    from app.db import get_conn, new_id, now
    from app.gap_analysis import run_gap_analysis
    from app.services.cmmc_documents import generate_ssp_markdown

    uid = _setup(monkeypatch, tmp_path)
    create_org(uid, name="Acme Defense LLC")
    assessment = run_gap_analysis(
        framework_id="cmmc_l2",
        evidence="access control least privilege authorized users",
        user_id=uid,
        title="t",
    )
    implemented = next(r for r in assessment["results"] if r["status"] == "implemented")
    cid = implemented["control_id"]

    fid = new_id()
    c = get_conn()
    c.execute(
        "INSERT INTO files (id, user_id, filename, stored_path, size_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (fid, uid, "access-control-policy.pdf", "/tmp/access-control-policy.pdf", 10, now()),
    )
    c.commit()
    link_evidence(uid, file_id=fid, control_id=cid, status="accepted", notes="Reviewed by CISO")

    md = generate_ssp_markdown(uid, assessment["id"])
    assert "Acme Defense LLC" in md
    assert "access-control-policy.pdf" in md
    assert "Reviewed by CISO" in md


def test_poam_lists_only_open_controls(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis
    from app.services.cmmc_documents import generate_poam_markdown

    uid = _setup(monkeypatch, tmp_path)
    assessment = run_gap_analysis(
        framework_id="cmmc_l2",
        evidence="access control least privilege authorized users",
        user_id=uid,
        title="t",
    )
    implemented_ids = {r["control_id"] for r in assessment["results"] if r["status"] == "implemented"}
    missing_ids = {r["control_id"] for r in assessment["results"] if r["status"] in ("missing", "partial")}
    assert implemented_ids, "test needs at least one implemented control to be meaningful"

    md = generate_poam_markdown(uid, assessment["id"])
    assert "Plan of Action" in md
    assert "not a POA&M accepted by any authority" in md
    for cid in list(missing_ids)[:5]:
        assert cid in md
    for cid in list(implemented_ids)[:3]:
        # implemented controls must not appear in the open-items table
        assert f"| {cid} |" not in md


def test_poam_shows_remediation_owner_when_present(tmp_path, monkeypatch):
    from app.enterprise import create_remediations_from_assessment
    from app.gap_analysis import run_gap_analysis
    from app.services.cmmc_documents import generate_poam_markdown

    uid = _setup(monkeypatch, tmp_path)
    assessment = run_gap_analysis(framework_id="cmmc_l2", evidence="", user_id=uid, title="t")
    gaps = [r for r in assessment["results"] if r["status"] == "missing"]
    rems = create_remediations_from_assessment(uid, assessment["id"], gaps[:1], engagement_id=None)
    assert rems

    from app.db import get_conn

    c = get_conn()
    c.execute(
        "UPDATE gap_remediations SET owner = ?, due_date = ? WHERE id = ?",
        ("jane@example.com", "2027-01-01", rems[0]["id"]),
    )
    c.commit()

    md = generate_poam_markdown(uid, assessment["id"])
    assert "jane@example.com" in md
    assert "2027-01-01" in md


def test_sprs_preview_none_for_non_cmmc_framework(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis
    from app.services.cmmc_documents import compute_sprs_preview

    uid = _setup(monkeypatch, tmp_path)
    assessment = run_gap_analysis(framework_id="cis_controls", evidence="", user_id=uid, title="t")
    assert compute_sprs_preview(uid, assessment["id"]) is None


def test_sprs_preview_computes_real_score(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis
    from app.services.cmmc_documents import compute_sprs_preview

    uid = _setup(monkeypatch, tmp_path)
    # No evidence at all -> everything missing -> score should be 0 (max - all weight lost)
    empty_assessment = run_gap_analysis(framework_id="cmmc_l2", evidence="", user_id=uid, title="empty")
    preview = compute_sprs_preview(uid, empty_assessment["id"])
    assert preview is not None
    assert preview["max_score"] == 313
    assert preview["score"] == 0
    assert preview["points_lost"] == 313

    # Some real matching evidence -> score should move up from zero
    covered_assessment = run_gap_analysis(
        framework_id="cmmc_l2",
        evidence="access control least privilege authorized users multi-factor authentication MFA",
        user_id=uid,
        title="covered",
    )
    preview2 = compute_sprs_preview(uid, covered_assessment["id"])
    assert preview2["score"] > 0
    assert preview2["score"] < 313
