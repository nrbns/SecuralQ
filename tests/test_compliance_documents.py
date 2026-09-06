"""Tests for app.services.compliance_documents -- the framework-generic
report / action-plan generator that replaces a one-size-fits-all "SSP" label
with the real document name used in each framework's own ecosystem (see
FRAMEWORK_DOCS)."""

from __future__ import annotations

import pytest

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="compliance_doc_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def test_report_raises_for_unknown_assessment(tmp_path, monkeypatch):
    from app.services.compliance_documents import generate_report_markdown

    _setup(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        generate_report_markdown("local", "does-not-exist")


@pytest.mark.parametrize(
    "framework_id,expected_report_heading,expected_plan_heading",
    [
        ("iso27001", "Statement of Applicability (SoA)", "Corrective Action Plan"),
        ("hipaa", "Security Risk Assessment (SRA) Report", "Corrective Action Plan"),
        ("pci_dss", "PCI DSS Compliance Readiness Report", "Remediation Action Plan"),
        ("gdpr", "Article 32 Security Measures Report", "Corrective Action Plan"),
        ("nis2", "Article 21 Risk-Management Measures Report", "Corrective Action Plan"),
        ("soc2", "Control Implementation Report", "Remediation Action Plan"),
        ("cis_controls", "Control Implementation Report", "Remediation Action Plan"),
    ],
)
def test_document_uses_framework_correct_names(
    tmp_path, monkeypatch, framework_id, expected_report_heading, expected_plan_heading
):
    """Every framework must get its own real-world document name, not a
    generic 'SSP'/'POA&M' label borrowed from CMMC."""
    from app.gap_analysis import run_gap_analysis
    from app.services.compliance_documents import (
        generate_action_plan_markdown,
        generate_report_markdown,
    )

    uid = _setup(monkeypatch, tmp_path, username=f"tester_{framework_id}")
    assessment = run_gap_analysis(framework_id=framework_id, evidence="", user_id=uid, title="t")

    report = generate_report_markdown(uid, assessment["id"])
    assert f"# {expected_report_heading}" in report
    assert "System Security Plan" not in report or framework_id in {"cmmc_l2", "nist_800_171", "nist_800_53"}

    plan = generate_action_plan_markdown(uid, assessment["id"])
    assert f"# {expected_plan_heading}" in plan


def test_gdpr_report_discloses_ropa_limitation(tmp_path, monkeypatch):
    """GDPR's real Art. 30 document (RoPA) needs a data-processing register
    SecuraIQ doesn't collect -- the report must say so rather than pretend
    this is a RoPA."""
    from app.gap_analysis import run_gap_analysis
    from app.services.compliance_documents import generate_report_markdown

    uid = _setup(monkeypatch, tmp_path, username="gdpr_tester")
    assessment = run_gap_analysis(framework_id="gdpr", evidence="", user_id=uid, title="t")
    report = generate_report_markdown(uid, assessment["id"])
    assert "Record of Processing Activities" in report
    assert "does not yet collect" in report


def test_pci_report_discloses_no_saq_or_aoc_claim(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis
    from app.services.compliance_documents import generate_report_markdown

    uid = _setup(monkeypatch, tmp_path, username="pci_tester")
    assessment = run_gap_analysis(framework_id="pci_dss", evidence="", user_id=uid, title="t")
    report = generate_report_markdown(uid, assessment["id"])
    assert "not a completed Self-Assessment Questionnaire" in report
    assert "Attestation of Compliance" in report


def test_default_profile_used_for_unmapped_framework():
    from app.services.compliance_documents import document_profile

    profile = document_profile("some_future_framework_id")
    assert profile["report_kind"] == "Control Implementation Report"
    assert profile["plan_kind"] == "Remediation Action Plan"


def test_report_reflects_real_evidence_not_fabricated(tmp_path, monkeypatch):
    from app.commercial_ext import create_org, link_evidence
    from app.db import get_conn, new_id, now
    from app.gap_analysis import run_gap_analysis
    from app.services.compliance_documents import generate_report_markdown

    uid = _setup(monkeypatch, tmp_path, username="iso_evidence_tester")
    create_org(uid, name="Acme ISO Co")
    assessment = run_gap_analysis(
        framework_id="iso27001",
        evidence="information security policy approved by management",
        user_id=uid,
        title="t",
    )
    implemented = next((r for r in assessment["results"] if r["status"] == "implemented"), None)
    assert implemented, "test needs at least one implemented control"
    cid = implemented["control_id"]

    fid = new_id()
    c = get_conn()
    c.execute(
        "INSERT INTO files (id, user_id, filename, stored_path, size_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (fid, uid, "isms-policy.pdf", "/tmp/isms-policy.pdf", 10, now()),
    )
    c.commit()
    link_evidence(uid, file_id=fid, control_id=cid, status="accepted", notes="Approved by CISO")

    report = generate_report_markdown(uid, assessment["id"])
    assert "Acme ISO Co" in report
    assert "isms-policy.pdf" in report
    assert "not yet documented" in report  # other controls without evidence must say so
