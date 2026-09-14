"""CMMC "Secure Enclave" architecture type -- an engagement-level, self-reported
classification of the CUI-boundary technology pattern an organization uses
(app.cmmc_enclave_architecture). Covers the taxonomy module itself, the
engagement CRUD wiring (create/update persist and normalize it, get returns
it), and that it actually shows up in the generated SSP/compliance document
when set on the engagement linked to an assessment -- and is silently omitted
when not set, per the product's no-fabricated-compliance-data rule.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _setup(tmp_path, monkeypatch, username="enclave_arch_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    u = register_user(username, "password123", role="admin")
    return u.id


def test_normalize_accepts_known_ids_and_variants():
    from app.cmmc_enclave_architecture import normalize_enclave_architecture

    assert normalize_enclave_architecture("commercial_vdi") == "commercial_vdi"
    assert normalize_enclave_architecture("Commercial VDI") == "commercial_vdi"
    assert normalize_enclave_architecture("commercial-rds-cloud") == "commercial_rds_cloud"
    assert normalize_enclave_architecture("  MSP_GCC_HIGH  ") == "msp_gcc_high"
    assert normalize_enclave_architecture("not-a-real-type") == ""
    assert normalize_enclave_architecture(None) == ""
    assert normalize_enclave_architecture("") == ""


def test_list_enclave_architecture_types_covers_all_six_with_labels_and_descriptions():
    from app.cmmc_enclave_architecture import ENCLAVE_ARCH_ORDER, list_enclave_architecture_types

    types = list_enclave_architecture_types()
    assert len(types) == len(ENCLAVE_ARCH_ORDER) == 6
    ids = {t["id"] for t in types}
    assert ids == set(ENCLAVE_ARCH_ORDER)
    for t in types:
        assert t["label"].strip()
        assert t["description"].strip()
        assert len(t["description"]) > 40  # not a placeholder stub


def test_label_and_description_helpers_handle_unset_and_unknown():
    from app.cmmc_enclave_architecture import (
        enclave_architecture_description,
        enclave_architecture_label,
    )

    assert enclave_architecture_label("") == "Not set"
    assert enclave_architecture_label("bogus") == "Not set"
    assert enclave_architecture_description("") == ""
    assert enclave_architecture_description("onprem_rds").strip()


def test_create_engagement_persists_normalized_enclave_architecture(tmp_path, monkeypatch):
    uid = _setup(tmp_path, monkeypatch)
    from app.services.engagements import create_engagement

    eng = create_engagement(uid, "Acme CMMC Engagement", cmmc_enclave_architecture="Commercial-VDI")
    assert eng["cmmc_enclave_architecture"] == "commercial_vdi"


def test_create_engagement_rejects_garbage_enclave_value_silently_to_unset(tmp_path, monkeypatch):
    uid = _setup(tmp_path, monkeypatch)
    from app.services.engagements import create_engagement

    eng = create_engagement(uid, "Acme Engagement", cmmc_enclave_architecture="not-a-real-type")
    assert eng["cmmc_enclave_architecture"] == ""


def test_update_engagement_sets_and_clears_enclave_architecture(tmp_path, monkeypatch):
    uid = _setup(tmp_path, monkeypatch)
    from app.services.engagements import create_engagement, get_engagement, update_engagement

    eng = create_engagement(uid, "Acme Engagement")
    assert eng["cmmc_enclave_architecture"] == ""

    updated = update_engagement(uid, eng["id"], cmmc_enclave_architecture="msp_gcc_high")
    assert updated["cmmc_enclave_architecture"] == "msp_gcc_high"
    assert get_engagement(uid, eng["id"])["cmmc_enclave_architecture"] == "msp_gcc_high"

    # Omitting the field on a later update leaves it unchanged (None = no-op, not clear).
    updated2 = update_engagement(uid, eng["id"], name="Renamed Acme")
    assert updated2["cmmc_enclave_architecture"] == "msp_gcc_high"
    assert updated2["name"] == "Renamed Acme"

    # Explicit empty string clears it.
    cleared = update_engagement(uid, eng["id"], cmmc_enclave_architecture="")
    assert cleared["cmmc_enclave_architecture"] == ""


def test_update_engagement_returns_none_for_missing_engagement(tmp_path, monkeypatch):
    uid = _setup(tmp_path, monkeypatch)
    from app.services.engagements import update_engagement

    assert update_engagement(uid, "does-not-exist", cmmc_enclave_architecture="onprem_rds") is None


def test_ssp_includes_enclave_architecture_note_when_set_on_linked_engagement(tmp_path, monkeypatch):
    uid = _setup(tmp_path, monkeypatch)
    from app.gap_analysis import run_gap_analysis
    from app.services.compliance_documents import generate_report_markdown
    from app.services.engagements import create_engagement, update_engagement

    eng = create_engagement(uid, "Acme CMMC Engagement")
    update_engagement(uid, eng["id"], cmmc_enclave_architecture="onprem_rds")

    assessment = run_gap_analysis(
        framework_id="cmmc_l2",
        evidence="We use MFA everywhere and encrypt all CUI at rest and in transit.",
        title="CMMC self-assessment",
        engagement_id=eng["id"],
        user_id=uid,
    )
    md = generate_report_markdown(uid, assessment["id"])
    assert "Enclave architecture" in md
    assert "On-prem RDS enclave" in md
    assert "self-reported" in md.lower()


def test_ssp_omits_enclave_architecture_note_when_not_set(tmp_path, monkeypatch):
    uid = _setup(tmp_path, monkeypatch)
    from app.gap_analysis import run_gap_analysis
    from app.services.compliance_documents import generate_report_markdown
    from app.services.engagements import create_engagement

    eng = create_engagement(uid, "Acme CMMC Engagement (no enclave type set)")

    assessment = run_gap_analysis(
        framework_id="cmmc_l2",
        evidence="Some evidence text.",
        title="CMMC self-assessment",
        engagement_id=eng["id"],
        user_id=uid,
    )
    md = generate_report_markdown(uid, assessment["id"])
    assert "Enclave architecture" not in md


def test_ssp_omits_enclave_architecture_note_when_no_engagement_linked(tmp_path, monkeypatch):
    uid = _setup(tmp_path, monkeypatch)
    from app.gap_analysis import run_gap_analysis
    from app.services.compliance_documents import generate_report_markdown

    assessment = run_gap_analysis(
        framework_id="cmmc_l2",
        evidence="Some evidence text.",
        title="CMMC self-assessment (no engagement)",
        engagement_id=None,
        user_id=uid,
    )
    md = generate_report_markdown(uid, assessment["id"])
    assert "Enclave architecture" not in md
