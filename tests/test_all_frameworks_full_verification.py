"""Full-coverage verification: every framework in the catalog, and every
control inside each, actually works end-to-end through the real pipeline --
not just a spot check on one or two frameworks.

For each of the 14 catalogs (657 controls total as of this writing) this
file exercises the real code path a user hits: run a gap analysis against
every single control, confirm the assessment round-trips, generate the
framework-correct compliance document and action plan, build an audit pack,
confirm the attestation/affirmation system has a working profile, and
confirm live control testing doesn't error even where no live test is
mapped. Nothing here is mocked -- it is the same app.gap_analysis /
app.services.compliance_documents / app.services.compliance_attestation /
app.services.control_testing code the HTTP routes call.
"""

from __future__ import annotations

import pytest

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def _all_framework_ids() -> list[str]:
    from app.gap_analysis import list_frameworks

    return sorted(f["id"] for f in list_frameworks())


ALL_FRAMEWORK_IDS = _all_framework_ids()

# Generic evidence text with no framework-specific keywords -- deliberately
# thin, so most controls land as "missing"/"partial" and we exercise the
# real gap/remediation/document code paths rather than an all-implemented
# assessment.
GENERIC_EVIDENCE = (
    "We maintain written information security policies reviewed annually by "
    "management, an asset inventory, and role-based access control with "
    "multi-factor authentication for administrative accounts."
)


def test_catalog_covers_all_known_frameworks():
    """Sanity check on the fixture itself -- if a framework file is added or
    removed, this test (and the parametrized ones below) picks it up."""
    assert len(ALL_FRAMEWORK_IDS) == 14
    assert "cmmc_l2" in ALL_FRAMEWORK_IDS
    assert "iso27001" in ALL_FRAMEWORK_IDS


@pytest.mark.parametrize("framework_id", ALL_FRAMEWORK_IDS)
def test_catalog_schema_valid(framework_id):
    """Every control in every framework has the fields the rest of the app
    depends on, with no duplicate or empty ids."""
    from app.gap_analysis import load_framework

    fw = load_framework(framework_id)
    controls = fw.get("controls") or []
    assert controls, f"{framework_id} has no controls"

    ids = [c.get("id") for c in controls]
    assert all(ids), f"{framework_id} has a control with an empty id"
    assert len(set(ids)) == len(ids), f"{framework_id} has duplicate control ids"

    for c in controls:
        assert c.get("title"), f"{framework_id}/{c.get('id')} has no title"
        assert isinstance(c.get("keywords"), list), f"{framework_id}/{c.get('id')} keywords must be a list"


@pytest.mark.parametrize("framework_id", ALL_FRAMEWORK_IDS)
def test_gap_analysis_scores_every_control(tmp_path, monkeypatch, framework_id):
    """run_gap_analysis must score every single control in the catalog --
    not silently drop any -- and every control must land in exactly one of
    the four known statuses."""
    from app.gap_analysis import load_framework, run_gap_analysis

    uid = _setup(monkeypatch, tmp_path, username=f"full_verify_{framework_id}")
    fw = load_framework(framework_id)
    expected_ids = {c["id"] for c in fw["controls"]}

    assessment = run_gap_analysis(
        framework_id=framework_id, evidence=GENERIC_EVIDENCE, user_id=uid, title="full-verify"
    )

    assert assessment["control_count"] == len(expected_ids)
    result_ids = {r["control_id"] for r in assessment["results"]}
    assert result_ids == expected_ids, f"{framework_id}: scored ids don't match catalog ids"

    valid_statuses = {"implemented", "partial", "missing", "not_applicable"}
    for r in assessment["results"]:
        assert r["status"] in valid_statuses, f"{framework_id}/{r['control_id']} has invalid status {r['status']!r}"

    assert sum(assessment["counts"].values()) == len(expected_ids)


@pytest.mark.parametrize("framework_id", ALL_FRAMEWORK_IDS)
def test_documents_generate_without_error(tmp_path, monkeypatch, framework_id):
    """The framework-correct report and action plan must generate for every
    framework, using that framework's own document terminology."""
    from app.gap_analysis import run_gap_analysis
    from app.services.compliance_documents import (
        document_profile,
        generate_action_plan_markdown,
        generate_report_markdown,
    )

    uid = _setup(monkeypatch, tmp_path, username=f"docs_verify_{framework_id}")
    assessment = run_gap_analysis(
        framework_id=framework_id, evidence=GENERIC_EVIDENCE, user_id=uid, title="doc-verify"
    )

    profile = document_profile(framework_id)
    assert profile["report_kind"]
    assert profile["plan_kind"]

    report = generate_report_markdown(uid, assessment["id"])
    assert f"# {profile['report_kind']}" in report
    assert framework_id in report

    plan = generate_action_plan_markdown(uid, assessment["id"])
    assert f"# {profile['plan_kind']}" in plan


@pytest.mark.parametrize("framework_id", ALL_FRAMEWORK_IDS)
def test_export_markdown_and_audit_pack_build(tmp_path, monkeypatch, framework_id):
    """The original gap-export markdown and the evidence audit-pack ZIP must
    both build without error for every framework."""
    from app.evidence_workflow import build_audit_pack_zip
    from app.gap_analysis import export_gap_markdown, run_gap_analysis

    uid = _setup(monkeypatch, tmp_path, username=f"export_verify_{framework_id}")
    assessment = run_gap_analysis(
        framework_id=framework_id, evidence=GENERIC_EVIDENCE, user_id=uid, title="export-verify"
    )

    md = export_gap_markdown(uid, assessment["id"])
    assert md and framework_id in md

    zip_bytes = build_audit_pack_zip(uid, assessment["id"])
    assert zip_bytes[:2] == b"PK"  # real ZIP magic bytes, not an empty/error payload


@pytest.mark.parametrize("framework_id", ALL_FRAMEWORK_IDS)
def test_live_control_tests_do_not_error(tmp_path, monkeypatch, framework_id):
    """run_live_tests_for_framework must never raise, whether or not this
    framework has any live-test-mapped controls."""
    from app.services.control_testing import run_live_tests_for_framework

    uid = _setup(monkeypatch, tmp_path, username=f"live_verify_{framework_id}")
    results = run_live_tests_for_framework(uid, framework_id, record_evidence=False)
    assert isinstance(results, dict)


@pytest.mark.parametrize("framework_id", ALL_FRAMEWORK_IDS)
def test_attestation_or_affirmation_system_works(tmp_path, monkeypatch, framework_id):
    """cmmc_l2 has its own dedicated SPRS affirmation system; every other
    framework must have a working generic attestation profile and be able
    to record + read back an attestation."""
    from app.db import now

    uid = _setup(monkeypatch, tmp_path, username=f"attest_verify_{framework_id}")

    if framework_id == "cmmc_l2":
        from app.services.cmmc_affirmation import create_affirmation, get_affirmation

        created = create_affirmation(
            uid, level="Level 1", assessment_date=now(), affirming_official="Verifier"
        )
        assert get_affirmation(uid, created["id"]) is not None
        return

    from app.services.compliance_attestation import attestation_profile, create_attestation, get_attestation

    profile = attestation_profile(framework_id)
    assert profile["attestation_label"]
    assert profile["affirmation_cycle_days"] > 0
    assert profile["reassessment_cycle_days"] > 0

    created = create_attestation(
        uid, framework_id=framework_id, assessment_date=now(), attesting_official="Verifier"
    )
    assert get_attestation(uid, created["id"]) is not None


@pytest.mark.parametrize("framework_id", ALL_FRAMEWORK_IDS)
def test_full_implementation_scores_100_percent(tmp_path, monkeypatch, framework_id):
    """Feeding every control's own title + keywords back in as evidence must
    drive every control to implemented and the assessment to 100% -- proves
    the scoring path can actually reach full compliance for every framework,
    not just partial credit."""
    from app.gap_analysis import load_framework, run_gap_analysis

    uid = _setup(monkeypatch, tmp_path, username=f"full_impl_{framework_id}")
    fw = load_framework(framework_id)
    full_evidence = ". ".join(
        f"{c['title']} {' '.join(c.get('keywords') or [])}" for c in fw["controls"]
    )

    assessment = run_gap_analysis(
        framework_id=framework_id, evidence=full_evidence, user_id=uid, title="full-impl-verify"
    )
    assert assessment["compliance_percent"] == 100.0, (
        f"{framework_id}: full self-evidence did not reach 100% "
        f"(counts={assessment['counts']})"
    )
