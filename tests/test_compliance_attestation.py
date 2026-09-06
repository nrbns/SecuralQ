"""Tests for app.services.compliance_attestation -- generalized per-framework
attestation tracking (the non-cmmc_l2 counterpart to cmmc_affirmation.py).
"""

from __future__ import annotations

import pytest

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="attest_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def test_attestation_profile_known_frameworks():
    from app.services.compliance_attestation import attestation_profile

    iso = attestation_profile("iso27001")
    assert iso["attestation_label"] == "Management review sign-off"
    assert iso["reassessment_cycle_days"] == 3 * 365
    assert iso["mandated"] is True

    soc2 = attestation_profile("soc2")
    assert soc2["attestation_label"] == "Type II report issuance"
    assert soc2["mandated"] is False

    pci = attestation_profile("pci_dss")
    assert pci["attestation_label"] == "SAQ / Attestation of Compliance (AOC)"
    assert pci["mandated"] is True


def test_attestation_profile_default_for_unmapped_framework():
    from app.services.compliance_attestation import attestation_profile

    profile = attestation_profile("some_future_framework")
    assert profile["attestation_label"] == "Internal control review sign-off"
    assert profile["mandated"] is False


def test_create_attestation_requires_official(tmp_path, monkeypatch):
    from app.db import now
    from app.services.compliance_attestation import create_attestation

    uid = _setup(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        create_attestation(uid, framework_id="iso27001", assessment_date=now(), attesting_official="  ")


def test_create_attestation_rejects_future_date(tmp_path, monkeypatch):
    from app.db import now
    from app.services.compliance_attestation import create_attestation

    uid = _setup(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        create_attestation(
            uid, framework_id="iso27001", assessment_date=now() + 999999, attesting_official="Jane CISO"
        )


def test_create_and_get_attestation_computes_real_due_dates(tmp_path, monkeypatch):
    from app.db import now
    from app.services.compliance_attestation import create_attestation, get_attestation

    uid = _setup(monkeypatch, tmp_path)
    assessment_date = now() - 1000
    created = create_attestation(
        uid, framework_id="iso27001", assessment_date=assessment_date, attesting_official="Jane CISO"
    )
    assert created["attesting_official"] == "Jane CISO"
    # 1-year affirmation, 3-year recert -- computed from calendar math, not fabricated
    assert abs(created["next_affirmation_due"] - (assessment_date + 365 * 86400)) < 1
    assert abs(created["next_reassessment_due"] - (assessment_date + 3 * 365 * 86400)) < 1

    got = get_attestation(uid, created["id"])
    assert got["framework_id"] == "iso27001"
    assert got["profile"]["attestation_label"] == "Management review sign-off"


def test_list_and_latest_attestation(tmp_path, monkeypatch):
    from app.db import now
    from app.services.compliance_attestation import create_attestation, latest_attestation, list_attestations

    uid = _setup(monkeypatch, tmp_path)
    create_attestation(
        uid, framework_id="hipaa", assessment_date=now() - 500000, attesting_official="A"
    )
    create_attestation(
        uid, framework_id="hipaa", assessment_date=now() - 100, attesting_official="B"
    )
    create_attestation(
        uid, framework_id="pci_dss", assessment_date=now() - 100, attesting_official="C"
    )

    hipaa_only = list_attestations(uid, framework_id="hipaa")
    assert len(hipaa_only) == 2

    latest = latest_attestation(uid, framework_id="hipaa")
    assert latest["attesting_official"] == "B"

    everything = list_attestations(uid)
    assert len(everything) == 3


def test_delete_attestation(tmp_path, monkeypatch):
    from app.db import now
    from app.services.compliance_attestation import create_attestation, delete_attestation, get_attestation

    uid = _setup(monkeypatch, tmp_path)
    created = create_attestation(
        uid, framework_id="gdpr", assessment_date=now(), attesting_official="DPO"
    )
    assert delete_attestation(uid, created["id"]) is True
    assert get_attestation(uid, created["id"]) is None
    assert delete_attestation(uid, created["id"]) is False


def test_overdue_flags_computed_correctly(tmp_path, monkeypatch):
    from app.services.compliance_attestation import create_attestation

    uid = _setup(monkeypatch, tmp_path)
    # An assessment from 2 years ago on an annual cadence must show overdue.
    two_years_ago = 0.0
    from app.db import now

    two_years_ago = now() - (2 * 365 * 86400)
    created = create_attestation(
        uid, framework_id="soc2", assessment_date=two_years_ago, attesting_official="Auditor"
    )
    assert created["affirmation_overdue"] is True
    assert created["reassessment_overdue"] is True
