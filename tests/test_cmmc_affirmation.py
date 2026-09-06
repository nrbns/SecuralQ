"""Tests for app.services.cmmc_affirmation -- the SPRS self-assessment
affirmation record. Every value stored is what the caller explicitly
provided (score, date, official) except the two due dates, which are
deterministic calendar math off assessment_date -- these tests pin both the
validation rules and the due-date arithmetic."""

from __future__ import annotations

import pytest

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="cmmc_affirm_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def test_level2_requires_score_in_range(tmp_path, monkeypatch):
    from app.db import now
    from app.services.cmmc_affirmation import create_affirmation

    uid = _setup(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        create_affirmation(uid, level="Level 2", assessment_date=now(), affirming_official="Jane CISO")
    with pytest.raises(ValueError):
        create_affirmation(
            uid, level="Level 2", assessment_date=now(), affirming_official="Jane CISO", score=500
        )


def test_level1_rejects_score(tmp_path, monkeypatch):
    from app.db import now
    from app.services.cmmc_affirmation import create_affirmation

    uid = _setup(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        create_affirmation(
            uid, level="Level 1", assessment_date=now(), affirming_official="Jane CISO", score=90
        )


def test_requires_affirming_official(tmp_path, monkeypatch):
    from app.db import now
    from app.services.cmmc_affirmation import create_affirmation

    uid = _setup(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        create_affirmation(uid, level="Level 1", assessment_date=now(), affirming_official="  ")


def test_rejects_future_assessment_date(tmp_path, monkeypatch):
    from app.db import now
    from app.services.cmmc_affirmation import create_affirmation

    uid = _setup(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        create_affirmation(
            uid, level="Level 1", assessment_date=now() + 999999, affirming_official="Jane CISO"
        )


def test_level2_due_dates_are_annual_and_3yr(tmp_path, monkeypatch):
    from app.db import now
    from app.services.cmmc_affirmation import DAY, create_affirmation

    uid = _setup(monkeypatch, tmp_path)
    d = now() - 10 * DAY
    rec = create_affirmation(
        uid, level="Level 2", assessment_date=d, affirming_official="Jane CISO", score=88
    )
    assert rec["score"] == 88
    assert abs(rec["next_affirmation_due"] - (d + 365 * DAY)) < 1
    assert abs(rec["next_assessment_due"] - (d + 3 * 365 * DAY)) < 1
    assert rec["affirmation_overdue"] is False
    assert rec["assessment_overdue"] is False


def test_level1_due_dates_are_both_annual(tmp_path, monkeypatch):
    from app.db import now
    from app.services.cmmc_affirmation import DAY, create_affirmation

    uid = _setup(monkeypatch, tmp_path)
    d = now() - 10 * DAY
    rec = create_affirmation(uid, level="Level 1", assessment_date=d, affirming_official="Jane CISO")
    assert rec["score"] is None
    assert abs(rec["next_affirmation_due"] - (d + 365 * DAY)) < 1
    assert abs(rec["next_assessment_due"] - (d + 365 * DAY)) < 1


def test_overdue_flags_when_due_date_in_past(tmp_path, monkeypatch):
    from app.services.cmmc_affirmation import DAY, create_affirmation

    uid = _setup(monkeypatch, tmp_path)
    # An assessment date far enough in the past that both the 1yr and 3yr
    # cycles have already elapsed.
    from app.db import now

    old = now() - (4 * 365 * DAY)
    rec = create_affirmation(uid, level="Level 2", assessment_date=old, affirming_official="Jane CISO", score=50)
    assert rec["affirmation_overdue"] is True
    assert rec["assessment_overdue"] is True


def test_list_and_latest_affirmation(tmp_path, monkeypatch):
    from app.db import now
    from app.services.cmmc_affirmation import create_affirmation, latest_affirmation, list_affirmations

    uid = _setup(monkeypatch, tmp_path)
    create_affirmation(uid, level="Level 2", assessment_date=now() - 200000, affirming_official="A", score=40)
    create_affirmation(uid, level="Level 2", assessment_date=now() - 100, affirming_official="B", score=70)

    rows = list_affirmations(uid, framework_id="cmmc_l2")
    assert len(rows) == 2
    latest = latest_affirmation(uid)
    assert latest["affirming_official"] == "B"
    assert latest["score"] == 70


def test_delete_affirmation(tmp_path, monkeypatch):
    from app.db import now
    from app.services.cmmc_affirmation import create_affirmation, delete_affirmation, get_affirmation

    uid = _setup(monkeypatch, tmp_path)
    rec = create_affirmation(uid, level="Level 1", assessment_date=now(), affirming_official="Jane CISO")
    assert delete_affirmation(uid, rec["id"]) is True
    assert get_affirmation(uid, rec["id"]) is None
    assert delete_affirmation(uid, rec["id"]) is False
