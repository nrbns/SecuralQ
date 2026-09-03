"""Tests for app.services.evidence -- the shared "why" layer other modules
write real observations to. Every record must carry a real source
(declared/derived/inferred/observed), and `verified` must never drift from
what actually backs the record: True by default only for source="declared"
(a human said so), everything else starts False and only flips via an
explicit confirm_evidence() call.
"""

from __future__ import annotations

import pytest

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="evidence_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def test_record_evidence_rejects_unknown_source(tmp_path, monkeypatch):
    from app.services.evidence import record_evidence

    uid = _setup(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        record_evidence(uid, entity_type="threat", entity_id="t1", source="fabricated", summary="x")


def test_record_evidence_requires_entity_reference(tmp_path, monkeypatch):
    from app.services.evidence import record_evidence

    uid = _setup(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        record_evidence(uid, entity_type="", entity_id="", source="derived", summary="x")


def test_declared_evidence_defaults_verified_true(tmp_path, monkeypatch):
    from app.services.evidence import record_evidence

    uid = _setup(monkeypatch, tmp_path)
    ev = record_evidence(uid, entity_type="asset_dependency", entity_id="d1", source="declared", summary="human declared")
    assert ev["verified"] is True
    assert ev["source"] == "declared"


@pytest.mark.parametrize("source", ["derived", "inferred", "observed"])
def test_non_declared_evidence_defaults_verified_false(tmp_path, monkeypatch, source):
    """A guess or a live signal is never verified just because it exists --
    only an explicit human confirmation (or a declared source) makes it
    verified. High confidence must not silently imply verified."""
    from app.services.evidence import record_evidence

    uid = _setup(monkeypatch, tmp_path)
    ev = record_evidence(uid, entity_type="threat", entity_id="t1", source=source, summary="signal", confidence=0.95)
    assert ev["verified"] is False


def test_confirm_evidence_flips_verified_and_is_explicit(tmp_path, monkeypatch):
    from app.services.evidence import confirm_evidence, record_evidence

    uid = _setup(monkeypatch, tmp_path)
    ev = record_evidence(uid, entity_type="threat", entity_id="t1", source="observed", summary="signal")
    assert ev["verified"] is False

    confirmed = confirm_evidence(uid, ev["id"], confirmed_by=uid)
    assert confirmed["verified"] is True


def test_confirm_evidence_unknown_id_returns_none(tmp_path, monkeypatch):
    from app.services.evidence import confirm_evidence

    uid = _setup(monkeypatch, tmp_path)
    assert confirm_evidence(uid, "does-not-exist", confirmed_by=uid) is None


def test_repeated_observation_dedupes_via_fingerprint(tmp_path, monkeypatch):
    """The same (entity, source, summary) recorded twice is the same fact
    re-observed -- it must bump hit_count/last_seen, not create a second row."""
    from app.services.evidence import get_evidence_for, record_evidence

    uid = _setup(monkeypatch, tmp_path)
    first = record_evidence(uid, entity_type="threat", entity_id="t1", source="observed", summary="recurring signal")
    second = record_evidence(uid, entity_type="threat", entity_id="t1", source="observed", summary="recurring signal")
    assert first["id"] == second["id"]
    assert second["hit_count"] == 2

    trail = get_evidence_for(uid, entity_type="threat", entity_id="t1")
    assert len(trail) == 1


def test_different_summary_creates_a_distinct_record(tmp_path, monkeypatch):
    from app.services.evidence import get_evidence_for, record_evidence

    uid = _setup(monkeypatch, tmp_path)
    record_evidence(uid, entity_type="threat", entity_id="t1", source="observed", summary="signal A")
    record_evidence(uid, entity_type="threat", entity_id="t1", source="observed", summary="signal B")

    trail = get_evidence_for(uid, entity_type="threat", entity_id="t1")
    assert len(trail) == 2


def test_get_evidence_for_scoped_to_entity(tmp_path, monkeypatch):
    from app.services.evidence import get_evidence_for, record_evidence

    uid = _setup(monkeypatch, tmp_path)
    record_evidence(uid, entity_type="threat", entity_id="t1", source="observed", summary="for t1")
    record_evidence(uid, entity_type="threat", entity_id="t2", source="observed", summary="for t2")

    assert len(get_evidence_for(uid, entity_type="threat", entity_id="t1")) == 1
    assert len(get_evidence_for(uid, entity_type="threat", entity_id="t2")) == 1


def test_list_evidence_filters_by_source_and_verified(tmp_path, monkeypatch):
    from app.services.evidence import confirm_evidence, list_evidence, record_evidence

    uid = _setup(monkeypatch, tmp_path)
    d = record_evidence(uid, entity_type="asset_dependency", entity_id="d1", source="declared", summary="declared one")
    o = record_evidence(uid, entity_type="threat", entity_id="t1", source="observed", summary="observed one")
    confirm_evidence(uid, o["id"], confirmed_by=uid)

    declared_only = list_evidence(uid, source="declared")
    assert len(declared_only) == 1
    assert declared_only[0]["id"] == d["id"]

    verified_only = list_evidence(uid, verified=True)
    ids = {e["id"] for e in verified_only}
    assert d["id"] in ids
    assert o["id"] in ids  # confirmed, so now also verified

    unverified_only = list_evidence(uid, verified=False)
    assert unverified_only == []


def test_evidence_scoped_to_owning_user(tmp_path, monkeypatch):
    from app.services.evidence import get_evidence_for, record_evidence

    uid_a = _setup(monkeypatch, tmp_path, username="evidence_owner_a")
    from app.auth import login, register_user

    register_user("evidence_owner_b", "password123", role="admin")
    uid_b, _token = login("evidence_owner_b", "password123")
    uid_b = uid_b.id

    record_evidence(uid_a, entity_type="threat", entity_id="shared-id", source="observed", summary="a's evidence")

    assert len(get_evidence_for(uid_a, entity_type="threat", entity_id="shared-id")) == 1
    assert len(get_evidence_for(uid_b, entity_type="threat", entity_id="shared-id")) == 0


def test_detail_round_trips_as_dict(tmp_path, monkeypatch):
    from app.services.evidence import record_evidence

    uid = _setup(monkeypatch, tmp_path)
    ev = record_evidence(
        uid, entity_type="remediation_plan", entity_id="p1", source="derived", summary="band basis",
        detail={"disruption_band": "medium", "assets_affected": 3},
    )
    assert ev["detail"]["disruption_band"] == "medium"
    assert ev["detail"]["assets_affected"] == 3


# --- real integration points: confirmed connections, threats, remediation --


def test_confirming_asset_dependency_records_declared_evidence(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_asset_dependency
    from app.services.evidence import get_evidence_for

    uid = _setup(monkeypatch, tmp_path)
    a = create_asset(uid, "WEB-01", asset_type="web")
    b = create_asset(uid, "DB-01", asset_type="database")

    dep = create_asset_dependency(uid, a["id"], b["id"], source="declared", confidence=1.0)
    trail = get_evidence_for(uid, entity_type="asset_dependency", entity_id=dep["id"])
    assert len(trail) == 1
    assert trail[0]["source"] == "declared"
    assert trail[0]["verified"] is True


def test_inferred_asset_dependency_records_unverified_evidence(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_asset_dependency
    from app.services.evidence import get_evidence_for

    uid = _setup(monkeypatch, tmp_path)
    a = create_asset(uid, "WEB-02", asset_type="web")
    b = create_asset(uid, "DB-02", asset_type="database")

    dep = create_asset_dependency(uid, a["id"], b["id"], source="inferred", confidence=0.3)
    trail = get_evidence_for(uid, entity_type="asset_dependency", entity_id=dep["id"])
    assert len(trail) == 1
    assert trail[0]["source"] == "inferred"
    assert trail[0]["verified"] is False


def test_threat_detection_records_observed_evidence(tmp_path, monkeypatch):
    from app.agents import enroll_agent, record_threat_detections
    from app.services.evidence import list_evidence

    uid = _setup(monkeypatch, tmp_path)
    agent = enroll_agent(uid, name="evidence-agent")
    result = record_threat_detections(
        agent["agent_id"],
        [{"severity": "high", "category": "behavioral", "title": "Suspicious PowerShell", "detail": "encoded command"}],
    )
    threat_id = result["detections"][0]["id"]

    trail = list_evidence(uid, entity_type="threat")
    assert len(trail) == 1
    assert trail[0]["entity_id"] == threat_id
    assert trail[0]["source"] == "observed"
    assert trail[0]["created_by"] == f"agent:{agent['agent_id']}"


def test_remediation_plan_creation_records_derived_evidence(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_vulnerability
    from app.services.evidence import get_evidence_for
    from app.services.remediation import create_plan

    uid = _setup(monkeypatch, tmp_path)
    a = create_asset(uid, "WEB-03", asset_type="web", business_criticality="critical")
    create_vulnerability(
        uid,
        {"asset_id": a["id"], "asset_name": "WEB-03", "title": "Apache RCE", "cve": "CVE-2024-7777", "severity": "critical", "cvss": 9.8, "status": "open"},
    )

    plan = create_plan(uid, "cve:CVE-2024-7777")
    trail = get_evidence_for(uid, entity_type="remediation_plan", entity_id=plan["id"])
    assert len(trail) == 1
    assert trail[0]["source"] == "derived"
    assert "disruption_band" in trail[0]["detail"]
