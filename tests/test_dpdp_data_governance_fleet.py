"""Data governance foundations + fleet aggregator / partitioner."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_data_governance_inventory_and_posture(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.data_governance import (
        family_posture,
        set_org_privacy_profile,
        upsert_data_element,
        upsert_processor,
        upsert_retention_policy,
    )

    set_org_privacy_profile("u1", sdf_status="unknown", jurisdiction="IN")
    upsert_data_element(
        "u1",
        {
            "name": "Email",
            "classification": "personal_data",
            "purpose": "Account management",
            "storage_system": "PostgreSQL",
        },
    )
    upsert_processor(
        "u1",
        {
            "name": "CRM",
            "contract_ref": "MSA-1",
            "security_requirements": "encryption + access control",
        },
    )
    upsert_retention_policy("u1", {"name": "Account email", "retention_days": 365})
    posture = family_posture("u1")
    assert posture["ok"] is True
    assert posture["counts"]["data_elements"] == 1
    assert posture["sdf_status"] == "unknown"
    assert "legal" in (posture.get("legal_disclaimer") or "").lower() or "not a legal" in (
        posture.get("legal_disclaimer") or ""
    ).lower()
    assert posture["assessment_kind"] == "inventory_completeness"
    assert posture["overall_percent"] >= 0


def test_data_governance_http_roundtrip(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.data_governance_api import router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("dg_admin", "password123", role="admin")
    _u, token = login("dg_admin", "password123")
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}

    res = client.put(
        "/api/data-governance/profile",
        headers=headers,
        json={"sdf_status": "not_applicable", "jurisdiction": "IN"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["sdf_status"] == "not_applicable"

    res = client.post(
        "/api/data-governance/elements",
        headers=headers,
        json={"name": "Phone", "classification": "personal_data", "storage_system": "CRM"},
    )
    assert res.status_code == 200, res.text

    res = client.get("/api/data-governance/data-map", headers=headers)
    assert res.status_code == 200
    assert len(res.json()["elements"]) >= 1

    res = client.get("/api/data-governance/posture", headers=headers)
    assert res.status_code == 200
    assert "overall_percent" in res.json()


def test_fleet_aggregator_publishes_summary_not_per_agent(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.realtime.fleet_aggregator import (
        fleet_summary,
        record_agent_observation,
        reset_fleet_state_for_tests,
    )

    reset_fleet_state_for_tests()
    pubs: list[dict] = []
    monkeypatch.setattr(
        "app.realtime_bus.publish",
        lambda **kw: pubs.append(kw),
    )
    for i in range(50):
        record_agent_observation("u-fleet", f"a{i}", status="online", publish=True)
    record_agent_observation("u-fleet", "a0", status="offline", publish=True)
    summary = fleet_summary("u-fleet")
    assert summary["total"] == 50
    assert summary["offline"] >= 1
    assert any(p.get("type") == "fleet.health.changed" for p in pubs)
    # Must not publish 50 individual heartbeat events from the aggregator
    assert sum(1 for p in pubs if p.get("type") == "fleet.health.changed") >= 1
    assert sum(1 for p in pubs if "heartbeat" in str(p.get("type") or "")) == 0


def test_dpdp_overview_and_privacy_events(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.data_governance import dpdp_overview, upsert_data_element
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    pubs: list[dict] = []
    monkeypatch.setattr("app.realtime_bus.publish", lambda **kw: pubs.append(kw))
    from app.gap_analysis import ensure_gap_schema

    ensure_gap_schema()
    upsert_data_element("u-ov", {"name": "Email", "classification": "personal_data"})
    ov = dpdp_overview("u-ov", as_of="2025-11-13")
    assert ov["ok"] is True
    assert ov["family"] == "India DPDP"
    assert ov["commencement"]["not_yet_in_force"] > 0
    assert "data_map" in ov
    assert any(p.get("type") == "privacy.inventory.changed" for p in pubs)


def test_event_registry_and_workload_streams_noop():
    from app.realtime.event_registry import event_catalog, is_fleet_aggregate, is_high_volume
    from app.realtime.workload_streams import configured_workloads, ensure_workload_streams

    cat = event_catalog()
    assert "fleet.health.changed" in cat["fleet_aggregates"]
    assert is_fleet_aggregate("fleet.health.changed")
    assert is_high_volume("agent.heartbeat")
    assert "telemetry" in configured_workloads()
    out = ensure_workload_streams(partitions=0)
    assert out.get("ok") is True


def test_privacy_recompute_maps_to_inventory_only():
    from app.controls.recompute import tests_for_event_type

    assert tests_for_event_type("privacy.inventory.changed") == ("asset_inventory",)
    assert tests_for_event_type("privacy.processor.changed") == ("asset_inventory",)


def test_partitioner_stable():
    from app.realtime.partitioner import claimable_partitions, partition_id, workload_stream_key

    a = partition_id("org1", "agent-9", partitions=16)
    b = partition_id("org1", "agent-9", partitions=16)
    assert a == b
    assert 0 <= a < 16
    assert workload_stream_key("telemetry", 3) == "securaiq:telemetry:p3"
    owned = claimable_partitions(0, 4, partitions=16)
    assert owned == [0, 4, 8, 12]
