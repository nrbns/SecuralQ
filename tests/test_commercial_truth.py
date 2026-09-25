"""Commercial truth loop — freshness, offline never PASS, Current vs Target."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_offline_pass_becomes_unknown(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.control_truth import resolve_result_truth
    from app.db import init_schema, now
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    row = {
        "status": "pass",
        "test_name": "host_firewall",
        "tested_at": now(),
        "summary": "firewall on",
        "detail": {},
    }
    online = resolve_result_truth(row, agents_online=True)
    assert online["status"] == "pass"
    assert online["freshness"] == "valid"
    offline = resolve_result_truth(row, agents_online=False)
    assert offline["status"] == "unknown"
    assert "never PASS" in offline["reason"]
    stale = resolve_result_truth(
        {**row, "tested_at": now() - 24 * 3600},
        agents_online=True,
    )
    assert stale["status"] == "expired"
    assert stale["freshness"] == "expired"


def test_profile_and_detail_http(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    from fastapi.testclient import TestClient

    from app.controls.catalog import list_framework_controls
    from app.controls.results import record_test_result
    from app.db import init_schema
    from app.main import app
    from app.nist_profile import organizational_profile, set_org_profile
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    set_org_profile("local", target_percent=88, current_tier=2, target_tier=3)
    prof = organizational_profile("local")
    assert prof["ok"] is True
    assert prof["target_percent"] == 88
    assert prof["tiers"]["current"]["name"] == "Risk Informed"
    assert "not a maturity score" in prof["tiers"]["note"].lower() or "not a maturity" in prof["tiers"]["note"].lower()
    ctrls = list_framework_controls("nist_csf")
    assert ctrls
    cid = ctrls[0].id
    record_test_result("local", "nist_csf", cid, test_name="host_firewall", status="fail", summary="off")
    client = TestClient(app)
    truth = client.get("/api/truth/indicators")
    assert truth.status_code == 200
    assert truth.json()["label"]
    profile = client.get("/api/compliance/profile")
    assert profile.status_code == 200
    assert profile.json()["ok"] is True
    posted = client.post("/api/compliance/profile", json={"target_percent": 91, "target_tier": 4})
    assert posted.status_code == 200
    assert posted.json()["target_percent"] == 91
    assert posted.json()["tiers"]["target"]["name"] == "Adaptive"
    detail = client.get(f"/api/controls/catalog/nist_csf/{cid}/detail")
    assert detail.status_code == 200
    why = client.get(f"/api/controls/why?framework_id=nist_csf&control_id={cid}")
    assert why.status_code == 200
    body = detail.json()
    assert why.json()["status"] == body["status"]
    assert body["ok"] is True
    assert body["status"]
    assert body["verify"]
    pulse = client.get("/api/command-center/pulse")
    assert pulse.status_code == 200
    assert "truth" in pulse.json()
    assert "profile" in pulse.json()
    assert "stage_latency" in pulse.json()
    stages = pulse.json()["stage_latency"] or {}
    assert "disclaimer" in stages
    ingest = stages.get("ingest") or {}
    assert "count" in ingest
    if ingest.get("count"):
        assert ingest.get("p95_ms") is not None
    else:
        assert ingest.get("p95_ms") is None


def test_offline_enrolled_agent_pass_is_not_live_percent(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents import enroll_agent, ensure_schema as ensure_agents
    from app.controls.live_compliance import compute_live_compliance
    from app.controls.results import record_test_result
    from app.db import init_schema
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    ensure_agents()
    uid = "local"
    enroll_agent(uid, name="offline-host")
    record_test_result(
        uid, "cis", "9.1", test_name="host_firewall", status="pass", summary="on"
    )
    snap = compute_live_compliance(uid)
    assert snap["passing"] == 0
    assert snap["unknown"] >= 1
    assert snap["live_percent"] is None


def test_no_agents_pass_still_counts(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.controls.live_compliance import compute_live_compliance
    from app.controls.results import record_test_result
    from app.db import init_schema
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    record_test_result(
        "local", "cis", "9.1", test_name="host_firewall", status="pass", summary="on"
    )
    snap = compute_live_compliance("local")
    assert snap["passing"] >= 1
    assert snap["live_percent"] == 100.0


def test_why_cached_and_summary_truth(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    from fastapi.testclient import TestClient

    from app.control_truth import truth_indicators
    from app.db import init_schema
    from app.gap_analysis import clear_framework_cache, load_framework
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    clear_framework_cache()
    load_framework("cmmc_l2")
    load_framework("cmmc_l2")
    truth = truth_indicators("local")
    assert truth["label"] == "UNKNOWN"
    assert "enrolled" in truth["note"].lower() or "results" in truth["note"].lower()
    client = TestClient(app)
    why = client.get("/api/controls/why?framework_id=cmmc_l2&control_id=RA.L2-3.11.2")
    assert why.status_code == 200
    body = why.json()
    assert body["ok"] is True
    assert body["control_id"]
    assert body["verify"]
    assert body["document"]["class"] == "document"
    assert "not" in body["document"]["disclaimer"].lower()
    assert body["observation"]["class"] == "observation"
    summary = client.get("/api/controls/summary?framework_id=cmmc_l2")
    assert summary.status_code == 200
    assert summary.json()["truth"]["label"]
    complete = client.get("/api/launch/complete")
    assert complete.status_code == 200
    assert "stage_latency" in (complete.json().get("measured_ops") or {})


def test_availability_skips_list_agents(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents import enroll_agent, ensure_schema as ensure_agents
    from app.control_truth import agent_availability
    from app.db import init_schema
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    ensure_agents()
    enroll_agent("local", name="avail-host")
    monkeypatch.setattr(
        "app.agents.list_agents",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("list_agents must not run")),
    )
    avail = agent_availability("local")
    assert avail["agents"] >= 1
    assert avail["any_online"] is False
