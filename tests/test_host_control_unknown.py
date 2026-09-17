"""Host control UNKNOWN honesty — persist + emit, never invent PASS."""

from __future__ import annotations

import importlib
from pathlib import Path


def _reload(monkeypatch, data_dir, **env):
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("REDIS_URL", "")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)
    db_mod.init_schema()
    return config_mod


def test_host_unknown_persists_and_emits(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path / "data")
    from app.agents import enroll_agent
    from app.controls.results import list_results_for_framework
    from app.services import control_testing as ct

    importlib.reload(ct)

    uid = "u-unknown-host"
    agent = enroll_agent(uid, name="unknown-host-agent")
    aid = agent["agent_id"]

    published: list[dict] = []

    def _capture(**kwargs):
        published.append(dict(kwargs))
        return "evt"

    monkeypatch.setattr("app.realtime_bus.publish", _capture)

    # Empty payload → host_firewall evaluates UNKNOWN (no firewall_status)
    out = ct.evaluate_agent_host_controls(
        uid,
        agent_id=aid,
        payload={"hostname": "lab-pc"},
        only_tests={ct.TEST_HOST_FIREWALL},
    )
    assert out.get("ok") is not False
    results = out.get("results") or []
    assert results, "expected at least one host_firewall result"
    assert (results[0].get("status") or "").lower() == "unknown"

    types = {e.get("type") for e in (out.get("events") or [])}
    assert "control.unknown" in types

    # Mapped CMMC bindings should show UNKNOWN last-result (not PASS)
    primary = ct._HOST_TEST_PRIMARY_CONTROLS.get(ct.TEST_HOST_FIREWALL)
    if primary:
        fid, cid = primary
        rows = list_results_for_framework(uid, fid)
        match = [r for r in rows if str(r.get("control_id") or "") == cid]
        assert match, f"expected stored result for {fid}/{cid}"
        assert str(match[0].get("status") or "").lower() == "unknown"


def test_processor_skips_when_host_side_effects_done(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path / "data")
    from app import event_processor as ep

    importlib.reload(ep)
    called = {"n": 0}

    def _boom(*_a, **_k):
        called["n"] += 1
        raise AssertionError("should not record evidence when host_side_effects_done")

    monkeypatch.setattr(ep, "_safe_record_evidence", _boom)
    ok = ep.process_event(
        {
            "type": "control.failed",
            "event_type": "control.failed",
            "event_id": "skip-dup-1",
            "user_id": "u1",
            "test": "host_firewall",
            "source": "securaiq_agent",
            "evidence_ids": ["ev1"],
            "host_side_effects_done": True,
        }
    )
    assert ok is True
    assert called["n"] == 0
