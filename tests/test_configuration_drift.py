"""Configuration observe / drift foundations (Sprint 2).

Firewall off → on must detect history drift; baseline compare marks disabled firewall as fail.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_extract_firewall_and_drift_off_to_on(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.configuration.baselines import default_baseline_id
    from app.configuration.drift import compare_to_baseline, drifts_vs_baseline
    from app.configuration.observe import extract_observed_config

    off = extract_observed_config(
        {"firewall_status": {"collected": True, "enabled": False, "backend": "ufw"}}
    )
    assert off["firewall.enabled"]["value"] is False
    fails = compare_to_baseline(off, baseline_id=default_baseline_id())
    assert any(d["key"] == "firewall.enabled" and d["status"] == "fail" for d in fails)

    on = extract_observed_config(
        {"firewall_status": {"collected": True, "enabled": True, "backend": "ufw"}}
    )
    assert on["firewall.enabled"]["value"] is True
    ok = compare_to_baseline(on, baseline_id=default_baseline_id())
    assert not any(d["key"] == "firewall.enabled" for d in ok)

    # History-style: previous False → current True matches baseline → no baseline fail
    hist = drifts_vs_baseline(
        on,
        previous_values={"firewall.enabled": False},
        agent_id="a1",
    )
    assert hist == [] or all(d.get("current") is True for d in hist)


def test_record_checkin_observations_detects_firewall_off_to_on(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.configuration import observe as obs

    published: list[dict] = []

    def _pub(*args, **kwargs):
        if args and isinstance(args[0], dict):
            published.append(dict(args[0], **kwargs))
        else:
            published.append(dict(kwargs))

    monkeypatch.setattr("app.realtime_bus.publish", _pub)
    obs._SCHEMA_READY = False
    obs.ensure_observations_schema()

    uid = "local-cfg-test"
    aid = "agent-cfg-1"
    r1 = obs.record_checkin_observations(
        uid,
        aid,
        {"firewall_status": {"collected": True, "enabled": False, "backend": "ufw"}},
        asset_id="asset-1",
    )
    assert "firewall.enabled" in r1["observed_keys"]
    assert not r1.get("drift_events")  # first observation — no previous

    r2 = obs.record_checkin_observations(
        uid,
        aid,
        {"firewall_status": {"collected": True, "enabled": True, "backend": "ufw"}},
        asset_id="asset-1",
    )
    assert any(row.get("changed") for row in (r2.get("recorded") or []))
    assert r2.get("drift_events"), "off→on must emit a drift/history-change event"
    assert any(
        e.get("event_type") == "configuration.drift_detected"
        or e.get("type") in {"configuration", "compliance", "configuration.drift_detected"}
        for e in published
    ) or r2.get("published")
