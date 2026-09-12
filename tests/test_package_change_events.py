"""Package diff → software.installed/removed/updated + evidence."""

from __future__ import annotations

from app.software.sources.securaiq_agent import diff_package_sets, publish_package_change_events
from app.event_schema import is_registered_event_type
from tests._http_test_utils import configure_isolated_settings


def test_diff_package_sets_install_remove_update():
    prev = [
        {"name": "curl", "version": "7.0"},
        {"name": "openssl", "version": "3.0"},
    ]
    cur = [
        {"name": "curl", "version": "8.0"},
        {"name": "wget", "version": "1.0"},
    ]
    d = diff_package_sets(prev, cur)
    assert [p["name"] for p in d["installed"]] == ["wget"]
    assert [p["name"] for p in d["removed"]] == ["openssl"]
    assert len(d["updated"]) == 1
    assert d["updated"][0]["name"] == "curl"
    assert d["updated"][0]["previous_version"] == "7.0"
    assert d["updated"][0]["version"] == "8.0"


def test_package_event_types_registered():
    assert is_registered_event_type("software.installed")
    assert is_registered_event_type("software.removed")
    assert is_registered_event_type("software.updated")


def test_publish_package_change_events_writes_evidence(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema
    from app.services.evidence import get_evidence_for
    from app.realtime_bus import clear_replay_buffer_for_tests

    ensure_tenant_schema()
    register_user("pkg_ev", "password123", role="admin")
    u, _ = login("pkg_ev", "password123")
    clear_replay_buffer_for_tests()
    agent = {"id": "agent-pkg-1", "asset_id": "asset-1", "hostname": "lab-pc", "org_id": None}
    diffs = {
        "installed": [{"name": "curl", "version": "8.0"}],
        "removed": [{"name": "legacy", "version": "1.0"}],
        "updated": [{"name": "openssl", "version": "3.1", "previous_version": "3.0"}],
    }
    counts = publish_package_change_events(u.id, agent, diffs)
    assert counts["installed"] == 1
    assert counts["removed"] == 1
    assert counts["updated"] == 1
    assert counts["evidence"] >= 3
    trail = get_evidence_for(u.id, entity_type="software_package", entity_id="agent-pkg-1:curl")
    assert trail
    assert trail[0]["source"] == "observed"
    assert trail[0].get("freshness_status") in ("fresh", "stale", "expired")
