"""Software inventory and patch posture aggregation."""

from app.software_inventory import (
    build_server_posture,
    classify_os,
    classify_product,
    ensure_schema,
    posture_summary,
    rebuild_for_user,
    upsert_software_row,
)


def test_classify_old_apache():
    hit = classify_product("Apache", "2.2.15", banner="Apache/2.2.15")
    assert hit["status"] in {"outdated", "eol"}


def test_classify_current_when_version_no_rule():
    hit = classify_product("nginx", "1.24.0")
    assert hit["status"] == "current"


def test_classify_unknown_without_version():
    hit = classify_product("custom-app", "")
    assert hit["status"] == "unknown"


def test_classify_os_eol_windows_server_2012():
    hit = classify_os("Microsoft Windows Server 2012 R2 Standard")
    assert hit["status"] == "eol"


def test_classify_os_current_windows_server_2022():
    hit = classify_os("Microsoft Windows Server 2022 Datacenter")
    assert hit["status"] == "current"


def test_upsert_and_posture_empty_user():
    ensure_schema()
    upsert_software_row(
        "test-sw-user",
        asset_id="a1",
        asset_name="lab-host",
        product="OpenSSH",
        version="7.4",
        port=22,
        source="scan:test",
    )
    sp = posture_summary("test-sw-user", rebuild_if_empty=False)
    assert sp["total_products"] >= 1
    assert sp["health_score"] >= 0
    assert "server_summary" in sp
    assert "servers" in sp


def test_build_server_posture_rollup():
    rows = [
        {
            "asset_id": "srv1",
            "asset_name": "web-01",
            "product": "Windows Server 2022",
            "version": "",
            "source": "wazuh:agent-os",
            "status": "current",
            "status_label": "Current",
            "severity": "info",
        },
        {
            "asset_id": "srv1",
            "asset_name": "web-01",
            "product": "Apache",
            "version": "2.2.15",
            "source": "scan:nmap",
            "status": "outdated",
            "status_label": "Outdated",
            "severity": "high",
        },
    ]
    sp = build_server_posture("test-sw-user", rows)
    assert sp["summary"]["total"] >= 1
    host = next((s for s in sp["servers"] if s.get("asset_id") == "srv1"), None)
    assert host is not None
    assert host["patch_status"] == "needs_update"


def test_rebuild_covers_all_source_keys():
    ensure_schema()
    counts = rebuild_for_user("test-sw-rebuild")
    for key in ("assets", "services", "xdr", "vulns", "wazuh", "openaudit", "local_tools", "local_os", "control_panel", "remote_os"):
        assert key in counts


def test_sync_all_and_rebuild_shape():
    from app.software_inventory import sync_all_and_rebuild

    ensure_schema()
    out = sync_all_and_rebuild("test-sync-all-user")
    assert "jobs_queued" in out
    assert "rebuilt" in out
    assert "posture" in out
    assert "local_os_patches" in out


def test_export_software_markdown():
    from app.software_inventory import export_software_csv, export_software_markdown

    ensure_schema()
    upsert_software_row(
        "test-export-user",
        asset_id="ex1",
        asset_name="export-host",
        product="nginx",
        version="1.24.0",
        source="scan:test",
    )
    md = export_software_markdown("test-export-user")
    assert "# Software & Patch Inventory" in md
    assert "nginx" in md
    csv = export_software_csv("test-export-user")
    assert "product" in csv.splitlines()[0]
    assert "nginx" in csv


def test_build_remediation_for_server():
    from app.software_inventory import build_remediation_for_server

    ensure_schema()
    upsert_software_row(
        "test-rem-user",
        asset_id="r1",
        asset_name="patch-me",
        product="Apache",
        version="2.2.15",
        source="scan:test",
        status="outdated",
    )
    draft = build_remediation_for_server("test-rem-user", asset_id="r1", asset_name="patch-me")
    assert draft["title"].startswith("Patch server:")
    assert draft["control_id"] == "PATCH"
    assert draft["recommendation"]


def test_posture_summary_rebuild_empty_user():
    """Empty inventory must not 500 when rebuild_if_empty=True (sqlite Row + asset category)."""
    ensure_schema()
    sp = posture_summary("test-empty-rebuild-user", rebuild_if_empty=True)
    assert sp["total_products"] >= 0
    assert "server_summary" in sp


def test_inventory_api_payload_empty():
    from app.software_inventory import empty_posture, inventory_api_payload

    payload = inventory_api_payload("nobody", inventory=[], posture=empty_posture())
    assert payload["status"] == "ok"
    assert payload["total"] == 0
    assert payload["message"]
    assert payload["inventory"] == []


def test_publish_software_realtime(monkeypatch):
    from app.software_inventory import publish_software_realtime

    ensure_schema()
    events: list[dict] = []

    def _capture(**kwargs):
        events.append(kwargs)

    monkeypatch.setattr("app.realtime_bus.publish", _capture)
    upsert_software_row(
        "test-rt-user",
        asset_id="rt1",
        asset_name="rt-host",
        product="nginx",
        version="1.24.0",
        source="scan:test",
    )
    publish_software_realtime("test-rt-user", {"assets": 1})
    assert events
    evt = events[-1]
    assert evt.get("type") == "software_inventory"
    assert evt.get("total_products", 0) >= 1
    assert "health_score" in evt
