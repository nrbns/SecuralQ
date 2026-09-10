"""Normalized software inventory engine."""

from app.software.models import PATCH_UNKNOWN, ensure_schema
from app.software.normalization import normalize_product
from app.software.patch_status import compare_versions, compute_patch_status
from app.software.service import (
    inventory_status,
    legacy_row_from_normalized,
    list_legacy_from_engine,
    sync_inventory,
    summary_for_user,
)
from app.software_inventory import rebuild_for_user, upsert_software_row


def test_normalize_chrome_variants():
    a = normalize_product("Google Chrome", "Google")
    b = normalize_product("chrome", "", "Google")
    assert a["normalized_name"] == b["normalized_name"]
    assert "chrome" in a["canonical_id"].lower()


def test_compare_versions_semantic():
    assert compare_versions("9.10", "9.9") == 1
    assert compare_versions("1.18.0", "1.26.0") == -1
    assert compare_versions("128.0.6613.84", "128.0.6613.84") == 0


def test_compute_patch_status_never_fabricates_latest():
    st, target, reason = compute_patch_status(
        installed="1.18.0",
        latest=None,
        latest_source=None,
        raw_status="outdated",
    )
    assert st == "update_available"
    assert target == ""
    assert "not resolved" in reason.lower() or "outdated" in reason.lower()


def test_compute_patch_status_with_trusted_latest():
    st, target, reason = compute_patch_status(
        installed="1.18.0",
        latest="1.26.0",
        latest_source="vendor",
        raw_status="outdated",
        severity="high",
    )
    assert st in {"security_update", "critical_security_update"}
    assert target == "1.26.0"
    assert "vendor" in reason


def test_sync_inventory_empty_user():
    ensure_schema()
    totals = sync_inventory("test-engine-empty", publish=False)
    assert "products" in totals
    assert "installations" in totals
    assert isinstance(totals["sources"], dict)


def test_sync_inventory_from_legacy_rows(monkeypatch, tmp_path):
    """Legacy asset_software → engine sync without live version-network refresh."""
    from tests._http_test_utils import configure_isolated_settings

    configure_isolated_settings(monkeypatch, tmp_path)
    ensure_schema()
    # Keep this unit hermetic: sync_inventory may call GitHub / reuse cached latest.
    monkeypatch.setattr(
        "app.software.versions.refresh_versions_for_user",
        lambda *_a, **_k: {"checked": 0, "resolved": 0, "skipped": 0, "errors": 0},
    )
    monkeypatch.setattr(
        "app.software.versions.get_cached_latest",
        lambda *_a, **_k: None,
    )
    uid = "test-engine-sync"
    upsert_software_row(
        uid,
        asset_id="eng-a1",
        asset_name="lab-web",
        product="OpenSSL",
        version="1.1.1k",
        source="scan:test",
        status="outdated",
        severity="high",
    )
    totals = sync_inventory(uid, publish=False)
    assert totals["installations"] >= 1
    rows = list_legacy_from_engine(uid, limit=50)
    assert any(r.get("product") == "OpenSSL" for r in rows)
    leg = legacy_row_from_normalized(rows[0])
    assert leg.get("latest_version") is None or leg.get("latest_version") == ""
    assert leg.get("patch_status") != PATCH_UNKNOWN or leg.get("status") in {
        "outdated",
        "missing_patch",
        "unknown",
    }


def test_rebuild_runs_engine_sync():
    ensure_schema()
    counts = rebuild_for_user("test-engine-rebuild")
    assert "engine_installations" in counts
    assert "engine_products" in counts


def test_inventory_status_never_raises():
    ensure_schema()
    st = inventory_status("test-engine-status-none")
    assert st["status"] == "ok"
    assert st["installations"] == 0
    assert isinstance(st["sources"], list)


def test_summary_for_user_shape():
    ensure_schema()
    uid = "test-engine-summary"
    upsert_software_row(
        uid,
        asset_id="s1",
        asset_name="host",
        product="nginx",
        version="1.24.0",
        source="scan:test",
        status="current",
    )
    sync_inventory(uid, publish=False)
    summary = summary_for_user(uid)
    assert summary["status"] == "ok"
    assert "patch_counts" in summary
    assert summary["total_installations"] >= 1
