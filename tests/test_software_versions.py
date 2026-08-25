"""Version intelligence — resolve, cache, never fabricate."""

from unittest.mock import patch

from app.software.ecosystems import ecosystem_for, upstream_for
from app.software.models import ensure_schema
from app.software.patch_status import compute_patch_status
from app.software.sources.osv import fixed_versions_from_vulns
from app.software.sources.vendor import resolve_upstream_latest
from app.software.versions import (
    get_cached_latest,
    products_needing_refresh,
    refresh_versions_for_user,
    resolve_latest_for_product,
    upsert_version_record,
    version_intelligence_status,
)


def test_upstream_mapping_nginx():
    up = upstream_for("nginx.nginx", "nginx")
    assert up.get("source") == "github"
    assert "nginx" in up.get("repo", "")


def test_upstream_unknown_product():
    assert upstream_for("unknown.widget", "widget-x") == {}


def test_ecosystem_for_wazuh_source():
    assert ecosystem_for("nginx.nginx", "nginx", "wazuh") in {"GitHub", "endpoint", ""}


def test_resolve_latest_returns_none_without_mapping():
    hit = resolve_latest_for_product(canonical_id="custom.unknown.app", name="MyApp")
    assert hit.get("latest") is None
    assert hit.get("source") is None


def test_resolve_latest_github_mocked():
    with patch("app.software.sources.vendor.fetch_latest_github", return_value="1.26.2"):
        hit = resolve_upstream_latest({"source": "github", "repo": "nginx/nginx"})
    assert hit["latest"] == "1.26.2"
    assert hit["source"] == "github"


def test_compute_patch_with_trusted_latest():
    st, target, _ = compute_patch_status(
        installed="1.18.0",
        latest="1.26.0",
        latest_source="github",
        raw_status="outdated",
        severity="high",
    )
    assert st in {"security_update", "critical_security_update"}
    assert target == "1.26.0"


def test_compute_patch_unknown_when_no_latest():
    st, target, reason = compute_patch_status(
        installed="1.18.0",
        latest=None,
        latest_source=None,
        raw_status="unknown",
    )
    assert st == "unknown"
    assert target == ""
    assert "not resolved" in reason.lower()


def test_version_cache_roundtrip():
    ensure_schema()
    uid = "test-version-cache"
    pid = "prod-v1-roundtrip"
    c = __import__("app.db", fromlist=["get_conn"]).get_conn()
    c.execute("DELETE FROM software_versions WHERE user_id=? AND software_product_id=?", (uid, pid))
    c.execute(
        "INSERT OR IGNORE INTO software_products (id, user_id, name, normalized_name, canonical_id, publisher, vendor, category, package_ecosystem, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (pid, uid, "nginx", "nginx", "nginx.nginx", "", "NGINX", "", "", 1.0, 1.0),
    )
    c.commit()
    assert get_cached_latest(uid, pid) is None
    upsert_version_record(uid, pid, version="1.26.0", source="github")
    cached = get_cached_latest(uid, pid)
    assert cached is not None
    assert cached["latest"] == "1.26.0"
    assert cached["source"] == "github"


def test_products_needing_refresh_includes_new():
    ensure_schema()
    rows = products_needing_refresh("test-version-cache", limit=10)
    assert isinstance(rows, list)


def test_refresh_versions_skips_unmapped():
    ensure_schema()
    result = refresh_versions_for_user("test-version-empty-user", limit=5)
    assert "resolved" in result
    assert "skipped" in result


def test_version_intelligence_status_shape():
    ensure_schema()
    st = version_intelligence_status("test-version-status-user")
    assert st["status"] == "ok"
    assert "products_total" in st
    assert "cache_ttl_sec" in st


def test_osv_fixed_versions_extraction():
    vulns = [
        {
            "affected": [
                {
                    "ranges": [
                        {"events": [{"introduced": "0"}, {"fixed": "1.26.0"}]}
                    ]
                }
            ]
        }
    ]
    fixed = fixed_versions_from_vulns(vulns)
    assert "1.26.0" in fixed
