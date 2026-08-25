"""CVE / KEV advisory matching and patch priority."""

from unittest.mock import patch

from app.software.advisories import (
    advisory_summary,
    compute_patch_with_advisories,
    kev_matches_product,
    load_kev_catalog,
    parse_cve_ids,
    refresh_advisories_for_user,
    upsert_advisory,
)
from app.software.models import PATCH_CRITICAL, PATCH_KEV, PATCH_SECURITY_UPDATE, ensure_schema


def test_parse_cve_ids():
    assert parse_cve_ids("Apache CVE-2021-44228 and CVE-2021-45046") == [
        "CVE-2021-44228",
        "CVE-2021-45046",
    ]


def test_kev_matches_openssl_product():
    item = {"vendor": "OpenSSL", "product": "OpenSSL", "cve": "CVE-2024-TEST"}
    assert kev_matches_product(item, "OpenSSL", "OpenSSL") is True
    assert kev_matches_product(item, "nginx", "F5") is False


def test_compute_patch_kev_priority():
    st, target, reason = compute_patch_with_advisories(
        installed="1.1.1k",
        latest="3.0.0",
        latest_source="github",
        advisories=[{"cve_id": "CVE-2024-0001", "kev": True, "cvss": 8.0}],
    )
    assert st == PATCH_KEV
    assert "KEV" in reason


def test_compute_patch_critical_cvss():
    st, _, reason = compute_patch_with_advisories(
        installed="1.18.0",
        latest=None,
        latest_source=None,
        advisories=[{"cve_id": "CVE-2024-0002", "kev": False, "cvss": 9.8}],
    )
    assert st == PATCH_CRITICAL
    assert "9.8" in reason


def test_compute_patch_security_with_fixed_version():
    st, target, _ = compute_patch_with_advisories(
        installed="1.18.0",
        latest=None,
        latest_source=None,
        advisories=[{"cve_id": "CVE-2020-0001", "kev": False, "cvss": 7.5, "fixed_version": "1.26.0", "source": "osv"}],
    )
    assert st == PATCH_SECURITY_UPDATE
    assert target == "1.26.0"


def test_advisory_upsert_and_summary():
    ensure_schema()
    uid = "test-adv-user"
    pid = "prod-adv-1"
    c = __import__("app.db", fromlist=["get_conn"]).get_conn()
    c.execute(
        "INSERT OR IGNORE INTO software_products (id, user_id, name, normalized_name, canonical_id, publisher, vendor, category, package_ecosystem, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (pid, uid, "OpenSSL", "openssl", "openssl.openssl", "", "OpenSSL", "", "", 1.0, 1.0),
    )
    c.commit()
    upsert_advisory(uid, pid, cve_id="CVE-2024-TEST", severity="CRITICAL", cvss=9.8, kev=True, source="test")
    summary = advisory_summary(uid)
    assert summary["total_advisories"] >= 1
    assert summary["kev"] >= 1


def test_refresh_advisories_empty_user():
    ensure_schema()
    result = refresh_advisories_for_user("test-adv-empty-user", limit=5)
    assert "checked" in result
    assert "advisories_matched" in result


def test_load_kev_catalog_from_cache():
    kev_set, items = load_kev_catalog()
    assert isinstance(kev_set, set)
    assert isinstance(items, list)


def test_refresh_with_mocked_cve_on_installation():
    ensure_schema()
    uid = "test-adv-match"
    from app.db import get_conn, new_id, now

    c = get_conn()
    pid = new_id()
    iid = new_id()
    c.execute(
        "INSERT INTO software_products (id, user_id, name, normalized_name, canonical_id, publisher, vendor, category, package_ecosystem, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (pid, uid, "Apache", "apache", "apache.httpd", "", "Apache", "", "", now(), now()),
    )
    c.execute(
        """
        INSERT INTO software_installations
        (id, user_id, asset_id, asset_name, software_product_id, version, architecture, install_path, install_date, source, source_id, first_seen, last_seen, status, severity, cve, detail, port, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (iid, uid, "a1", "web-01", pid, "2.2.15", "", "", "", "scan", "scan:1", now(), now(), "outdated", "high", "CVE-2017-7679", "Apache httpd", None, now()),
    )
    c.commit()
    with patch("app.software.advisories.fetch_nvd_sync", return_value={"cvss": 9.8, "severity": "CRITICAL", "description": "test"}):
        with patch("app.software.advisories.load_kev_catalog", return_value=({"CVE-2017-7679"}, [])):
            result = refresh_advisories_for_user(uid, limit=10)
    assert result["advisories_matched"] >= 1
