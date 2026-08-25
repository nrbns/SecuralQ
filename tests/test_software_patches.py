"""Patch APIs and remediation/verify workflow."""

from app.db import get_conn, new_id, now
from app.software.models import ensure_schema
from app.software.patches import (
    asset_software_detail,
    build_remediation_for_installation,
    get_patch_detail,
    list_patches,
    product_detail,
    verify_patch,
)
from app.software.service import legacy_row_from_normalized, list_normalized_rows


def test_list_patches_empty():
    ensure_schema()
    rows = list_patches("test-patches-empty")
    assert isinstance(rows, list)


def test_product_detail_unknown():
    ensure_schema()
    detail = product_detail("test-patches-empty", key="nonexistent.product.xyz")
    assert detail["product"] is None


def test_asset_software_detail():
    ensure_schema()
    detail = asset_software_detail("test-patches-empty", "no-such-asset")
    assert detail["total"] == 0


def test_build_remediation_for_missing():
    draft = build_remediation_for_installation("test-patches-empty", "missing-id")
    assert draft["control_id"] == "PATCH"
    assert draft["title"]


def test_patch_detail_and_verify_flow():
    ensure_schema()
    uid = "test-patch-flow"
    pid = new_id()
    iid = new_id()
    c = get_conn()
    ts = now()
    c.execute(
        "INSERT INTO software_products (id, user_id, name, normalized_name, canonical_id, publisher, vendor, category, package_ecosystem, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (pid, uid, "nginx", "nginx", "nginx.nginx", "", "NGINX", "", "", ts, ts),
    )
    c.execute(
        """
        INSERT INTO software_installations
        (id, user_id, asset_id, asset_name, software_product_id, version, architecture, install_path, install_date, source, source_id, first_seen, last_seen, status, severity, cve, detail, port, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (iid, uid, "host1", "web-01", pid, "1.18.0", "", "", "", "scan", "s1", ts, ts, "outdated", "high", "CVE-TEST", "", None, ts),
    )
    c.execute(
        """
        INSERT INTO patch_status
        (id, user_id, asset_id, software_installation_id, current_version, target_version, status, reason, version_source, checked_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (new_id(), uid, "host1", iid, "1.18.0", "1.26.0", "security_update", "Below latest", "github", ts),
    )
    c.commit()
    detail = get_patch_detail(uid, iid)
    assert detail and detail.get("patch")
    assert detail["patch"]["product"] == "nginx"
    draft = build_remediation_for_installation(uid, iid)
    assert "nginx" in draft["title"].lower()
    asset = asset_software_detail(uid, "host1")
    assert asset["total"] >= 1
    prod = product_detail(uid, key="nginx.nginx")
    assert prod.get("product")
