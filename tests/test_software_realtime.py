"""SSE partial refresh payloads."""

from app.software.models import ensure_schema
from app.software.service import installation_snapshots, list_legacy_from_engine


def test_installation_snapshots_empty():
    ensure_schema()
    rows = installation_snapshots("test-sse-empty-user", limit=5)
    assert isinstance(rows, list)


def test_list_legacy_filter_by_product():
    ensure_schema()
    from app.db import get_conn, new_id, now

    uid = "test-sse-product-filter"
    pid = new_id()
    iid = new_id()
    c = get_conn()
    c.execute(
        "INSERT OR IGNORE INTO software_products (id, user_id, name, normalized_name, canonical_id, publisher, vendor, category, package_ecosystem, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (pid, uid, "nginx", "nginx", "nginx.nginx", "", "NGINX", "", "", now(), now()),
    )
    c.execute(
        """
        INSERT OR IGNORE INTO software_installations
        (id, user_id, asset_id, asset_name, software_product_id, version, architecture, install_path, install_date, source, source_id, first_seen, last_seen, status, severity, cve, detail, port, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (iid, uid, "host1", "web-01", pid, "1.18.0", "", "", "", "scan", "s1", now(), now(), "outdated", "high", "", "", None, now()),
    )
    c.commit()
    rows = list_legacy_from_engine(uid, product="nginx", limit=10)
    assert any(r.get("product") == "nginx" for r in rows)
    snap = installation_snapshots(uid, asset_ids=["host1"], limit=5)
    assert isinstance(snap, list)
