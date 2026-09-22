"""USP lab-production closes: graph depth, risk narrative, SBOM, vendors, scanners."""

from __future__ import annotations

import json

from tests._http_test_utils import configure_isolated_settings


def test_graph_identity_depth(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.commercial_ext import create_org
    from app.enterprise import create_asset
    from app.knowledge_graph import build_knowledge_graph
    from app.security_graph_depth import graph_depth_status
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("g_user", "password123", role="admin")
    user, _ = login("g_user", "password123")
    create_org(user.id, "GraphOrg")
    create_asset(user.id, "db-1", asset_type="database")
    create_asset(user.id, "web-1", asset_type="web", notes=json.dumps({"cloud_provider": "aws"}))
    g = build_knowledge_graph(user.id)
    by = (g.get("counts") or {}).get("by_type") or {}
    assert g.get("identity_depth", {}).get("lab_production") is True
    assert int(by.get("user") or 0) >= 1 or int(by.get("data_store") or 0) >= 1
    st = graph_depth_status(user.id)
    assert st["lab_production"] is True
    assert st["full_twin"] is False


def test_risk_why_increased_narrative(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.services.risk_narrative import explain_risk_increase
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("r_narr", "password123", role="admin")
    user, _ = login("r_narr", "password123")
    out = explain_risk_increase(user.id)
    assert out["ok"] is True
    assert out["lab_production"] is True
    assert out["narrative"]
    assert out["llm_product_gate"] is False


def test_sbom_branded_export(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.sbom import build_cyclonedx, sbom_status
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("sbom_u", "password123", role="admin")
    user, _ = login("sbom_u", "password123")
    st = sbom_status(user.id)
    assert st["product"] == "SecuraIQ SBOM"
    assert st["lab_production"] is True
    bom = build_cyclonedx(user.id)
    assert bom["bomFormat"] == "CycloneDX"
    assert "components" in bom


def test_vendor_ingest_export(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.connectors.vendor_ingest import catalog_status, ingest_vendor_export, vendor_status
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("vend_u", "password123", role="admin")
    user, _ = login("vend_u", "password123")
    cat = catalog_status()
    assert cat["lab_production"] is True
    assert len(cat["vendors"]) == 7
    assert vendor_status("wiz")["configured"] is False
    assert vendor_status("wiz")["export_ingest"] is True
    out = ingest_vendor_export(
        user.id,
        "tenable",
        {
            "findings": [
                {
                    "title": "TLS weak cipher",
                    "severity": "high",
                    "cve": "CVE-2024-0001",
                    "asset": "host-a",
                }
            ]
        },
        filename="tenable.json",
    )
    assert out["ok"] is True
    assert out["created"] >= 1


def test_product_scanners_branded(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.scanners.product_facades import catalog, product_status

    cat = catalog()
    assert cat["lab_production"] is True
    assert len(cat["products"]) == 3
    secret = product_status("secret_scanner")
    assert secret["name"] == "SecuraIQ Secret Scanner"
    assert secret["ready"] is True
    api = product_status("api_scanner")
    assert "API Scanner" in api["name"]
    cfg = product_status("config_scanner")
    assert "Config Scanner" in cfg["name"]
