"""Unit tests for app.services.attack_graph — the "why is this asset
actually dangerous" layer built on top of the risk engine.

Function-level (not HTTP) since these exercise graph construction and path
computation directly, following the pattern in tests/test_risk_scoring.py.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="graph_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user, login
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def _seed_software(user_id, asset_id, *, product_name, version, cve_id="", fixed_version=""):
    from app.db import get_conn, new_id, now
    from app.software.models import ensure_schema as ensure_software_schema

    ensure_software_schema()
    c = get_conn()
    ts = now()
    product_id = new_id()
    c.execute(
        "INSERT INTO software_products (id, user_id, name, normalized_name, canonical_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
        (product_id, user_id, product_name, product_name.lower(), product_name.lower(), ts, ts),
    )
    c.execute(
        "INSERT INTO software_installations (id, user_id, asset_id, asset_name, software_product_id, version, first_seen, last_seen, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (new_id(), user_id, asset_id, "seeded", product_id, version, ts, ts, ts),
    )
    if cve_id:
        c.execute(
            "INSERT INTO software_advisories (id, user_id, software_product_id, cve_id, fixed_version, severity, updated_at) VALUES (?,?,?,?,?,?,?)",
            (new_id(), user_id, product_id, cve_id, fixed_version, "high", ts),
        )
    c.commit()
    return product_id


# --- build_graph --------------------------------------------------------


def test_build_graph_empty_when_no_assets(tmp_path, monkeypatch):
    from app.services.attack_graph import build_graph

    uid = _setup(monkeypatch, tmp_path)
    graph = build_graph(uid)
    assert graph["total_assets"] == 0
    assert [n for n in graph["nodes"] if n["type"] != "internet"] == []
    assert graph["edges"] == []


def test_build_graph_tags_web_asset_as_application_and_exposes_it(tmp_path, monkeypatch):
    from app.enterprise import create_asset
    from app.services.attack_graph import build_graph

    uid = _setup(monkeypatch, tmp_path)
    create_asset(uid, "WEB-01", asset_type="web", criticality="medium")

    graph = build_graph(uid)
    web_node = next(n for n in graph["nodes"] if n["type"] == "application")
    assert web_node["label"] == "WEB-01"
    assert web_node["exposed"] is True
    assert any(e["type"] == "exposed_to" and e["to"] == web_node["id"] for e in graph["edges"])


def test_build_graph_internal_server_not_exposed(tmp_path, monkeypatch):
    from app.enterprise import create_asset
    from app.services.attack_graph import build_graph

    uid = _setup(monkeypatch, tmp_path)
    create_asset(uid, "INTERNAL-01", asset_type="server", criticality="low")

    graph = build_graph(uid)
    server_node = next(n for n in graph["nodes"] if n["type"] == "asset")
    assert server_node["exposed"] is False
    assert not any(e["type"] == "exposed_to" for e in graph["edges"])


def test_build_graph_domain_asset_type_normalizes_to_exposed(tmp_path, monkeypatch):
    """Regression check for the asset_categories fix: "domain" now aliases
    to "web" so it's correctly flagged as internet-exposed."""
    from app.enterprise import create_asset
    from app.services.attack_graph import build_graph

    uid = _setup(monkeypatch, tmp_path)
    create_asset(uid, "shop.example.com", asset_type="domain")

    graph = build_graph(uid)
    node = next(n for n in graph["nodes"] if n["type"] in ("asset", "application"))
    assert node["exposed"] is True


def test_build_graph_vulnerability_attaches_to_software_when_advisory_matches(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_vulnerability
    from app.services.attack_graph import build_graph

    uid = _setup(monkeypatch, tmp_path)
    web = create_asset(uid, "WEB-01", asset_type="web")
    _seed_software(uid, web["id"], product_name="apache", version="2.4.49", cve_id="CVE-2024-1111", fixed_version="2.4.51")
    create_vulnerability(uid, {"asset_id": web["id"], "asset_name": "WEB-01", "title": "Apache RCE", "cve": "CVE-2024-1111", "severity": "critical", "cvss": 9.8, "status": "open"})

    graph = build_graph(uid)
    sw_node = next(n for n in graph["nodes"] if n["type"] == "software")
    vuln_node = next(n for n in graph["nodes"] if n["type"] == "vulnerability")
    assert vuln_node["cve"] == "CVE-2024-1111"
    assert any(e["type"] == "affected_by" and e["from"] == sw_node["id"] and e["to"] == vuln_node["id"] for e in graph["edges"])
    # must NOT also attach directly to the asset when a software match exists
    assert not any(e["type"] == "affected_by" and e["from"] == web["id"] for e in graph["edges"])


def test_build_graph_vulnerability_attaches_to_asset_when_no_software_match(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_vulnerability
    from app.services.attack_graph import build_graph

    uid = _setup(monkeypatch, tmp_path)
    web = create_asset(uid, "WEB-02", asset_type="web")
    create_vulnerability(uid, {"asset_id": web["id"], "asset_name": "WEB-02", "title": "Scanner finding, no CPE", "severity": "high", "cvss": 7.0, "status": "open"})

    graph = build_graph(uid)
    vuln_node = next(n for n in graph["nodes"] if n["type"] == "vulnerability")
    assert any(e["type"] == "affected_by" and e["from"] == web["id"] and e["to"] == vuln_node["id"] for e in graph["edges"])


def test_build_graph_identity_nodes_only_when_service_accounts_set(tmp_path, monkeypatch):
    from app.enterprise import create_asset
    from app.services.attack_graph import build_graph

    uid = _setup(monkeypatch, tmp_path)
    create_asset(uid, "no-accounts-host")
    create_asset(uid, "with-accounts-host", service_accounts="svc-web-prod, deploy-bot")

    graph = build_graph(uid)
    identity_nodes = [n for n in graph["nodes"] if n["type"] == "identity"]
    assert len(identity_nodes) == 2
    labels = {n["label"] for n in identity_nodes}
    assert labels == {"svc-web-prod", "deploy-bot"}
    assert all(n["source"] == "declared" and n["confidence"] == "unverified" for n in identity_nodes)


def test_build_graph_declared_dependency_edge(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_asset_dependency
    from app.services.attack_graph import build_graph

    uid = _setup(monkeypatch, tmp_path)
    web = create_asset(uid, "WEB-01", asset_type="web")
    db = create_asset(uid, "DB-01", asset_type="database")
    create_asset_dependency(uid, web["id"], db["id"])

    graph = build_graph(uid)
    edge = next(e for e in graph["edges"] if e["type"] == "connects_to")
    assert edge["from"] == web["id"] and edge["to"] == db["id"]
    assert edge["source"] == "declared"
    assert edge["confidence"] == 1.0


def test_build_graph_infers_dependency_for_exposed_and_database_pair(tmp_path, monkeypatch):
    from app.enterprise import create_asset
    from app.services.attack_graph import build_graph

    uid = _setup(monkeypatch, tmp_path)
    web = create_asset(uid, "WEB-01", asset_type="web")
    db = create_asset(uid, "DB-01", asset_type="database")

    graph = build_graph(uid)
    edge = next(e for e in graph["edges"] if e["type"] == "connects_to")
    assert edge["from"] == web["id"] and edge["to"] == db["id"]
    assert edge["source"] == "inferred"
    assert 0 < edge["confidence"] < 1.0


def test_build_graph_declared_edge_suppresses_inferred_for_same_pair(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_asset_dependency
    from app.services.attack_graph import build_graph

    uid = _setup(monkeypatch, tmp_path)
    web = create_asset(uid, "WEB-01", asset_type="web")
    db = create_asset(uid, "DB-01", asset_type="database")
    create_asset_dependency(uid, web["id"], db["id"])

    graph = build_graph(uid)
    connects_edges = [e for e in graph["edges"] if e["type"] == "connects_to" and e["from"] == web["id"] and e["to"] == db["id"]]
    assert len(connects_edges) == 1
    assert connects_edges[0]["source"] == "declared"


def test_build_graph_no_dependencies_between_unrelated_assets(tmp_path, monkeypatch):
    """No inference between two exposed assets, or two databases — only
    exposed<->database pairs get an inferred guess."""
    from app.enterprise import create_asset
    from app.services.attack_graph import build_graph

    uid = _setup(monkeypatch, tmp_path)
    create_asset(uid, "WEB-01", asset_type="web")
    create_asset(uid, "WEB-02", asset_type="web")
    create_asset(uid, "DB-01", asset_type="database")
    create_asset(uid, "DB-02", asset_type="database")

    graph = build_graph(uid)
    connects_edges = [e for e in graph["edges"] if e["type"] == "connects_to"]
    # exactly the 2x2 exposed-x-database cross product, nothing else
    assert len(connects_edges) == 4
    assert all(e["source"] == "inferred" for e in connects_edges)


# --- compute_attack_paths ------------------------------------------------


def test_compute_attack_paths_empty_when_no_exposure(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_vulnerability
    from app.services.attack_graph import compute_attack_paths

    uid = _setup(monkeypatch, tmp_path)
    internal = create_asset(uid, "INTERNAL-01", asset_type="server")
    create_vulnerability(uid, {"asset_id": internal["id"], "asset_name": "INTERNAL-01", "title": "Old openssh", "severity": "high", "cvss": 7.0, "status": "open"})

    result = compute_attack_paths(uid)
    assert result["total_paths"] == 0


def test_compute_attack_paths_direct_hop(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_vulnerability
    from app.services.attack_graph import compute_attack_paths

    uid = _setup(monkeypatch, tmp_path)
    web = create_asset(uid, "WEB-01", asset_type="web", criticality="medium")
    create_vulnerability(uid, {"asset_id": web["id"], "asset_name": "WEB-01", "title": "Apache RCE", "cve": "CVE-2024-1111", "severity": "critical", "cvss": 9.8, "status": "open"})

    result = compute_attack_paths(uid)
    assert result["total_paths"] == 1
    path = result["paths"][0]
    assert path["hops"] == 1
    assert path["path_confidence"] == 1.0
    assert path["target_asset"]["label"] == "WEB-01"
    assert path["worst_vulnerability"]["cve"] == "CVE-2024-1111"


def test_compute_attack_paths_multi_hop_accumulates_entry_point_vulnerability(tmp_path, monkeypatch):
    """The core narrative case: DB-01 has no vulnerability of its own, but
    reaching it via a vulnerable WEB-01 is still a real, reported path —
    driven by the entry-point vulnerability, not a vuln on the target."""
    from app.enterprise import create_asset, create_asset_dependency, create_vulnerability
    from app.services.attack_graph import compute_attack_paths

    uid = _setup(monkeypatch, tmp_path)
    web = create_asset(uid, "WEB-01", asset_type="web", criticality="medium")
    db = create_asset(uid, "DB-01", asset_type="database", criticality="high", business_criticality="critical")
    create_vulnerability(uid, {"asset_id": web["id"], "asset_name": "WEB-01", "title": "Apache RCE", "cve": "CVE-2024-1111", "severity": "critical", "cvss": 9.8, "status": "open"})
    create_asset_dependency(uid, web["id"], db["id"])

    result = compute_attack_paths(uid)
    assert result["total_paths"] == 2
    db_path = next(p for p in result["paths"] if p["target_asset"]["label"] == "DB-01")
    assert db_path["hops"] == 2
    assert db_path["worst_vulnerability"]["cve"] == "CVE-2024-1111"
    assert db_path["path_confidence"] == 1.0  # declared edge, full confidence
    web_path = next(p for p in result["paths"] if p["target_asset"]["label"] == "WEB-01")
    # reaching the business-critical DB should score higher than stopping at WEB-01
    assert db_path["risk_score"] > web_path["risk_score"]


def test_compute_attack_paths_respects_max_depth(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_asset_dependency, create_vulnerability
    from app.services.attack_graph import compute_attack_paths

    uid = _setup(monkeypatch, tmp_path)
    web = create_asset(uid, "WEB-01", asset_type="web")
    mid = create_asset(uid, "MID-01", asset_type="server")
    db = create_asset(uid, "DB-01", asset_type="database")
    create_vulnerability(uid, {"asset_id": web["id"], "asset_name": "WEB-01", "title": "RCE", "cve": "CVE-2024-2222", "severity": "critical", "cvss": 9.0, "status": "open"})
    create_asset_dependency(uid, web["id"], mid["id"])
    create_asset_dependency(uid, mid["id"], db["id"])

    full = compute_attack_paths(uid, max_depth=4)
    assert any(p["target_asset"]["label"] == "DB-01" for p in full["paths"])

    shallow = compute_attack_paths(uid, max_depth=1)
    assert not any(p["target_asset"]["label"] == "DB-01" for p in shallow["paths"])


def test_compute_attack_paths_scoped_to_owning_user(tmp_path, monkeypatch):
    from app.auth import login, register_user
    from app.enterprise import create_asset, create_vulnerability
    from app.services.attack_graph import compute_attack_paths

    uid_a = _setup(monkeypatch, tmp_path, username="graph_owner_a")
    register_user("graph_owner_b", "password123", role="admin")
    u_b, _tok = login("graph_owner_b", "password123")

    web = create_asset(uid_a, "A-WEB-01", asset_type="web")
    create_vulnerability(uid_a, {"asset_id": web["id"], "asset_name": "A-WEB-01", "title": "RCE", "severity": "critical", "cvss": 9.0, "status": "open"})

    assert compute_attack_paths(uid_a)["total_paths"] == 1
    assert compute_attack_paths(u_b.id)["total_paths"] == 0


# --- attack_paths_disrupted_by_group --------------------------------------


def test_attack_paths_disrupted_by_group(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_asset_dependency, create_vulnerability
    from app.services.attack_graph import attack_paths_disrupted_by_group, build_graph

    uid = _setup(monkeypatch, tmp_path)
    web = create_asset(uid, "WEB-01", asset_type="web")
    db = create_asset(uid, "DB-01", asset_type="database", business_criticality="critical")
    v = create_vulnerability(uid, {"asset_id": web["id"], "asset_name": "WEB-01", "title": "Apache RCE", "cve": "CVE-2024-3333", "severity": "critical", "cvss": 9.8, "status": "open"})
    create_asset_dependency(uid, web["id"], db["id"])

    graph = build_graph(uid)
    assert any(n.get("vuln_id") == v["id"] for n in graph["nodes"])

    disrupted = attack_paths_disrupted_by_group(uid, {"apache_group": {v["id"]}})
    assert disrupted["apache_group"]["attack_paths_disrupted"] == 2
    assert disrupted["apache_group"]["business_critical_paths_disrupted"] == 1

    # a group referencing a vuln that isn't on any path disrupts nothing
    disrupted_none = attack_paths_disrupted_by_group(uid, {"unrelated": {"not-a-real-vuln-id"}})
    assert disrupted_none["unrelated"]["attack_paths_disrupted"] == 0
