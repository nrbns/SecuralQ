"""World-class remaining rows: EASM, macOS hardening, toxic chains, host change."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_easm_discovers_owned_localhost(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user
    from app.checklist_board import world_class_section_proofs
    from app.db import init_schema
    from app.easm import discover_attack_surface, easm_status
    from app.enterprise import create_asset
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    assert all(world_class_section_proofs().values())
    assert easm_status()["lab_production"] is True
    u = register_user("easm_op", "password123")
    create_asset(u.id, name="127.0.0.1", asset_type="server")
    out = discover_attack_surface(u.id, include_cert_sans=False)
    assert out["ok"] is True
    assert out["owned_count"] >= 1
    hosts = {h.get("host") for h in out.get("hosts") or []}
    assert "127.0.0.1" in hosts


def test_macos_hardening_parsers_and_non_darwin():
    from app.macos_hardening import collect_macos_hardening, parse_gatekeeper, parse_remote_login, parse_sip

    assert parse_gatekeeper("assessments enabled") is True
    assert parse_sip("System Integrity Protection status: disabled.") is False
    assert parse_remote_login("Remote Login: Off") is False
    blob = collect_macos_hardening()
    assert "collected" in blob
    if blob["collected"] is False:
        assert blob.get("os") != "darwin"


def test_toxic_chain_kinds(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user
    from app.db import init_schema
    from app.enterprise import create_asset, create_vulnerability
    from app.tenancy import ensure_tenant_schema
    from app.toxic_combos import TOXIC_KINDS, compute_toxic_combinations

    init_schema()
    ensure_tenant_schema()
    assert len(TOXIC_KINDS) >= 6
    u = register_user("toxic_op", "password123")
    asset = create_asset(
        u.id,
        name="edge.example.com",
        asset_type="server",
        business_criticality="high",
        service_accounts="payments-api",
    )
    create_vulnerability(
        u.id,
        {
            "asset_id": asset["id"],
            "asset_name": "edge.example.com",
            "title": "Remote code execution",
            "severity": "critical",
            "cve": "CVE-2024-0001",
            "status": "open",
            "raw": {"kev": True},
        },
    )
    toxic = compute_toxic_combinations(u.id)
    assert toxic["ok"] is True
    kinds = set(toxic.get("kinds") or [])
    assert "internet_facing_high_vuln" in kinds
    assert "public_kev" in kinds
    assert "public_service_account_high_vuln" in kinds
    assert "high_vuln_missing_compensating_control" in kinds


def test_host_change_and_checkin(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents import checkin, enroll_agent
    from app.auth import register_user
    from app.db import init_schema
    from app.host_change import diff_host_payload, list_host_changes
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    prev = {
        "local_users": {"items": [{"name": "alice"}]},
        "listening_ports": [22],
        "firewall_status": {"enabled": True},
        "processes": [{"name": "sshd"}],
        "startup_apps": {"items": []},
    }
    curr = {
        "local_users": {"items": [{"name": "alice"}, {"name": "bob"}]},
        "listening_ports": [22, 3389],
        "firewall_status": {"enabled": False},
        "processes": [{"name": "sshd"}],
        "startup_apps": {"items": []},
    }
    diff = diff_host_payload(prev, curr)
    assert diff["has_changes"] is True
    assert "bob" in diff["changes"]["users_added"]
    assert "3389" in diff["changes"]["ports_opened"]
    u = register_user("change_op", "password123")
    agent = enroll_agent(u.id, name="change-host")
    checkin(agent["agent_id"], prev)
    checkin(agent["agent_id"], curr)
    listed = list_host_changes(u.id)
    assert listed["ok"] is True
    assert listed["count"] >= 1


def test_world_class_http_easm_and_changes(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    from fastapi.testclient import TestClient

    from app.db import init_schema
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    client = TestClient(app)
    r = client.get("/api/easm/status")
    assert r.status_code == 200
    assert r.json()["lab_production"] is True
    r = client.post("/api/easm/discover", json={"include_cert_sans": False})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    r = client.get("/api/exposure/changes")
    assert r.status_code == 200
    assert r.json()["ok"] is True
    r = client.get("/api/checklists")
    assert r.status_code == 200
    body = r.json()
    wc = next(c for c in body["checklists"] if c["id"] == "world_class")
    assert wc["complete"] is True
    assert wc["proofs"]["easm"] is True
    assert wc["proofs"]["macos_hardening"] is True
    assert wc["proofs"]["toxic_kinds"] is True
