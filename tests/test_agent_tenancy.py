"""Cross-tenant isolation for native SecuraIQ agents."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.agents_api import router as agents_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    app = FastAPI()
    app.include_router(agents_router)
    return TestClient(app)


def test_agents_isolated_across_orgs(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    from app.auth import login, register_user
    from app.commercial_ext import create_org

    alice = register_user("alice_ag", "password123", role="user")
    bob = register_user("bob_ag", "password123", role="user")
    org_a = create_org(alice.id, "OrgA-Agents")
    org_b = create_org(bob.id, "OrgB-Agents")
    _, tok_a = login("alice_ag", "password123")
    _, tok_b = login("bob_ag", "password123")

    ha = {"Authorization": f"Bearer {tok_a}", "X-SecuraIQ-Org": org_a["id"]}
    hb = {"Authorization": f"Bearer {tok_b}", "X-SecuraIQ-Org": org_b["id"]}

    ea = client.post("/api/agents/enroll", json={"name": "a-host"}, headers=ha)
    assert ea.status_code == 200, ea.text
    aid = ea.json()["agent_id"]

    listed_b = client.get("/api/agents", headers=hb)
    assert listed_b.status_code == 200
    assert listed_b.json()["agents"] == []

    got = client.get(f"/api/agents/{aid}", headers=hb)
    assert got.status_code == 404

    listed_a = client.get("/api/agents", headers=ha)
    names = {a["name"] for a in listed_a.json()["agents"]}
    assert "a-host" in names
    assert listed_a.json()["agents"][0].get("org_id") == org_a["id"]


def test_org_member_can_see_shared_agent(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    from app.auth import login, register_user
    from app.commercial_ext import add_org_member, create_org

    admin = register_user("orgadmin_ag", "password123", role="user")
    analyst = register_user("analyst_ag", "password123", role="user")
    org = create_org(admin.id, "Shared-Agents")
    add_org_member(admin.id, org["id"], "analyst_ag", role="analyst")
    _, tok_admin = login("orgadmin_ag", "password123")
    _, tok_an = login("analyst_ag", "password123")
    h_admin = {"Authorization": f"Bearer {tok_admin}", "X-SecuraIQ-Org": org["id"]}
    h_an = {"Authorization": f"Bearer {tok_an}", "X-SecuraIQ-Org": org["id"]}

    enroll = client.post("/api/agents/enroll", json={"name": "shared"}, headers=h_admin)
    assert enroll.status_code == 200
    listed = client.get("/api/agents", headers=h_an)
    assert listed.status_code == 200
    assert any(a["name"] == "shared" for a in listed.json()["agents"])
