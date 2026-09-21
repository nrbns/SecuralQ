"""Asset identity — multi-source aliases → one canonical asset."""

from __future__ import annotations

import json

from tests._http_test_utils import configure_isolated_settings


def _uid(monkeypatch, tmp_path, name="ident_user"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(name, "password123", role="admin")
    u, _ = login(name, "password123")
    return u.id


def test_agent_and_cloud_ids_merge_to_one_asset(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "ident_merge")
    from app.asset_identity import list_aliases, resolve_canonical
    from app.enterprise import ensure_asset_for_target, list_assets

    a1 = ensure_asset_for_target(
        uid,
        "SERVER01",
        notes=json.dumps(
            {
                "hostname": "SERVER01",
                "ip": "10.0.0.21",
                "securaiq_agent_id": "ag-892",
                "source": "agent",
            }
        ),
    )
    assert a1 and a1["id"]
    a2 = ensure_asset_for_target(
        uid,
        "i-123",
        notes=json.dumps(
            {
                "ip": "10.0.0.21",
                "aws_instance_id": "i-123",
                "hostname": "SERVER01",
                "source": "aws",
            }
        ),
    )
    assert a2["id"] == a1["id"]
    a3 = ensure_asset_for_target(
        uid,
        "edr-host",
        notes=json.dumps(
            {
                "edr_id": "ABC123",
                "ip": "10.0.0.21",
                "source": "edr",
            }
        ),
    )
    assert a3["id"] == a1["id"]
    assert len(list_assets(uid)) == 1

    hit = resolve_canonical(uid, agent_id="ag-892")
    assert hit and hit["asset_id"] == a1["id"]
    hit2 = resolve_canonical(uid, aws_instance_id="i-123")
    assert hit2 and hit2["asset_id"] == a1["id"]
    aliases = list_aliases(uid, a1["id"])
    kinds = {a["kind"] for a in aliases}
    assert "securaiq_agent_id" in kinds
    assert "aws_instance_id" in kinds
    assert "ip" in kinds


def test_alias_conflict_recorded(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "ident_conflict")
    from app.asset_identity import list_conflicts, register_alias
    from app.enterprise import create_asset

    a = create_asset(uid, "host-a", notes="{}")
    b = create_asset(uid, "host-b", notes="{}")
    register_alias(uid, a["id"], kind="ip", value="10.1.1.1", source="test")
    conflict = register_alias(uid, b["id"], kind="ip", value="10.1.1.1", source="test")
    assert conflict.get("conflict") is True
    assert conflict["existing_asset_id"] == a["id"]
    assert len(list_conflicts(uid)) >= 1


def test_asset_identity_api(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("ident_api", "password123", role="admin")
    _, token = login("ident_api", "password123")
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}

    r = client.post(
        "/api/assets",
        headers=headers,
        json={"name": "pay-api-01", "notes": json.dumps({"ip": "10.9.9.9"})},
    )
    assert r.status_code == 200
    aid = r.json()["id"] if "id" in r.json() else r.json().get("asset", {}).get("id")
    if not aid:
        # create_asset response shapes vary
        body = r.json()
        aid = body.get("id") or (body.get("asset") or {}).get("id")
    assert aid

    r2 = client.post(
        f"/api/assets/{aid}/aliases",
        headers=headers,
        json={"kind": "aws_instance_id", "value": "i-deadbeef", "source": "api"},
    )
    assert r2.status_code == 200

    r3 = client.post(
        "/api/assets/resolve",
        headers=headers,
        json={"aws_instance_id": "i-deadbeef"},
    )
    assert r3.status_code == 200
    assert r3.json()["match"]["asset_id"] == aid
