"""Finding lifecycle: triage → remediate → resolve with canonical statuses."""

from __future__ import annotations

import importlib

import pytest

from app.enterprise import VULN_STATUSES


def test_vuln_statuses_canonical():
    assert "open" in VULN_STATUSES
    assert "triaged" in VULN_STATUSES
    assert "resolved" in VULN_STATUSES
    assert "bogus" not in VULN_STATUSES


def test_finding_lifecycle_triage_and_close(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEPLOYMENT_MODE", "lab")
    monkeypatch.setenv("DATABASE_URL", "")
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)

    from app.auth import register_user
    from app.enterprise import (
        create_vulnerability,
        get_vulnerability,
        triage_vulnerability,
        update_vulnerability,
    )
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    user = register_user("life_user", "password123", role="user")
    v = create_vulnerability(
        user.id,
        {
            "title": "Open SMB share",
            "severity": "high",
            "asset_name": "lab.local",
            "cve": "",
            "source": "scan:nmap",
        },
    )
    assert (v.get("status") or "open") == "open"

    out = triage_vulnerability(user.id, v["id"], owner="BlueTeam")
    assert out["ok"] is True
    assert out["risk"]["id"]
    assert out["remediation"]["id"]
    assert (out["vulnerability"] or {}).get("status") == "triaged"

    mid = update_vulnerability(user.id, v["id"], {"status": "in_progress"})
    assert mid["status"] == "in_progress"
    rem = update_vulnerability(user.id, v["id"], {"status": "remediated"})
    assert rem["status"] == "remediated"
    done = update_vulnerability(user.id, v["id"], {"status": "resolved"})
    assert done["status"] == "resolved"
    assert get_vulnerability(user.id, v["id"])["status"] == "resolved"

    with pytest.raises(ValueError, match="Invalid vulnerability status"):
        update_vulnerability(user.id, v["id"], {"status": "not_a_real_status"})
