"""Scan evidence investigation pack — loads report.md, no LLM call."""

from __future__ import annotations

import importlib
from pathlib import Path


def test_investigate_scan_includes_report_excerpt(tmp_path, monkeypatch):
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
    from app.enterprise import create_vulnerability
    from app.scan_engine.models import create_scan, evidence_root, update_scan
    from app.services.investigation import investigate_scan
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    user = register_user("inv_scan", "password123", role="user")
    scan = create_scan(
        user_id=user.id,
        target="192.168.56.101",
        scanner="securaiq",
        profile="discovery",
        scope=["192.168.56.0/24"],
        authorized=True,
    )
    sid = scan["id"]
    ev = Path(evidence_root(sid))
    ev.mkdir(parents=True, exist_ok=True)
    (ev / "report.md").write_text(
        "# SecuraIQ scan report\n\nOpen ports: 22, 80\nFinding: OpenSSH outdated\n",
        encoding="utf-8",
    )
    (ev / "config.json").write_text("{}", encoding="utf-8")
    create_vulnerability(
        user.id,
        {
            "title": "OpenSSH outdated",
            "severity": "high",
            "asset_name": "192.168.56.101",
            "source": "scan:securaiq",
            "raw": {"scan_id": sid},
        },
    )
    update_scan(
        sid,
        status="completed",
        summary_json={"findings": 1, "risk": {"score": 40, "band": "medium"}, "artifacts": [str(ev / "report.md")]},
    )

    pack = investigate_scan(user.id, sid)
    assert pack["kind"] == "scan_evidence"
    assert pack["summary"]["has_report"] is True
    assert "OpenSSH" in pack["prompt"]
    assert "report.md excerpt" in pack["prompt"]
    assert pack["context"]["artifacts"]
