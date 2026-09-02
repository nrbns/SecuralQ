"""ZAP executor E2E — fixture JSON, no ZAP binary required."""

from __future__ import annotations

import importlib
import json

import pytest

SAMPLE_ZAP = {
    "site": [
        {
            "@name": "http://192.168.56.101",
            "alerts": [
                {
                    "name": "Missing Anti-clickjacking Header",
                    "riskcode": "1",
                    "riskdesc": "Low",
                    "pluginid": "10020",
                    "instances": [{}],
                },
                {
                    "name": "Cross Site Scripting (Reflected)",
                    "riskcode": "3",
                    "riskdesc": "High",
                    "pluginid": "40012",
                    "instances": [{}, {}],
                },
            ],
        }
    ]
}


@pytest.mark.asyncio
async def test_execute_scan_zap_fixture_e2e(tmp_path, monkeypatch):
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
    from app.enterprise import list_vulnerabilities
    from app.scan_engine.executor import execute_scan
    from app.scan_engine.models import create_scan, evidence_root, get_scan
    from app.scanners.base import RawScanResult
    from app.scanners import zap as zap_mod
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    user = register_user("zap_e2e", "password123", role="user")
    scan = create_scan(
        user_id=user.id,
        # A real public hostname, not a private/lab IP: app.scanners.zap's
        # validate_target (called by execute_scan below, before execute()
        # is invoked — and NOT covered by the execute() monkeypatch further
        # down) now rejects loopback/RFC1918/link-local targets, since the
        # Web Scanner is scoped to public web apps only (internal hosts go
        # through the network/VAPT scanner instead). A private lab IP here
        # would fail validate_target and the scan would never reach the
        # fixture-execute path this test is actually exercising.
        target="http://example.com",
        scanner="zap",
        profile="web",
        scope=["example.com"],
        authorized=True,
    )
    sid = scan["id"]
    ev = evidence_root(sid)

    async def _fake_execute(self, ctx):
        ctx.evidence_dir.mkdir(parents=True, exist_ok=True)
        zj = ctx.evidence_dir / "zap.json"
        zj.write_text(json.dumps(SAMPLE_ZAP), encoding="utf-8")
        (ctx.evidence_dir / "stdout.log").write_text("fixture zap", encoding="utf-8")
        (ctx.evidence_dir / "stderr.log").write_text("", encoding="utf-8")
        (ctx.evidence_dir / "command.txt").write_text("zap -fixture", encoding="utf-8")
        return RawScanResult(
            exit_code=0,
            stdout="fixture zap",
            stderr="",
            artifact_paths=[
                str(zj),
                str(ctx.evidence_dir / "stdout.log"),
                str(ctx.evidence_dir / "stderr.log"),
                str(ctx.evidence_dir / "command.txt"),
            ],
        )

    monkeypatch.setattr(zap_mod.ZapScanner, "available", lambda self: (True, "zap"))
    monkeypatch.setattr(zap_mod.ZapScanner, "execute", _fake_execute)

    result = await execute_scan(sid)
    assert result["ok"] is True
    done = get_scan(sid)
    assert done["status"] == "completed"
    summary = done.get("summary") or {}
    assert summary.get("findings", 0) >= 1
    assert (ev / "config.json").is_file()
    assert (ev / "zap.json").is_file()
    assert (ev / "report.md").is_file()
    vulns = list_vulnerabilities(user.id)
    assert any("XSS" in (v.get("title") or "") or "Scripting" in (v.get("title") or "") for v in vulns)
    assert any((v.get("severity") or "").lower() == "high" for v in vulns)
