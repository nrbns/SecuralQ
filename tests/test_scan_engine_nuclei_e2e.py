"""Nuclei executor E2E — fixture JSONL, no nuclei binary required."""

from __future__ import annotations

import importlib
import json

import pytest

SAMPLE_JSONL = """
{"template-id":"http-missing-security-headers","info":{"name":"HTTP Missing Security Headers","severity":"info"},"matched-at":"http://192.168.56.101/","host":"192.168.56.101"}
{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical","classification":{"cve-id":["CVE-2021-44228"]}},"matched-at":"http://192.168.56.101:8080/","host":"192.168.56.101"}
""".strip()


@pytest.mark.asyncio
async def test_execute_scan_nuclei_fixture_e2e(tmp_path, monkeypatch):
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
    from app.scanners import nuclei as nuclei_mod
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    user = register_user("nuclei_e2e", "password123", role="user")
    scan = create_scan(
        user_id=user.id,
        target="http://192.168.56.101",
        scanner="nuclei",
        profile="web",
        scope=["192.168.56.0/24"],
        authorized=True,
    )
    sid = scan["id"]
    ev = evidence_root(sid)

    async def _fake_execute(self, ctx):
        ctx.evidence_dir.mkdir(parents=True, exist_ok=True)
        jl = ctx.evidence_dir / "nuclei.jsonl"
        jl.write_text(SAMPLE_JSONL, encoding="utf-8")
        (ctx.evidence_dir / "stdout.log").write_text("fixture nuclei", encoding="utf-8")
        (ctx.evidence_dir / "stderr.log").write_text("", encoding="utf-8")
        (ctx.evidence_dir / "command.txt").write_text("nuclei -fixture", encoding="utf-8")
        return RawScanResult(
            exit_code=0,
            stdout="fixture nuclei",
            stderr="",
            artifact_paths=[
                str(jl),
                str(ctx.evidence_dir / "stdout.log"),
                str(ctx.evidence_dir / "stderr.log"),
                str(ctx.evidence_dir / "command.txt"),
            ],
        )

    monkeypatch.setattr(nuclei_mod.NucleiScanner, "available", lambda self: (True, "nuclei"))
    monkeypatch.setattr(nuclei_mod.NucleiScanner, "execute", _fake_execute)

    result = await execute_scan(sid)
    assert result["ok"] is True
    done = get_scan(sid)
    assert done["status"] == "completed"
    summary = done.get("summary") or {}
    assert summary.get("findings", 0) >= 1
    assert (ev / "config.json").is_file()
    assert (ev / "nuclei.jsonl").is_file()
    assert (ev / "report.md").is_file()
    vulns = list_vulnerabilities(user.id)
    assert any("Log4j" in (v.get("title") or "") or "CVE-2021-44228" in (v.get("cve") or "") for v in vulns)
    assert any((v.get("severity") or "").lower() == "critical" for v in vulns)
