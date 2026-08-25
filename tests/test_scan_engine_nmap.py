"""Nmap scan engine — parse / normalize / scope (no live nmap required)."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun>
  <host>
    <address addr="192.168.56.101" addrtype="ipv4"/>
    <hostnames><hostname name="lab.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="7.4"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache" version="2.4.6"/></port>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
      <port protocol="tcp" portid="443"><state state="closed"/><service name="https"/></port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml():
    from app.scanners.nmap import parse_nmap_xml

    data = parse_nmap_xml(SAMPLE_NMAP_XML)
    assert data["address"] == "192.168.56.101"
    assert data["hostname"] == "lab.local"
    ports = {p["port"] for p in data["ports"]}
    assert 22 in ports and 80 in ports and 445 in ports
    assert 443 not in ports  # closed filtered out


def test_normalize_risky_ports():
    from app.scanners.base import ScanContext
    from app.scanners.nmap import NmapScanner, parse_nmap_xml

    sc = NmapScanner()
    ctx = ScanContext(
        scan_id="t1",
        target="192.168.56.101",
        profile="discovery",
        scope=["192.168.56.0/24"],
        authorized=True,
        evidence_dir=Path("."),
    )
    normalized = sc.normalize(parse_nmap_xml(SAMPLE_NMAP_XML), ctx)
    assert normalized.summary["open_ports"] == 3
    titles = " ".join(f.title for f in normalized.findings)
    assert "SMB" in titles or "445" in titles
    assert any(f.severity == "info" for f in normalized.findings)


def test_scope_blocks_out_of_range():
    from app.scanners.nmap import NmapScanner

    sc = NmapScanner()
    ok, _ = sc.validate_scope("10.0.0.5", ["192.168.56.0/24"])
    assert not ok
    ok2, _ = sc.validate_scope("192.168.56.101", ["192.168.56.0/24"])
    assert ok2


def test_scan_create_and_normalize_persist(tmp_path, monkeypatch):
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
    from app.enterprise import list_assets, list_vulnerabilities
    from app.scan_engine.models import create_scan, evidence_root, update_scan
    from app.scanners.base import RawScanResult, ScanContext
    from app.scanners.nmap import NmapScanner
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    user = register_user("scan_user", "password123", role="user")
    scan = create_scan(
        user_id=user.id,
        target="192.168.56.101",
        scanner="nmap",
        profile="discovery",
        scope=["192.168.56.0/24"],
        authorized=True,
    )
    assert scan["status"] == "queued"

    # Simulate parse/normalize/persist without running nmap binary
    ev = evidence_root(scan["id"])
    (ev / "nmap.xml").write_text(SAMPLE_NMAP_XML, encoding="utf-8")
    sc = NmapScanner()
    ctx = ScanContext(
        scan_id=scan["id"],
        target="192.168.56.101",
        profile="discovery",
        scope=["192.168.56.0/24"],
        authorized=True,
        evidence_dir=ev,
        user_id=user.id,
    )
    raw = RawScanResult(exit_code=0, stdout="", stderr="", artifact_paths=[str(ev / "nmap.xml")])
    parsed = sc.parse(raw, ctx)
    normalized = sc.normalize(parsed, ctx)

    from app.enterprise import create_vulnerability, ensure_asset_for_target

    asset = ensure_asset_for_target(user.id, normalized.asset_name, notes="test")
    for f in normalized.findings:
        create_vulnerability(
            user.id,
            {
                "title": f.title,
                "severity": f.severity,
                "asset_name": normalized.asset_name,
                "asset_id": (asset or {}).get("id"),
                "source": f.source,
                "raw": {"scan_id": scan["id"]},
            },
        )
    update_scan(scan["id"], status="completed", summary_json=normalized.summary)

    assets = list_assets(user.id)
    vulns = list_vulnerabilities(user.id)
    assert any(a["name"] in {"lab.local", "192.168.56.101"} for a in assets)
    assert len(vulns) >= 2


@pytest.mark.asyncio
async def test_execute_scan_nmap_fixture_e2e(tmp_path, monkeypatch):
    """Full executor path with fixture XML — no nmap binary required."""
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
    from app.enterprise import list_assets, list_risks, list_vulnerabilities
    from app.scan_engine.executor import execute_scan
    from app.scan_engine.models import create_scan, evidence_root, get_scan
    from app.scanners.base import RawScanResult
    from app.scanners import nmap as nmap_mod
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    user = register_user("nmap_e2e", "password123", role="user")
    scan = create_scan(
        user_id=user.id,
        target="192.168.56.101",
        scanner="nmap",
        profile="discovery",
        scope=["192.168.56.0/24"],
        authorized=True,
    )
    sid = scan["id"]
    ev = evidence_root(sid)

    async def _fake_execute(self, ctx):
        ctx.evidence_dir.mkdir(parents=True, exist_ok=True)
        xml_path = ctx.evidence_dir / "nmap.xml"
        xml_path.write_text(SAMPLE_NMAP_XML, encoding="utf-8")
        (ctx.evidence_dir / "stdout.log").write_text("fixture nmap", encoding="utf-8")
        (ctx.evidence_dir / "stderr.log").write_text("", encoding="utf-8")
        (ctx.evidence_dir / "command.txt").write_text("nmap -fixture 192.168.56.101", encoding="utf-8")
        return RawScanResult(
            exit_code=0,
            stdout="fixture nmap",
            stderr="",
            artifact_paths=[
                str(xml_path),
                str(ctx.evidence_dir / "stdout.log"),
                str(ctx.evidence_dir / "stderr.log"),
                str(ctx.evidence_dir / "command.txt"),
            ],
        )

    monkeypatch.setattr(nmap_mod.NmapScanner, "available", lambda self: (True, "nmap"))
    monkeypatch.setattr(nmap_mod.NmapScanner, "execute", _fake_execute)

    result = await execute_scan(sid)
    assert result["ok"] is True
    done = get_scan(sid)
    assert done["status"] == "completed"
    summary = done.get("summary") or {}
    assert summary.get("findings", 0) >= 1
    assert summary.get("risk", {}).get("score") is not None
    assert (ev / "config.json").is_file()
    assert (ev / "metadata.json").is_file()
    assert (ev / "nmap.xml").is_file()
    assert (ev / "report.md").is_file()
    assets = list_assets(user.id)
    vulns = list_vulnerabilities(user.id)
    assert any(a["name"] in {"lab.local", "192.168.56.101"} for a in assets)
    assert len(vulns) >= 1
    # SMB/445 should open at least one high risk register row
    risks = list_risks(user.id)
    assert isinstance(risks, list)


@pytest.mark.asyncio
async def test_execute_scan_nmap_blocks_empty_scope(tmp_path, monkeypatch):
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
    from app.scan_engine.executor import execute_scan
    from app.scan_engine.models import create_scan, get_scan
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    user = register_user("nmap_scope", "password123", role="user")
    scan = create_scan(
        user_id=user.id,
        target="192.168.56.101",
        scanner="nmap",
        profile="discovery",
        scope=[],
        authorized=True,
    )
    result = await execute_scan(scan["id"])
    assert result.get("blocked") is True
    assert get_scan(scan["id"])["status"] == "blocked"
