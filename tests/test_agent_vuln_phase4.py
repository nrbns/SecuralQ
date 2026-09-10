"""Phase 4: agent packages → advisory match → enterprise vuln bridge."""

from __future__ import annotations

from unittest.mock import patch

from tests._http_test_utils import configure_isolated_settings


def _reload(monkeypatch, data_dir):
    return configure_isolated_settings(monkeypatch, data_dir)


def test_refresh_advisories_for_asset_and_bridge(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.db import get_conn, new_id, now
    from app.enterprise import list_vulnerabilities
    from app.software.advisories import refresh_advisories_for_asset
    from app.software.models import ensure_schema as ensure_sw

    ensure_sw()
    uid = "local"
    pid = new_id()
    iid = new_id()
    asset_id = "asset-phase4"
    c = get_conn()
    c.execute(
        "INSERT INTO software_products (id, user_id, name, normalized_name, canonical_id, publisher, vendor, category, package_ecosystem, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (pid, uid, "OpenSSL", "openssl", "openssl.openssl", "", "OpenSSL", "", "", now(), now()),
    )
    c.execute(
        """
        INSERT INTO software_installations
        (id, user_id, asset_id, asset_name, software_product_id, version, architecture, install_path, install_date, source, source_id, first_seen, last_seen, status, severity, cve, detail, port, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            iid,
            uid,
            asset_id,
            "lab-host",
            pid,
            "1.1.1k",
            "",
            "",
            "",
            "securaiq_agent",
            "agent-pkg:x:openssl",
            now(),
            now(),
            "installed",
            "high",
            "CVE-2022-0778",
            "openssl",
            None,
            now(),
        ),
    )
    c.commit()

    with patch(
        "app.software.advisories.fetch_nvd_sync",
        return_value={"cvss": 9.8, "severity": "CRITICAL", "description": "OpenSSL"},
    ):
        with patch(
            "app.software.advisories.load_kev_catalog",
            return_value=(
                {"CVE-2022-0778"},
                [{"cve": "CVE-2022-0778", "vendor": "OpenSSL", "product": "OpenSSL"}],
            ),
        ):
            with patch("app.software.advisories.query_package_vulns", return_value=[]):
                result = refresh_advisories_for_asset(
                    uid,
                    asset_id,
                    limit=10,
                    os_hint="Linux Ubuntu",
                    asset_name="lab-host",
                    listening_ports=[22, 443],
                    agent_ip="10.0.0.5",
                    bridge_vulns=True,
                )

    assert result["checked"] >= 1
    assert result["advisories_matched"] >= 1
    bridged = result.get("bridged") or {}
    assert int(bridged.get("created") or 0) + int(bridged.get("updated") or 0) >= 1

    vulns = list_vulnerabilities(uid)
    assert any((v.get("cve") or "").upper() == "CVE-2022-0778" for v in vulns)
    hit = next(v for v in vulns if (v.get("cve") or "").upper() == "CVE-2022-0778")
    assert hit.get("asset_id") == asset_id
    assert (hit.get("source") or "").startswith("software:advisory")


def test_checkin_runs_advisory_refresh(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agents import checkin, enroll_agent, ensure_schema
    from app.software.models import ensure_schema as ensure_sw

    ensure_schema()
    ensure_sw()
    enrolled = enroll_agent("local", name="phase4-host")
    aid = enrolled["agent_id"]

    calls: list[dict] = []

    def _fake_refresh(user_id, asset_id, **kwargs):
        calls.append({"user_id": user_id, "asset_id": asset_id, **kwargs})
        return {"checked": 1, "advisories_matched": 0, "bridged": {}}

    monkeypatch.setattr(
        "app.software.advisories.refresh_advisories_for_asset",
        _fake_refresh,
    )
    monkeypatch.setattr("app.software.advisories.should_refresh_asset", lambda *a, **k: True)

    result = checkin(
        aid,
        {
            "hostname": "phase4-host",
            "os": "linux",
            "os_version": "Ubuntu 22.04",
            "ip": "10.0.0.9",
            "listening_ports": [22],
            "packages": [{"name": "curl", "version": "7.81.0"}],
        },
    )
    assert result.get("ok")
    assert result.get("asset_id")
    assert calls, "expected refresh_advisories_for_asset on check-in"
    assert calls[0]["asset_id"] == result["asset_id"]
    assert calls[0].get("listening_ports") == [22]
