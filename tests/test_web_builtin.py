"""Built-in SecuraIQ Web Scanner — no external ZAP required."""

from __future__ import annotations

import pytest

from app.scanners.web_builtin import run_builtin_web_scan
from app.scanners.zap import parse_zap_json


@pytest.mark.asyncio
async def test_run_builtin_web_scan_writes_zap_json(tmp_path, monkeypatch):
    class _Resp:
        status_code = 200
        text = "<html><title>lab</title>SecuraIQCanary7x</html>"
        url = "http://example.com/"

        @property
        def headers(self):
            import httpx

            return httpx.Headers({"server": "nginx/1.18", "set-cookie": "sid=abc; Path=/"})

    async def _fake_fetch(client, url, *, headers=None):
        return _Resp(), ""

    monkeypatch.setattr("app.scanners.web_builtin._fetch", _fake_fetch)
    monkeypatch.setattr("app.scanners.web_builtin._tls_probe", lambda *a, **k: {"tls_version": "TLSv1.3"})

    out = await run_builtin_web_scan(
        target_url="http://example.com",
        profile="vulnerability",
        evidence_dir=tmp_path,
        scan_id="scan-web-1",
        timeout_sec=30.0,
    )
    assert out["ok"] is True
    assert out["mode"] == "securaiq_web_builtin"
    assert (tmp_path / "zap.json").is_file()
    report = __import__("json").loads((tmp_path / "zap.json").read_text(encoding="utf-8"))
    assert report.get("@version") == "SecuraIQ-WebScanner"
    rows = parse_zap_json(report)
    assert len(rows) >= 3
    titles = " ".join(r["title"].lower() for r in rows)
    assert "header" in titles or "clickjacking" in titles or "content security" in titles
    assert "cookie" in titles or "reflected" in titles
    # Must not pad inaccurate "sensitive path" hits for generic /login|/admin 200s
    assert "sensitive path exposed: /login" not in titles
    assert "sensitive path exposed: /admin" not in titles
    # Honest plugin ids — not OWASP ZAP numbers
    plugins = " ".join(str(r.get("plugin") or "") for r in rows)
    assert "seciq-" in plugins


@pytest.mark.asyncio
async def test_builtin_does_not_flag_tls13_as_weak(tmp_path, monkeypatch):
    class _Resp:
        status_code = 200
        text = "<html>ok</html>"
        url = "https://example.com/"

        @property
        def headers(self):
            import httpx

            return httpx.Headers(
                {
                    "strict-transport-security": "max-age=1",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "no-referrer",
                    "permissions-policy": "geolocation=()",
                }
            )

    async def _fake_fetch(client, url, *, headers=None):
        return _Resp(), ""

    monkeypatch.setattr("app.scanners.web_builtin._fetch", _fake_fetch)
    monkeypatch.setattr("app.scanners.web_builtin._tls_probe", lambda *a, **k: {"tls_version": "TLSv1.3"})

    await run_builtin_web_scan(
        target_url="https://example.com",
        profile="web",
        evidence_dir=tmp_path,
        timeout_sec=30.0,
    )
    report = __import__("json").loads((tmp_path / "zap.json").read_text(encoding="utf-8"))
    titles = [a["name"] for a in report["site"][0]["alerts"]]
    assert not any("Weak TLS" in t for t in titles)


@pytest.mark.asyncio
async def test_builtin_flags_tls10(tmp_path, monkeypatch):
    class _Resp:
        status_code = 200
        text = "ok"
        url = "https://example.com/"

        @property
        def headers(self):
            import httpx

            return httpx.Headers(
                {
                    "strict-transport-security": "max-age=1",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "no-referrer",
                    "permissions-policy": "geolocation=()",
                }
            )

    async def _fake_fetch(client, url, *, headers=None):
        return _Resp(), ""

    monkeypatch.setattr("app.scanners.web_builtin._fetch", _fake_fetch)
    monkeypatch.setattr("app.scanners.web_builtin._tls_probe", lambda *a, **k: {"tls_version": "TLSv1.0"})

    await run_builtin_web_scan(
        target_url="https://example.com",
        profile="web",
        evidence_dir=tmp_path,
        timeout_sec=30.0,
    )
    report = __import__("json").loads((tmp_path / "zap.json").read_text(encoding="utf-8"))
    assert any("Weak TLS" in a["name"] for a in report["site"][0]["alerts"])


@pytest.mark.asyncio
async def test_builtin_does_not_flag_generic_login_200(tmp_path, monkeypatch):
    class _Resp:
        def __init__(self, url, text="ok"):
            self.status_code = 200
            self.text = text
            self.url = url

        @property
        def headers(self):
            import httpx

            return httpx.Headers(
                {
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff",
                    "strict-transport-security": "max-age=1",
                    "referrer-policy": "no-referrer",
                    "permissions-policy": "geolocation=()",
                }
            )

    async def _fake_fetch(client, url, *, headers=None):
        return _Resp(url, "login form"), ""

    monkeypatch.setattr("app.scanners.web_builtin._fetch", _fake_fetch)
    monkeypatch.setattr("app.scanners.web_builtin._tls_probe", lambda *a, **k: {"tls_version": "TLSv1.3"})

    out = await run_builtin_web_scan(
        target_url="https://example.com",
        profile="vulnerability",
        evidence_dir=tmp_path,
        timeout_sec=30.0,
    )
    report = __import__("json").loads((tmp_path / "zap.json").read_text(encoding="utf-8"))
    titles = [a["name"].lower() for a in report["site"][0]["alerts"]]
    assert not any("sensitive path" in t for t in titles)
    assert out["alerts"] == len(titles)
