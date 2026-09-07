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
    rows = parse_zap_json(__import__("json").loads((tmp_path / "zap.json").read_text(encoding="utf-8")))
    assert len(rows) >= 3
    titles = " ".join(r["title"].lower() for r in rows)
    assert "header" in titles or "clickjacking" in titles or "content security" in titles
    assert "cookie" in titles or "reflected" in titles
