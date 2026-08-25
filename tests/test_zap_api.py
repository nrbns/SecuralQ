"""ZAP REST API client — mocked HTTP, no live daemon required."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.scanners.zap_api import (
    ZapApiClient,
    api_alerts_to_report_json,
    parse_zap_api_alerts,
    run_zap_api_assessment,
)


@pytest.mark.asyncio
async def test_zap_api_client_probe():
    client = ZapApiClient("http://127.0.0.1:8090/", api_key="test-key")

    async def _fake_call(component, operation, name, *, params=None):
        assert component == "core" and operation == "view" and name == "version"
        return {"version": "2.14.0"}

    with patch.object(client, "call", new=AsyncMock(side_effect=_fake_call)):
        ok, detail = await client.probe()
    assert ok is True
    assert "2.14.0" in detail


def test_api_alerts_to_report_json_roundtrip():
    alerts = [
        {"name": "XSS", "risk": "High", "pluginId": "40012", "url": "http://lab/x"},
        {"name": "Missing header", "risk": "Low", "pluginId": "10020"},
    ]
    report = api_alerts_to_report_json("http://lab/", alerts)
    rows = report["site"][0]["alerts"]
    assert len(rows) == 2
    assert rows[0]["riskcode"] == "3"
    parsed = parse_zap_api_alerts(alerts, asset="http://lab/")
    assert any(p["severity"] == "high" for p in parsed)


@pytest.mark.asyncio
async def test_run_zap_api_assessment_writes_evidence(tmp_path):
    async def _fake_call(*args, **kwargs):
        if len(args) >= 4:
            component, operation, name = args[1], args[2], args[3]
        else:
            component, operation, name = args[0], args[1], args[2]
        if component == "core" and name == "accessUrl":
            return {"accessUrl": "OK"}
        if component == "spider" and operation == "action" and name == "scan":
            return {"scan": "1"}
        if component == "spider" and name == "status":
            return {"status": "100"}
        if component == "pscan" and name == "recordsToScan":
            return {"recordsToScan": "0"}
        if component == "alert" and name == "alerts":
            return {
                "alerts": [
                    {
                        "name": "Cross Site Scripting (Reflected)",
                        "risk": "High",
                        "pluginId": "40012",
                        "url": "http://192.168.56.101/x",
                    }
                ]
            }
        return {}

    with patch("app.scanners.zap_api.ZapApiClient.call", new=AsyncMock(side_effect=_fake_call)):
        out = await run_zap_api_assessment(
            target_url="http://192.168.56.101/",
            profile="web",
            evidence_dir=tmp_path,
            base_url="http://127.0.0.1:8090/",
            api_key="k",
            timeout_sec=30.0,
        )
    assert out["ok"] is True
    assert (tmp_path / "zap.json").is_file()
    assert (tmp_path / "zap_api_trace.json").is_file()
    data = json.loads((tmp_path / "zap.json").read_text(encoding="utf-8"))
    assert data["site"][0]["alerts"][0]["name"].startswith("Cross Site")
