"""SecuraIQ Web Scanner scan-engine adapter — parse/normalize (no external install required)."""

from __future__ import annotations

from pathlib import Path

from app.scanners.base import RawScanResult, ScanContext
from app.scanners.registry import ENGINE_ENABLED, list_scanners
from app.scanners.zap import ZapScanner, parse_zap_baseline_text, parse_zap_json

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


def test_zap_engine_enabled():
    assert "zap" in ENGINE_ENABLED
    assert {s["id"] for s in list_scanners()} >= {"securaiq", "nmap", "nuclei", "zap"}


def test_parse_zap_json():
    rows = parse_zap_json(SAMPLE_ZAP)
    assert len(rows) == 2
    assert any(r["severity"] == "high" for r in rows)
    assert any("Clickjacking" in r["title"] or "clickjacking" in r["title"].lower() for r in rows)


def test_parse_zap_baseline_text():
    text = "WARN-10021 X-Content-Type-Options header missing\nFAIL-40012 Cross Site Scripting\n"
    rows = parse_zap_baseline_text(text, asset="lab.local")
    assert len(rows) == 2
    assert rows[1]["severity"] == "high"


def test_normalize_zap(tmp_path):
    sc = ZapScanner()
    ctx = ScanContext(
        scan_id="z1",
        target="http://192.168.56.101",
        profile="web",
        scope=["192.168.56.0/24"],
        authorized=True,
        evidence_dir=tmp_path,
    )
    (tmp_path / "zap.json").write_text(
        __import__("json").dumps(SAMPLE_ZAP),
        encoding="utf-8",
    )
    raw = RawScanResult(exit_code=0, stdout="", stderr="", artifact_paths=[])
    parsed = sc.parse(raw, ctx)
    normalized = sc.normalize(parsed, ctx)
    assert normalized.summary["scanner"] == "securaiq_web"
    assert normalized.summary["alerts"] == 2
    assert any(f.severity == "high" for f in normalized.findings)


def test_zap_always_available_builtin():
    sc = ZapScanner()
    ok, detail = sc.available()
    assert ok is True
    assert "built-in" in detail.lower()


def test_zap_scope_blocks():
    sc = ZapScanner()
    ok, _ = sc.validate_scope("https://evil.example/", ["192.168.56.0/24"])
    assert not ok
