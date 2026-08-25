"""Windows Control Panel installed-software inventory."""

from unittest.mock import patch

from app.windows_inventory import ingest_local_control_panel_software, parse_control_panel_json


def test_parse_control_panel_json_array():
    raw = """[
      {"name": "Google Chrome", "version": "120.0.6099.129", "publisher": "Google LLC", "install_date": "20240115"},
      {"name": "7-Zip 23.01", "version": "23.01", "publisher": "Igor Pavlov", "install_date": "20230901"}
    ]"""
    rows = parse_control_panel_json(raw)
    assert len(rows) == 2
    assert rows[0]["name"] == "Google Chrome"
    assert rows[0]["version"].startswith("120")
    assert rows[1]["publisher"] == "Igor Pavlov"


def test_parse_control_panel_json_single_object():
    raw = '{"name": "Notepad++", "version": "8.6.2", "publisher": "Don Ho", "install_date": ""}'
    rows = parse_control_panel_json(raw)
    assert len(rows) == 1
    assert rows[0]["name"] == "Notepad++"


def test_parse_control_panel_json_dedupes():
    raw = '[{"name": "App", "version": "1"}, {"name": "App", "version": "1"}]'
    assert len(parse_control_panel_json(raw)) == 1


def test_parse_windows_updates_json():
    from app.windows_inventory import parse_windows_updates_json

    raw = """{
      "pending_count": 2,
      "pending": [
        {"title": "2024-08 Cumulative Update for Windows 11", "kb": "KB5041585", "severity": "Critical"},
        {"title": "Microsoft Defender Antivirus", "kb": "KB2267602", "severity": "Moderate"}
      ],
      "hotfixes": [{"id": "KB5034123", "name": "Security Update", "installed": "2024-01-09"}],
      "last_patch": "2024-01-09"
    }"""
    parsed = parse_windows_updates_json(raw)
    assert parsed["pending_count"] == 2
    assert parsed["pending"][0]["kb"] == "KB5041585"
    assert parsed["hotfixes"][0]["id"] == "KB5034123"


def test_ingest_windows_updates_mocked():
    from app.windows_inventory import ingest_local_windows_updates

    probe = {
        "platform": "windows",
        "host": "LAB-PC",
        "pending_count": 1,
        "pending": [{"title": "Cumulative Update", "kb": "KB5041585", "severity": "Critical"}],
        "hotfixes": [{"id": "KB5034123", "name": "Security Update", "installed": "2024-01-09"}],
        "last_patch": "2024-01-09",
    }
    with patch("app.windows_inventory.probe_windows_updates", return_value=probe):
        out = ingest_local_windows_updates("test-wu-user")
    assert out["ingested"] >= 2
    assert out["pending"] == 1


def test_ingest_control_panel_mocked():
    probe = {
        "platform": "windows",
        "host": "LAB-PC",
        "manager": "control-panel",
        "count": 2,
        "programs": [
            {"name": "Google Chrome", "version": "120.0", "publisher": "Google LLC", "install_date": "20240115"},
            {"name": "Python 3.11", "version": "3.11.9", "publisher": "Python Software Foundation", "install_date": ""},
        ],
        "detail": "",
    }
    with patch("app.windows_inventory.probe_windows_control_panel", return_value=probe):
        out = ingest_local_control_panel_software("test-cp-user")
    assert out["ingested"] == 2
    assert out["total"] == 2
