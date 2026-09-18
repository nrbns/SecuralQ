"""Every scan/test type should leave a real, reportable trace behind.

Before this, only network scans (nmap/nuclei/zap via app.scan_engine) got a
row in the `scans` table, a downloadable Markdown/PDF report, and coverage
by the existing scan archive/delete paths. A SecuraIQ Code run (code_scan /
semgrep / codeql), a Windows hardening audit, and a cloud posture sync all
wrote vulnerabilities straight into the register with no persisted scan
record at all — finished, the run left no trace anywhere outside the live
findings it happened to create, and never showed up in the Reports page.

These tests cover the shared helpers in app.jobs (_start_report_scan /
_finish_report_scan, used by the hardening-audit and cloud-posture-sync job
handlers) and the code-scan-specific closer in app.sonarqube_api
(_finish_code_scan / _build_code_scan_report_md), without needing a real
Windows host, cloud credentials, or a real SAST tool run.
"""

from __future__ import annotations

from pathlib import Path

from tests._http_test_utils import configure_isolated_settings


def _setup(tmp_path, monkeypatch, username="reports_wiring_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    u = register_user(username, "password123", role="admin")
    return u.id


def test_start_report_scan_creates_running_row(tmp_path, monkeypatch):
    uid = _setup(tmp_path, monkeypatch)
    from app.jobs import _start_report_scan
    from app.scan_engine.models import get_scan

    scan = _start_report_scan(uid, target="localhost (Windows hardening)", scanner="hardeningkitty")
    assert scan is not None
    row = get_scan(scan["id"])
    assert row["status"] == "running"
    assert row["scanner"] == "hardeningkitty"
    assert row["target"] == "localhost (Windows hardening)"


def test_finish_report_scan_success_writes_report_and_completes(tmp_path, monkeypatch):
    uid = _setup(tmp_path, monkeypatch)
    from app.jobs import _finish_report_scan, _start_report_scan
    from app.scan_engine.models import get_scan

    scan = _start_report_scan(uid, target="Cloud posture (AWS/Azure/GCP)", scanner="cloud_posture")
    _finish_report_scan(
        scan,
        ok=True,
        summary={"findings_created": 7},
        summary_lines=["Findings imported: 7", "aws: ok — 7 finding(s)"],
    )
    row = get_scan(scan["id"])
    assert row["status"] == "completed"
    assert row["completed_at"] is not None
    assert row["summary"]["findings_created"] == 7

    report = Path(row["evidence_dir"]) / "report.md"
    assert report.is_file()
    text = report.read_text(encoding="utf-8")
    assert "cloud_posture" in text
    assert "Findings imported: 7" in text
    assert "aws: ok" in text


def test_finish_report_scan_failure_marks_failed_with_error(tmp_path, monkeypatch):
    uid = _setup(tmp_path, monkeypatch)
    from app.jobs import _finish_report_scan, _start_report_scan
    from app.scan_engine.models import get_scan

    scan = _start_report_scan(uid, target="localhost (Windows hardening)", scanner="hardeningkitty")
    _finish_report_scan(scan, ok=False, error="PowerShell not found on PATH")
    row = get_scan(scan["id"])
    assert row["status"] == "failed"
    assert "PowerShell not found" in row["error"]

    report = Path(row["evidence_dir"]) / "report.md"
    assert report.is_file()
    assert "PowerShell not found" in report.read_text(encoding="utf-8")


def test_finish_report_scan_is_a_noop_without_a_scan(tmp_path, monkeypatch):
    """_start_report_scan can legitimately return None (best-effort — never
    blocks the real job); _finish_report_scan must tolerate that silently."""
    _setup(tmp_path, monkeypatch)
    from app.jobs import _finish_report_scan

    _finish_report_scan(None, ok=True)  # must not raise


def test_completed_scan_of_any_scanner_appears_in_reports_catalog(tmp_path, monkeypatch):
    uid = _setup(tmp_path, monkeypatch)
    from app.jobs import _finish_report_scan, _start_report_scan
    from app.ops import reports_catalog

    scan = _start_report_scan(uid, target="localhost (Windows hardening)", scanner="hardeningkitty")
    _finish_report_scan(scan, ok=True, summary={"findings_created": 3}, summary_lines=["Failed: 3"])

    catalog = reports_catalog(uid)
    scan_ids = {i.get("scan_id") for i in catalog["reports"] if i.get("scan_id")}
    assert scan["id"] in scan_ids


def test_finish_code_scan_success_writes_tool_output_report(tmp_path, monkeypatch):
    uid = _setup(tmp_path, monkeypatch)
    from app.scan_engine.models import create_scan, get_scan
    from app.sonarqube_api import _finish_code_scan

    scan = create_scan(user_id=uid, target="E:/Regen Browser", scanner="code_scan", profile="full", authorized=True)
    payload = {
        "ok": True,
        "requested": ["code_scan"],
        "authorized": True,
        "vulnerabilities_persisted": {"created": 44, "asset_name": "Regen Browser"},
        "runs": [
            {
                "tool": "code_scan",
                "ok": True,
                "output": "Code security scan of E:/Regen Browser: 1551 file(s) scanned, 64 possible secret(s)",
            }
        ],
    }
    _finish_code_scan(scan["id"], payload)

    row = get_scan(scan["id"])
    assert row["status"] == "completed"
    assert row["summary"]["findings_created"] == 44
    assert row["summary"]["asset_name"] == "Regen Browser"

    report = Path(row["evidence_dir"]) / "report.md"
    assert report.is_file()
    text = report.read_text(encoding="utf-8")
    assert "44" in text
    assert "Regen Browser" in text
    assert "1551 file(s) scanned" in text


def test_finish_code_scan_without_done_event_marks_failed_not_stuck(tmp_path, monkeypatch):
    """If the stream breaks before a 'done' event ever arrives (e.g. an
    unhandled exception inside iter_security_tools), the scan must still
    close out as failed rather than being left at 'running' forever — the
    same class of bug fixed earlier this session for network scans."""
    uid = _setup(tmp_path, monkeypatch)
    from app.scan_engine.models import create_scan, get_scan
    from app.sonarqube_api import _finish_code_scan

    scan = create_scan(user_id=uid, target="/some/path", scanner="code_scan", profile="full", authorized=True)
    _finish_code_scan(scan["id"], None)

    row = get_scan(scan["id"])
    assert row["status"] == "failed"
    assert row["error"]


def test_finish_code_scan_does_not_reopen_an_already_terminal_scan(tmp_path, monkeypatch):
    uid = _setup(tmp_path, monkeypatch)
    from app.scan_engine.models import create_scan, get_scan, update_scan
    from app.sonarqube_api import _finish_code_scan
    from app.db import now

    scan = create_scan(user_id=uid, target="/some/path", scanner="code_scan", profile="full", authorized=True)
    update_scan(scan["id"], status="completed", completed_at=now(), summary_json={"findings_created": 1})
    _finish_code_scan(scan["id"], {"ok": False, "error": "should be ignored"})

    row = get_scan(scan["id"])
    assert row["status"] == "completed"
    assert row["summary"]["findings_created"] == 1
