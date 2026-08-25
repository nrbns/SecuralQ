"""Lab zero-start archives scans then loads an empty workspace."""

from __future__ import annotations

import importlib
from pathlib import Path


def test_zero_start_archives_then_empties(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WORKSPACE_ZERO_START", "true")
    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("DATABASE_URL", "")

    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)

    from app.archive import find_archived_scan
    from app.enterprise import apply_workspace_zero_start
    from app.scan_engine.models import create_scan, ensure_scans_schema, list_scans

    ensure_scans_schema()
    scan = create_scan(
        user_id="local",
        target="127.0.0.1",
        scanner="securaiq",
        authorized=True,
    )
    ev = Path(scan["evidence_dir"])
    ev.mkdir(parents=True, exist_ok=True)
    (ev / "report.md").write_text("# prior scan\n", encoding="utf-8")

    result = apply_workspace_zero_start()
    assert result is not None
    assert list_scans("local") == []
    assert find_archived_scan(scan["id"]) is not None
