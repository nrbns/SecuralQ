"""First-run bootstrap: .env + data dirs without wiping anything."""

from __future__ import annotations

from pathlib import Path


def test_ensure_env_file_copies_example(tmp_path, monkeypatch):
    from app.bootstrap import ensure_env_file, project_root

    example = project_root() / ".env.example"
    assert example.is_file()
    dest = tmp_path / "clone"
    dest.mkdir()
    (dest / ".env.example").write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    result = ensure_env_file(dest)
    assert result["created"] is True
    assert Path(result["path"]).is_file()
    again = ensure_env_file(dest)
    assert again["created"] is False


def test_ensure_data_dirs_creates_layout():
    from app.bootstrap import ensure_data_dirs

    layout = ensure_data_dirs()
    data = Path(layout.get("data") or layout.get("evidence") or "").parent
    # evidence path is .../data/evidence/scans
    root = Path(layout["data"]) if "data" in layout else Path(layout["evidence"]).parents[1]
    assert root.is_dir()
