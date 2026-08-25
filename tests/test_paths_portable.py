"""Portable project-root path resolution."""

from __future__ import annotations

from pathlib import Path

from app.paths import project_root, resolve_path


def test_project_root_is_repo():
    root = project_root()
    assert (root / "run.py").is_file()
    assert (root / "app" / "config.py").is_file()


def test_resource_root_has_static_and_frameworks():
    from app.paths import resource_root

    root = resource_root()
    assert (root / "static" / "index.html").is_file()
    assert (root / "data" / "frameworks").is_dir()


def test_resolve_path_relative_to_root(tmp_path, monkeypatch):
    # Relative paths are under project root (not cwd)
    root = project_root()
    resolved = resolve_path("./data")
    assert resolved == (root / "data").resolve()
    abs_p = resolve_path(tmp_path / "elsewhere")
    assert abs_p == (tmp_path / "elsewhere").resolve()


def test_settings_data_dir_is_absolute():
    from app.config import settings

    p = Path(settings.data_dir)
    assert p.is_absolute(), settings.data_dir
