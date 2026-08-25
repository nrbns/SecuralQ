"""Project-root path helpers — portable across OS, cwd, and a frozen EXE."""

from __future__ import annotations

import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def resource_root() -> Path:
    """Read-only bundled files (static UI, shipped knowledge, .env.example).

    When frozen this is PyInstaller's extract dir (``sys._MEIPASS``).
    """
    if is_frozen():
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def project_root() -> Path:
    """Writable install / repo root (next to the EXE when frozen)."""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def resolve_path(value: str | Path, *, root: Path | None = None) -> Path:
    """Expand ``~`` and resolve relative paths against the project root."""
    p = Path(value).expanduser()
    if p.is_absolute():
        return p
    return ((root or project_root()) / p).resolve()
