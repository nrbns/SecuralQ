#!/usr/bin/env python3
"""Reclaim regenerable workspace junk. Never deletes .venv, DBs, or model caches.

Usage:
  python scripts/compress_workspace.py
"""

from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    for child in path.rglob("*"):
        if child.is_file():
            try:
                total += child.stat().st_size
            except OSError:
                pass
    return total


def _rm(path: Path) -> int:
    n = _size(path)
    if not path.exists():
        return 0
    try:
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)
    except OSError:
        return 0
    return n if not path.exists() else 0


def main() -> int:
    removed: list[dict[str, object]] = []
    bytes_freed = 0
    targets = [
        _ROOT / "securaiq-agent" / "target",
        _ROOT / "build",
        _ROOT / "dist" / "SecuraIQ.exe.bak-131400",
        _ROOT / "data" / "_ui_audit" / "chrome-profile",
        _ROOT / "data" / "_live_verify_iso",
        _ROOT / "data" / "run-stdout.log",
        _ROOT / "data" / "_server_restart.log",
        _ROOT / ".pytest_cache",
        _ROOT / ".ruff_cache",
        Path.home() / "AppData" / "Local" / "Temp" / "pytest-of-Nrb",
    ]
    for path in _ROOT.glob("data/_*.txt"):
        targets.append(path)
    for path in _ROOT.rglob("__pycache__"):
        if ".venv" in path.parts or "site-packages" in path.parts:
            continue
        targets.append(path)
    temp = Path.home() / "AppData" / "Local" / "Temp"
    if temp.is_dir():
        targets.extend(temp.glob("securaiq-drill-*"))
        targets.extend(temp.glob("pytest-of-*"))

    seen: set[str] = set()
    for path in targets:
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen:
            continue
        seen.add(key)
        n = _rm(path)
        if n:
            bytes_freed += n
            removed.append({"path": str(path), "mb": round(n / 1e6, 1)})

    try:
        import subprocess

        pip = subprocess.run(
            [sys.executable, "-m", "pip", "cache", "purge"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        removed.append({"path": "pip-cache", "ok": pip.returncode == 0})
    except Exception as exc:
        removed.append({"path": "pip-cache", "error": str(exc)[:160]})

    row = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "ok": True,
        "freed_mb": round(bytes_freed / 1e6, 1),
        "removed": removed[:80],
        "disclaimer": "Did not delete .venv, data/*.db, HuggingFace models, or current dist exe.",
    }
    print(json.dumps(row, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
