#!/usr/bin/env python3
"""Automated SQLite backup → restore drill (#229).

Creates a temp DB with a marker row, copies it as a "backup", restores into a
fresh data dir, and verifies the marker. Safe for CI — never touches production data.

Usage:
  python scripts/backup_restore_drill.py
  python scripts/backup_restore_drill.py --keep  # leave temp dirs for inspection
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

MARKER_TABLE = "drill_marker"
MARKER_VALUE = "securaiq-backup-restore-drill-ok"


def _create_source_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS {MARKER_TABLE} (id INTEGER PRIMARY KEY, note TEXT NOT NULL, created_at REAL)"
    )
    conn.execute(
        f"INSERT INTO {MARKER_TABLE} (id, note, created_at) VALUES (1, ?, ?)",
        (MARKER_VALUE, time.time()),
    )
    conn.commit()
    conn.close()


def _verify_restored(path: Path) -> str | None:
    if not path.is_file():
        return "restored DB missing"
    conn = sqlite3.connect(str(path))
    try:
        row = conn.execute(f"SELECT note FROM {MARKER_TABLE} WHERE id = 1").fetchone()
    except sqlite3.Error as exc:
        return f"query failed: {exc}"
    finally:
        conn.close()
    if not row or row[0] != MARKER_VALUE:
        return f"marker mismatch: {row!r}"
    return None


def run_drill(*, keep: bool = False) -> dict:
    root = Path(tempfile.mkdtemp(prefix="securaiq-drill-"))
    src_data = root / "src_data"
    backup = root / "backup"
    dest_data = root / "dest_data"
    src_db = src_data / "securaiq.db"
    backup.mkdir(parents=True)
    dest_data.mkdir(parents=True)

    _create_source_db(src_db)
    # Backup = file copy (same as scripts/backup fallback without sqlite3 CLI)
    shutil.copy2(src_db, backup / "securaiq.db")
    # Restore
    shutil.copy2(backup / "securaiq.db", dest_data / "securaiq.db")

    err = _verify_restored(dest_data / "securaiq.db")
    result = {
        "ok": err is None,
        "error": err,
        "marker": MARKER_VALUE,
        "src_db": str(src_db),
        "backup_db": str(backup / "securaiq.db"),
        "restored_db": str(dest_data / "securaiq.db"),
        "disclaimer": "lab/CI drill for SQLite path — Postgres pg_dump restore remains ops-owned",
        "kept_dir": str(root) if keep else None,
    }
    if not keep:
        shutil.rmtree(root, ignore_errors=True)
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keep", action="store_true", help="Keep temp dirs after drill")
    args = ap.parse_args()
    result = run_drill(keep=args.keep)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
