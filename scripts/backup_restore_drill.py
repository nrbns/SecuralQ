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
import os
import shutil
import sqlite3
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


def _ops_log_dir() -> Path:
    override = (os.environ.get("SECURAIQ_OPS_LOG_DIR") or "").strip()
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[1] / "data" / "ops"


def _persist(row: dict) -> Path:
    from datetime import datetime, timezone

    log = _ops_log_dir() / "ha_dr_measurements.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    payload = {"ts_utc": datetime.now(timezone.utc).isoformat(), **row}
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, default=str) + "\n")
    return log


def run_drill(*, keep: bool = False, persist: bool = False) -> dict:
    root = Path(tempfile.mkdtemp(prefix="securaiq-drill-"))
    src_data = root / "src_data"
    backup = root / "backup"
    dest_data = root / "dest_data"
    src_db = src_data / "securaiq.db"
    backup.mkdir(parents=True)
    dest_data.mkdir(parents=True)

    _create_source_db(src_db)
    src_bytes = int(src_db.stat().st_size)

    t0 = time.perf_counter()
    # Backup = file copy (same as scripts/backup fallback without sqlite3 CLI)
    shutil.copy2(src_db, backup / "securaiq.db")
    backup_ms = round((time.perf_counter() - t0) * 1000, 3)

    t1 = time.perf_counter()
    shutil.copy2(backup / "securaiq.db", dest_data / "securaiq.db")
    restore_ms = round((time.perf_counter() - t1) * 1000, 3)

    t2 = time.perf_counter()
    err = _verify_restored(dest_data / "securaiq.db")
    verify_ms = round((time.perf_counter() - t2) * 1000, 3)

    # RTO = restore + verify (usable DB). RPO = 0 for a closed-file copy.
    rto_ms = round(restore_ms + verify_ms, 3)
    rpo_ms = 0.0
    result = {
        "ok": err is None,
        "error": err,
        "marker": MARKER_VALUE,
        "src_bytes": src_bytes,
        "backup_ms": backup_ms,
        "restore_ms": restore_ms,
        "verify_ms": verify_ms,
        "rto_ms": rto_ms,
        "rpo_ms": rpo_ms,
        "src_db": str(src_db),
        "backup_db": str(backup / "securaiq.db"),
        "restored_db": str(dest_data / "securaiq.db"),
        "disclaimer": (
            "SQLite closed-file copy on this host. "
            "RTO is restore+verify ms — not API/Redis/Postgres cluster kill. "
            "Postgres pg_dump restore remains ops-owned."
        ),
        "kept_dir": str(root) if keep else None,
    }
    if persist:
        result["recorded"] = str(_persist({k: v for k, v in result.items() if k != "kept_dir"}))
    if not keep:
        shutil.rmtree(root, ignore_errors=True)
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keep", action="store_true", help="Keep temp dirs after drill")
    ap.add_argument("--record", action="store_true", help="Append timings to data/ops/ha_dr_measurements.jsonl")
    args = ap.parse_args()
    result = run_drill(keep=args.keep, persist=args.record)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
