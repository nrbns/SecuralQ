#!/usr/bin/env python3
"""Export SQLite SecuraIQ data to Postgres-friendly SQL (#227).

Does not replace Alembic / init_schema — produces INSERT statements for
user data tables so operators can load into an empty Postgres schema.

Usage:
  python scripts/sqlite_to_postgres_export.py --sqlite data/securaiq.db --out /tmp/export.sql
  python scripts/sqlite_to_postgres_export.py --sqlite data/securaiq.db --json-dir /tmp/export_json

Honesty: schema DDL still comes from app init_schema / Alembic baseline.
This tool moves *rows*, not the full migration history.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path


# Skip volatile / local-only tables
_SKIP = {
    "sqlite_sequence",
    "securaiq_schema_meta",
}


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _sql_literal(val) -> str:
    if val is None:
        return "NULL"
    if isinstance(val, (bytes, bytearray)):
        return r"E'\\x" + val.hex() + "'"
    if isinstance(val, bool):
        return "TRUE" if val else "FALSE"
    if isinstance(val, (int, float)):
        return str(val)
    s = str(val).replace("'", "''")
    return f"'{s}'"


def list_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [r[0] for r in rows if r[0] not in _SKIP]


def export_sql(sqlite_path: Path, out_path: Path) -> dict:
    conn = sqlite3.connect(str(sqlite_path))
    conn.row_factory = sqlite3.Row
    tables = list_tables(conn)
    lines = [
        "-- SecuraIQ SQLite → Postgres row export",
        "-- Apply against a DB that already has schema from init_schema/Alembic.",
        "BEGIN;",
        "",
    ]
    counts: dict[str, int] = {}
    for table in tables:
        cols_info = conn.execute(f"PRAGMA table_info({_quote_ident(table)})").fetchall()
        col_names = [c[1] for c in cols_info]
        if not col_names:
            continue
        rows = conn.execute(f"SELECT * FROM {_quote_ident(table)}").fetchall()
        counts[table] = len(rows)
        if not rows:
            continue
        cols_sql = ", ".join(_quote_ident(c) for c in col_names)
        lines.append(f"-- table {table} ({len(rows)} rows)")
        for row in rows:
            vals = ", ".join(_sql_literal(row[c]) for c in col_names)
            lines.append(f"INSERT INTO {_quote_ident(table)} ({cols_sql}) VALUES ({vals});")
        lines.append("")
    lines.append("COMMIT;")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    conn.close()
    return {"ok": True, "tables": counts, "out": str(out_path)}


def export_json(sqlite_path: Path, out_dir: Path) -> dict:
    conn = sqlite3.connect(str(sqlite_path))
    conn.row_factory = sqlite3.Row
    tables = list_tables(conn)
    out_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for table in tables:
        rows = [dict(r) for r in conn.execute(f"SELECT * FROM {_quote_ident(table)}").fetchall()]
        counts[table] = len(rows)
        (out_dir / f"{table}.json").write_text(
            json.dumps(rows, indent=2, default=str), encoding="utf-8"
        )
    manifest = {"tables": counts, "source": str(sqlite_path)}
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    conn.close()
    return {"ok": True, "tables": counts, "out": str(out_dir)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sqlite", type=Path, default=Path("data/securaiq.db"))
    ap.add_argument("--out", type=Path, default=None, help="Write .sql file")
    ap.add_argument("--json-dir", type=Path, default=None, help="Write per-table JSON")
    args = ap.parse_args()
    if not args.sqlite.is_file():
        print(f"SQLite DB not found: {args.sqlite}", file=sys.stderr)
        return 2
    if not args.out and not args.json_dir:
        args.out = Path("data/exports/sqlite_export.sql")
    results = []
    if args.out:
        results.append(export_sql(args.sqlite, args.out))
    if args.json_dir:
        results.append(export_json(args.sqlite, args.json_dir))
    print(json.dumps({"ok": True, "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
