#!/usr/bin/env python3
"""Measure (or template) Redis Sentinel lab failover timing.

Usage:
  python scripts/sentinel_failover_measure.py --dry-run
  python scripts/sentinel_failover_measure.py --record

Does not stop Docker for you — operator stops redis-primary, then re-runs
--record to append timing. Never invents HA certification claims.
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOTE = ROOT / "docs" / "ops" / "SENTINEL-FAILOVER-LAB.md"
LOG = ROOT / "data" / "ops" / "sentinel_failover_measurements.jsonl"


def _check_sentinel() -> dict:
    try:
        from app.redis_client import reconnect_after_failover, redis_ping

        t0 = time.perf_counter()
        reconnect_after_failover()
        ok = False
        try:
            ok = bool(redis_ping())
        except Exception:
            ok = False
        ms = round((time.perf_counter() - t0) * 1000, 1)
        return {"ok": ok, "reconnect_ms": ms, "error": None if ok else "ping_failed"}
    except Exception as exc:
        return {"ok": False, "reconnect_ms": None, "error": str(exc)[:300]}


def dry_run() -> int:
    print(
        json.dumps(
            {
                "ok": True,
                "mode": "dry_run",
                "note": str(NOTE.relative_to(ROOT)),
                "disclaimer": "lab stub — not commercial HA certification",
                "steps": [
                    "docker compose --profile redis-ha up -d",
                    "python scripts/realtime_phase1_proof.py --check-sentinel",
                    "docker compose stop redis-primary",
                    "python scripts/sentinel_failover_measure.py --record",
                ],
            },
            indent=2,
        )
    )
    return 0


def record() -> int:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "check": _check_sentinel(),
        "disclaimer": "lab / measured ops proof — not commercial HA certification",
    }
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
    print(json.dumps(row, indent=2))
    if NOTE.is_file():
        append = (
            f"\n### Measurement {row['ts_utc']}\n\n"
            f"- reconnect_ok: `{row['check'].get('ok')}`\n"
            f"- reconnect_ms: `{row['check'].get('reconnect_ms')}`\n"
            f"- error: `{row['check'].get('error')}`\n"
            f"- log: `data/ops/sentinel_failover_measurements.jsonl`\n"
        )
        text = NOTE.read_text(encoding="utf-8")
        if row["ts_utc"] not in text:
            NOTE.write_text(text.rstrip() + "\n" + append, encoding="utf-8")
    return 0 if row["check"].get("ok") else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--record", action="store_true")
    args = ap.parse_args()
    if args.record:
        return record()
    return dry_run()


if __name__ == "__main__":
    raise SystemExit(main())
