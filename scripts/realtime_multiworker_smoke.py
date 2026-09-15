#!/usr/bin/env python3
"""Multi-worker / Redis fan-out smoke checklist + Phase 1 pointers.

Usage:
  python scripts/realtime_multiworker_smoke.py --document
  python scripts/realtime_multiworker_smoke.py --check-client
  python scripts/realtime_multiworker_smoke.py --simulate

For the full Phase 1 release gate + Sentinel runbook see:
  python scripts/realtime_phase1_proof.py --document
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def document() -> int:
    print(
        """
SecuraIQ multi-worker realtime smoke (lab)
==========================================

1) Start Redis (single or HA stub):
     docker compose --profile redis up -d
   # or Sentinel lab stub:
     docker compose --profile redis-ha up -d
     # REDIS_SENTINEL_HOSTS=127.0.0.1:26379
     # REDIS_SENTINEL_MASTER=mymaster

2) Run three API workers with the same REDIS_URL / Sentinel settings:
     uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 3

3) Open two browsers to Mission Control; confirm Realtime Health shows
   mode=redis_streams_fanout and SSE clients > 0.

4) Trigger a publish (scan / agent check-in / vuln import) and confirm both
   browsers receive the event without soft-polling. Security handlers run
   once per event_id (RT-06).

5) Optional DLQ ops (admin):
     GET  /api/admin/realtime/dlq
     POST /api/admin/realtime/dlq/replay
     POST /api/admin/realtime/dlq/purge

6) Phase 1 release gate:
     python scripts/realtime_phase1_proof.py --simulate
     python scripts/realtime_acceptance_demo.py --local
     pytest -v tests/test_realtime_phase1_proof.py tests/test_realtime_acceptance_local.py

This is NOT:
  - Redis Sentinel failover certification (use phase1_proof --document for ops steps)
  - 5k agent load proof
  - mTLS / owned-host closed-loop proof

Use scripts/realtime_acceptance_demo.py --local for the firewall/Defender/SSH loop.
""".strip()
    )
    return 0


def check_client() -> int:
    try:
        from app.realtime.sentinel_ops import ping_master
        from app.redis_client import describe_backend, redis_enabled
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    desc = describe_backend()
    out = {"ok": True, "enabled": redis_enabled(), "backend": desc, "ping": None}
    if redis_enabled():
        ping = ping_master()
        out["ping"] = ping
        out["ok"] = bool(ping.get("ok"))
    print(json.dumps(out, indent=2))
    return 0 if out["ok"] else 2


def simulate() -> int:
    from scripts.realtime_phase1_proof import simulate as phase1_simulate

    return phase1_simulate()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--document", action="store_true", help="Print multi-worker smoke steps")
    ap.add_argument("--check-client", action="store_true", help="Probe redis_client factory")
    ap.add_argument("--simulate", action="store_true", help="Run Phase 1 once-only simulation")
    args = ap.parse_args()
    if args.check_client:
        return check_client()
    if args.simulate:
        return simulate()
    return document()


if __name__ == "__main__":
    sys.exit(main())
