#!/usr/bin/env python3
"""Multi-worker / Redis fan-out smoke checklist (not HA proof).

Usage:
  python scripts/realtime_multiworker_smoke.py --document
  python scripts/realtime_multiworker_smoke.py --check-client

Prints operator steps to run two uvicorn workers against Redis Streams
fan-out, or verifies the local Redis client factory mode.
"""

from __future__ import annotations

import argparse
import json
import sys


def document() -> int:
    print(
        """
SecuraIQ multi-worker realtime smoke (lab)
==========================================

1) Start Redis (single or HA stub):
     docker compose --profile redis up -d
   # or Sentinel lab stub:
     docker compose --profile redis-ha up -d
     # REDIS_SENTINEL_HOSTS=redis-sentinel:26379
     # REDIS_SENTINEL_MASTER=mymaster

2) Run two API workers with the same REDIS_URL / Sentinel settings:
     uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 2

3) Open two browsers to Mission Control; confirm Realtime Health shows
   mode=redis_streams_fanout and SSE clients > 0.

4) Trigger a publish (scan / agent check-in / vuln import) and confirm both
   browsers receive the event without soft-polling.

5) Optional DLQ ops (admin):
     GET  /api/admin/realtime/dlq
     POST /api/admin/realtime/dlq/replay
     POST /api/admin/realtime/dlq/purge

This is NOT:
  - Redis Sentinel failover certification
  - 5k agent load proof
  - mTLS / owned-host closed-loop proof

Use scripts/realtime_acceptance_demo.py --local for the firewall/Defender/SSH loop.
""".strip()
    )
    return 0


def check_client() -> int:
    try:
        from app.redis_client import describe_backend, redis_enabled, get_sync_redis
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    desc = describe_backend()
    out = {"ok": True, "enabled": redis_enabled(), "backend": desc, "ping": None}
    if redis_enabled():
        client = get_sync_redis(decode_responses=True, socket_connect_timeout=1.5)
        if client is None:
            out["ok"] = False
            out["ping"] = "client_unavailable"
        else:
            try:
                out["ping"] = bool(client.ping())
            except Exception as exc:
                out["ok"] = False
                out["ping"] = str(exc)[:200]
            finally:
                try:
                    client.close()
                except Exception:
                    pass
    print(json.dumps(out, indent=2))
    return 0 if out["ok"] else 2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--document", action="store_true", help="Print multi-worker smoke steps")
    ap.add_argument("--check-client", action="store_true", help="Probe redis_client factory")
    args = ap.parse_args()
    if args.check_client:
        return check_client()
    return document()


if __name__ == "__main__":
    sys.exit(main())
