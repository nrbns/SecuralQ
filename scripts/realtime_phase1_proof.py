#!/usr/bin/env python3
"""Phase 1 realtime proof — once-only + Sentinel runbook (release gate companion).

CI proves once-only / XAUTOCLAIM / SSE replay via pytest
(``tests/test_realtime_phase1_proof.py`` + acceptance).

This script documents and optionally checks the Redis Sentinel lab stub.

Usage:
  python scripts/realtime_phase1_proof.py --document
  python scripts/realtime_phase1_proof.py --simulate
  python scripts/realtime_phase1_proof.py --check-sentinel
  python scripts/realtime_phase1_proof.py --check-client

Disclaimer: lab / measured ops proof — not a 5k-agent or commercial HA claim.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

DISCLAIMER = "lab / measured ops proof — not commercial HA certification"


def document() -> int:
    print(
        f"""
SecuraIQ Phase 1 realtime proof
===============================
{DISCLAIMER}

A) CI release gate (always)
---------------------------
  pytest -v \\
    tests/test_realtime_acceptance_local.py \\
    tests/test_realtime_phase1_proof.py \\
    tests/test_stream_durability.py \\
    tests/test_redis_dlq_ops.py \\
    tests/test_realtime_bus.py \\
    tests/test_realtime_rt02_rt06.py

  Golden loop (firewall FAIL→approve→PASS→verified):
    python scripts/realtime_acceptance_demo.py --local

B) Multi-worker once-only (lab)
-------------------------------
  1. docker compose --profile redis up -d
     # or HA stub:
     docker compose --profile redis-ha up -d
     export REDIS_SENTINEL_HOSTS=127.0.0.1:26379
     export REDIS_SENTINEL_MASTER=mymaster
     # leave REDIS_URL empty when using Sentinel

  2. uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 3

  3. Confirm Realtime Health: mode=redis_streams_fanout, SSE clients > 0

  4. Publish one event (agent check-in / scan). Each browser receives it;
     security handlers run once per event_id (RT-06 ledger).

C) Measured Sentinel failover (ops)
-----------------------------------
  1. docker compose --profile redis-ha up -d
  2. python scripts/realtime_phase1_proof.py --check-sentinel
  3. XADD a test event while app workers are up
  4. docker compose stop redis-primary
     # Sentinel promotes replica (quorum=1 lab stub)
  5. python scripts/realtime_phase1_proof.py --check-sentinel
     # expect ping ok after reconnect_after_failover
  6. Confirm pending reclaim: worker B claims idle messages (XAUTOCLAIM)
  7. Confirm SSE clients still receive new events (no soft-poll)

Proof chain:
  Agent → Redis Stream → Consumer A dies → Consumer B XAUTOCLAIM →
  process once → SSE → browser

This is NOT:
  - Redis Cluster / multi-AZ certification
  - 5k agent load proof
  - mTLS / signed installer commercial claim
""".strip()
    )
    return 0


def simulate() -> int:
    """In-process once-only simulation (no Redis)."""
    td_obj = tempfile.TemporaryDirectory()
    td = td_obj.name
    try:
        os.environ["DATA_DIR"] = td
        os.environ["DATABASE_URL"] = ""
        try:
            from app.config import settings

            settings.data_dir = td
            settings.database_url = ""
            settings.auth_enabled = True
            settings.deployment_mode = "lab"
        except Exception as exc:
            print(json.dumps({"ok": False, "error": f"settings: {exc}"}))
            return 2

        from app import event_idempotency, event_processor
        from app.db import reset_conn_for_tests
        from app.realtime.once_only import prove_consumer_failover_once_only
        from app.tenancy import ensure_tenant_schema

        reset_conn_for_tests()
        ensure_tenant_schema()
        event_idempotency.clear_processed_for_tests()
        event_idempotency.ensure_processed_events_schema()

        actions: list[str] = []

        def _act(ev: dict) -> None:
            actions.append(str(ev.get("event_id")))

        event_processor.HANDLERS["control.failed"] = _act
        ev = {"type": "control.failed", "event_id": "sim-once-1", "user_id": "u"}
        event_processor.process_event(ev)
        event_processor.process_event(ev)
        event_processor.process_event(ev)

        async def _reclaim_sim() -> dict:
            side: list[str] = []

            def _h(e: dict) -> None:
                side.append(str(e.get("event_id")))

            event_idempotency.clear_processed_for_tests()
            event_processor.HANDLERS["vuln"] = _h
            event = {
                "type": "vuln",
                "event_id": "sim-reclaim-1",
                "user_id": "u",
            }
            client = AsyncMock()
            client.xautoclaim = AsyncMock(
                return_value=(
                    "0-0",
                    [("1-0", {"payload": json.dumps(event)})],
                )
            )
            client.xpending_range = AsyncMock(return_value=[{"times_delivered": 1}])
            client.xack = AsyncMock()
            client.xadd = AsyncMock()
            result = await prove_consumer_failover_once_only(
                reclaim_pending=event_processor._reclaim_pending,
                process_event=event_processor.process_event,
                client=client,
                stream="securaiq:events",
                event=event,
                side_effects=side,
            )
            return {
                "ok": result.ok,
                "side_effect_count": result.side_effect_count,
                "reclaim_handled": result.reclaim_handled,
                "detail": result.detail,
                "steps": result.steps,
            }

        reclaim = asyncio.run(_reclaim_sim())
        out = {
            "ok": actions == ["sim-once-1"] and reclaim.get("ok") is True,
            "disclaimer": DISCLAIMER,
            "duplicate_delivery_actions": actions,
            "reclaim": reclaim,
        }
        print(json.dumps(out, indent=2, default=str))
        return 0 if out["ok"] else 2
    finally:
        try:
            from app.db import reset_conn_for_tests

            reset_conn_for_tests()
        except Exception:
            pass
        try:
            td_obj.cleanup()
        except Exception:
            pass


def check_client() -> int:
    try:
        from app.realtime.sentinel_ops import ping_master
        from app.redis_client import describe_backend, redis_enabled
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    out = {
        "ok": True,
        "disclaimer": DISCLAIMER,
        "enabled": redis_enabled(),
        "backend": describe_backend(),
        "ping": ping_master(),
    }
    if redis_enabled() and not out["ping"].get("ok"):
        out["ok"] = False
    print(json.dumps(out, indent=2))
    return 0 if out["ok"] else 2


def check_sentinel() -> int:
    try:
        from app.realtime.sentinel_ops import sentinel_ready_report
        from app.redis_client import reconnect_after_failover
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    report = sentinel_ready_report()
    reconnect_after_failover()
    report["after_reconnect"] = sentinel_ready_report()
    report["disclaimer"] = DISCLAIMER
    configured = bool(report.get("sentinel_configured"))
    reachable = bool(report.get("reachable")) or bool(
        (report.get("after_reconnect") or {}).get("reachable")
    )
    report["ok"] = configured and reachable
    print(json.dumps(report, indent=2, default=str))
    if not configured:
        return 3
    return 0 if reachable else 2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--document", action="store_true")
    ap.add_argument("--simulate", action="store_true", help="In-process once-only proof")
    ap.add_argument("--check-client", action="store_true")
    ap.add_argument("--check-sentinel", action="store_true")
    args = ap.parse_args()
    if args.simulate:
        return simulate()
    if args.check_client:
        return check_client()
    if args.check_sentinel:
        return check_sentinel()
    return document()


if __name__ == "__main__":
    sys.exit(main())
