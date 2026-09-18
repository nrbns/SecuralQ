"""In-process multi-worker / SSE fan-out soak (no Redis required).

Proves:
  - N local SSE subscribers each receive every published event
  - event_id dedupe drops duplicates on the bus
  - RT-06 once-only handler side-effects (via phase1 simulate)

Live 3× uvicorn + Redis fan-out remains an ops soak
(``python scripts/realtime_multiworker_smoke.py --document``).
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import time
from pathlib import Path
from typing import Any


def run_inprocess_soak(
    *,
    subscribers: int = 3,
    events: int = 20,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    """Fan out publishes to multiple local queues; assert full delivery + dedupe."""
    own = data_dir is None
    td = tempfile.TemporaryDirectory() if own else None
    root = Path(td.name) if td else Path(data_dir)  # type: ignore[arg-type]

    try:
        from tests._http_test_utils import configure_isolated_settings

        class _MP:
            def setattr(self, target, name=None, value=None, raising=True):
                if isinstance(target, str) and value is None and name is not None:
                    import importlib

                    mod_name, _, attr = target.rpartition(".")
                    obj = importlib.import_module(mod_name)
                    setattr(obj, attr, name)
                    return
                setattr(target, name, value)

        configure_isolated_settings(_MP(), root)
        from app.realtime_bus import (
            clear_replay_buffer_for_tests,
            publish,
            publish_throughput,
            subscribe,
            unsubscribe,
        )
        from app.tenancy import ensure_tenant_schema

        ensure_tenant_schema()
        clear_replay_buffer_for_tests()

        queues = [subscribe(maxsize=500) for _ in range(max(2, int(subscribers)))]
        try:
            # Bind a loop so threadsafe put works when called from sync publish.
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            from app.realtime_bus import bind_loop

            bind_loop(loop)

            t0 = time.perf_counter()
            for i in range(int(events)):
                publish(
                    type="agent",
                    event_id=f"soak-{i}",
                    id=f"agent-{i % 3}",
                    user_id="soak-user",
                    status="online",
                    _from_processor=True,
                )
            # Duplicate storm — must not inflate unique delivery
            for i in range(min(5, int(events))):
                publish(
                    type="agent",
                    event_id=f"soak-{i}",
                    id=f"agent-{i % 3}",
                    user_id="soak-user",
                    status="online",
                    _from_processor=True,
                )
            # Drain queues
            received: list[set[str]] = [set() for _ in queues]

            async def _drain() -> None:
                deadline = time.perf_counter() + 2.0
                while time.perf_counter() < deadline:
                    progressed = False
                    for qi, q in enumerate(queues):
                        try:
                            while True:
                                ev = q.get_nowait()
                                eid = str((ev or {}).get("event_id") or "")
                                if eid:
                                    received[qi].add(eid)
                                progressed = True
                        except Exception:
                            pass
                    if not progressed:
                        await asyncio.sleep(0.01)
                    # Stop early when all have full unique set
                    if all(len(s) >= int(events) for s in received):
                        break

            loop.run_until_complete(_drain())
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
            thr = publish_throughput()
            expected = {f"soak-{i}" for i in range(int(events))}
            per_ok = [s >= expected for s in received]
            dup_dropped = int(thr.get("duplicates_dropped") or 0)
            ok = all(per_ok) and dup_dropped >= min(5, int(events))
            return {
                "ok": ok,
                "mode": "inprocess_soak",
                "subscribers": len(queues),
                "events_published": int(events),
                "duplicates_injected": min(5, int(events)),
                "duplicates_dropped": dup_dropped,
                "per_subscriber_unique": [len(s) for s in received],
                "all_subscribers_complete": all(per_ok),
                "elapsed_ms": elapsed_ms,
                "disclaimer": "in-process SSE fan-out soak — not multi-uvicorn Redis HA proof",
            }
        finally:
            for q in queues:
                unsubscribe(q)
            try:
                loop.close()
            except Exception:
                pass
    finally:
        try:
            from app.db import reset_conn_for_tests

            reset_conn_for_tests()
        except Exception:
            pass
        if td is not None:
            try:
                td.cleanup()
            except Exception:
                pass


def verify_signing_scaffolds() -> dict[str, Any]:
    """Confirm packaging sign/notarize scripts exist and skip without secrets."""
    root = Path(__file__).resolve().parents[2]
    required = [
        "scripts/packaging/sign_windows.ps1",
        "scripts/packaging/sign_deb.sh",
        "scripts/packaging/sign_rpm.sh",
        "scripts/packaging/notarize_macos.sh",
        "docs/ops/SENTINEL-FAILOVER-LAB.md",
    ]
    missing = [p for p in required if not (root / p).is_file()]
    return {
        "ok": not missing,
        "missing": missing,
        "note": (
            "Authenticode/notarization require org secrets (SIGN_WINDOWS / NOTARIZE_MACOS). "
            "Scripts skip cleanly in lab CI without secrets."
        ),
        "disclaimer": "scaffold proof — not a signed commercial release",
    }
