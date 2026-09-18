"""Fleet load simulator — progressive ladder, not a 100K production claim.

Simulates N agent observations through the in-process fleet aggregator and
(optionally) incremental control recompute hooks. Measures events/sec and
aggregate publish behaviour.

Honest: lab/local measurement only. Filling docs/ops/CAPACITY-LAB.md is required
before any 5K+ capacity claim.

Usage:

  python scripts/fleet_simulator.py --agents 100
  python scripts/fleet_simulator.py --ladder
  python scripts/fleet_simulator.py --agents 1000 --partitions 16
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _run_batch(n_agents: int, *, partitions: int, ticks: int) -> dict[str, Any]:
    from app.realtime.fleet_aggregator import (
        fleet_summary,
        record_agent_observation,
        reset_fleet_state_for_tests,
    )
    from app.realtime.partitioner import partition_id

    reset_fleet_state_for_tests()
    user_id = "sim-user"
    latencies: list[float] = []
    publishes = 0
    t0 = time.perf_counter()
    for tick in range(max(1, ticks)):
        for i in range(n_agents):
            aid = f"sim-agent-{i:06d}"
            org = f"org-{(i % max(1, partitions)):03d}"
            st = "offline" if (i + tick) % 97 == 0 else "online"
            warn = (i + tick) % 211 == 0
            t1 = time.perf_counter()
            out = record_agent_observation(
                user_id,
                aid,
                status=st,
                warning=warn,
                org_id=org,
                publish=True,
            )
            latencies.append((time.perf_counter() - t1) * 1000.0)
            if out.get("ok") and tick == 0 and i < 3:
                # touch partition helper (ensures import path stays warm)
                _ = partition_id(org, aid, partitions=partitions)
        # force a summary read each tick
        fleet_summary(user_id)
    elapsed = time.perf_counter() - t0
    events = n_agents * max(1, ticks)
    summary = fleet_summary(user_id)
    return {
        "agents": n_agents,
        "ticks": ticks,
        "events": events,
        "elapsed_sec": round(elapsed, 4),
        "events_per_sec": round(events / max(elapsed, 1e-9), 2),
        "latency_ms_p50": round(statistics.median(latencies), 4) if latencies else None,
        "latency_ms_p95": round(
            statistics.quantiles(latencies, n=20)[18], 4
        )
        if len(latencies) >= 20
        else (round(max(latencies), 4) if latencies else None),
        "fleet_summary": summary,
        "partitions": partitions,
        "disclaimer": (
            "Lab simulation of aggregator throughput only — not Redis/Postgres/SSE "
            "production capacity. Do not claim 5K+ agents until CAPACITY-LAB is filled."
        ),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--agents", type=int, default=100)
    ap.add_argument("--ticks", type=int, default=2)
    ap.add_argument("--partitions", type=int, default=16)
    ap.add_argument(
        "--ladder",
        action="store_true",
        help="Run 100 → 1k → 5k → 10k (local aggregator only; may be heavy)",
    )
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.ladder:
        sizes = [100, 1000, 5000, 10000]
        rows = []
        for n in sizes:
            rows.append(_run_batch(n, partitions=args.partitions, ticks=1))
        out: dict[str, Any] = {"ladder": rows, "ok": True}
    else:
        out = _run_batch(args.agents, partitions=args.partitions, ticks=args.ticks)
        out["ok"] = True

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        if "ladder" in out:
            for row in out["ladder"]:
                print(
                    f"agents={row['agents']:>6}  eps={row['events_per_sec']:>10}  "
                    f"p95_ms={row['latency_ms_p95']}  online={row['fleet_summary'].get('online')}"
                )
            print(out["ladder"][-1]["disclaimer"])
        else:
            print(
                f"agents={out['agents']} events={out['events']} "
                f"eps={out['events_per_sec']} p95_ms={out['latency_ms_p95']}"
            )
            print(json.dumps(out["fleet_summary"], indent=2))
            print(out["disclaimer"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
