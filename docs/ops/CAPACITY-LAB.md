# Capacity lab — measure, do not claim

**Honesty:** `scripts/realtime_load_test.py` and `scripts/fleet_simulator.py` are **lab ladders**. Empty tables and unrun harnesses are **not** proof of 5 000 / 100 000 concurrent agents. Do not market those numbers until this table is filled from a real run on owned hardware.

## Harness

```bash
# Soft ladder (default top 1000) — NOT a production SLO
python scripts/realtime_load_test.py --server http://HOST:8080 --admin-token "$TOKEN" --ladder --persist

# In-process aggregator ladder (no HTTP agents) — measures fleet.health.changed path only
python scripts/fleet_simulator.py --ladder --json
python scripts/fleet_simulator.py --extended-ladder --json   # includes 25k/50k/100k sim rungs

# Extend HTTP rungs to 2500 / 5000 ONLY when the lab can enroll that many agents
python scripts/realtime_load_test.py --server http://HOST:8080 --admin-token "$TOKEN" --to-5k --persist --sse-sample
```

Results append to `data/ops/capacity_measurements.jsonl` when `--persist` is set.

## Last measured run (fill after ops)

| Rung (agents) | Tool | Duration (s) | Success % / eps | p50 (ms) | p95 (ms) | SSE / queue lag | Date (UTC) | Operator |
|---------------|------|--------------|-----------------|----------|----------|-----------------|------------|----------|
| 100 | realtime_load_test / fleet_simulator | _TBD_ | _TBD_ | _TBD_ | _TBD_ | _TBD_ | _unmeasured_ | _TBD_ |
| 500 | realtime_load_test | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |
| 1000 | both | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |
| 5000 | both | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |
| 10000 | fleet_simulator | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |
| 25000 | fleet_simulator (extended) | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |
| 50000 | fleet_simulator (extended) | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |
| 100000 | fleet_simulator (extended) | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |

When measured, copy numbers from the harness JSON / jsonl — **never invent**.

## Claim language

| Safe | Unsafe |
|------|--------|
| “Lab load ladder exists; capacity is measured per environment.” | “Supports 5 000 / 100 000 agents” / “enterprise scale proven” |
| “CI may smoke a tiny rung; ops fills this table.” | Publishing empty TBD rows as product proof |

See also: `docs/SPRINTS-2-6-PRODUCTION.md` Sprint 6, `docs/SECURAIQ-PRODUCTION-BUILD.md`, `docs/DPDP.md`.
