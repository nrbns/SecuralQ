# Capacity lab — measure, do not claim

**Honesty:** `scripts/realtime_load_test.py` and `scripts/fleet_simulator.py` are **lab ladders**. Empty tables and unrun harnesses are **not** proof of 5 000 / 100 000 concurrent agents. Do not market those numbers until this table is filled from a real run on owned hardware.

## Harness

```bash
# HTTP check-in wave ladder (one check-in per agent; default) — NOT a production SLO
python scripts/realtime_load_test.py --server http://HOST:8080 --admin-token "$TOKEN" --ladder --persist --sse-sample

# In-process aggregator ladder (no HTTP agents) — measures fleet.health.changed path only
python scripts/fleet_simulator.py --ladder --json
python scripts/fleet_simulator.py --extended-ladder --json   # includes 25k/50k/100k sim rungs

# Extend HTTP rungs to 2500 / 5000 ONLY when the lab can enroll that many agents
python scripts/realtime_load_test.py --server http://HOST:8080 --admin-token "$TOKEN" --to-5k --persist --sse-sample
```

Results append to `data/ops/capacity_measurements.jsonl` when `--persist` is set (fleet simulator ops row is appended by the lab wrapper).

## Last measured runs

### A) In-process fleet aggregator

**Source:** `python scripts/fleet_simulator.py --extended-ladder --json` on Windows lab host (in-process aggregator only — **not** Redis/Postgres/SSE production capacity).  
**Date (UTC):** 2026-09-19 · **Operator:** local lab  
**Note:** Fleet aggregator uses O(1) incremental counters so 25k–100k rungs complete in lab time.

| Rung (agents) | Tool | Duration (s) | Success % / eps | p50 (ms) | p95 (ms) | SSE / queue lag | Date (UTC) | Operator |
|---------------|------|--------------|-----------------|----------|----------|-----------------|------------|----------|
| 100 | fleet_simulator | 0.32 | 311.2 eps | 0.007 | 0.012 | n/a (in-proc) | 2026-09-19 | local lab |
| 1000 | fleet_simulator | 0.007 | 140380.4 eps | 0.004 | 0.007 | n/a (in-proc) | 2026-09-19 | local lab |
| 5000 | fleet_simulator | 0.026 | 192236.7 eps | 0.004 | 0.005 | n/a (in-proc) | 2026-09-19 | local lab |
| 10000 | fleet_simulator | 0.054 | 185678.6 eps | 0.004 | 0.006 | n/a (in-proc) | 2026-09-19 | local lab |
| 25000 | fleet_simulator (extended) | 0.175 | 143219.1 eps | 0.004 | 0.008 | n/a (in-proc) | 2026-09-19 | local lab |
| 50000 | fleet_simulator (extended) | 0.391 | 127990.1 eps | 0.004 | 0.010 | n/a (in-proc) | 2026-09-19 | local lab |
| 100000 | fleet_simulator (extended) | 0.705 | 141954.6 eps | 0.004 | 0.008 | n/a (in-proc) | 2026-09-19 | local lab |

### B) HTTP agent check-in wave (live lab API)

**Source:** `python scripts/realtime_load_test.py --server http://127.0.0.1:8080 --ladder --max-agents 50 --workers 4 --persist --sse-sample`  
**Date (UTC):** 2026-09-19 · **Operator:** local lab · **AUTH_ENABLED:** false (lab)  
**Note:** Wave = one check-in per enrolled agent. Latency includes host-control evaluation on check-in. **Not** Redis HA / multi-worker production capacity. p95 rises under queueing at 50 concurrent workers=4.

**Root cause (investigated 2026-09-21):** `POST /api/agents/checkin` was an `async` handler calling sync `checkin()` **on the event loop**, while each check-in ran 5 host-control evaluators + `control.evaluating` SSE spam. Concurrent waves serialized on one loop → non-linear p95 (17.7s → 68.8s).

**Mitigations landed:** `asyncio.to_thread(checkin)` on HTTP + WS gateway; `host_control_emit_evaluating=false` by default; fingerprint/interval skip for unchanged control payloads on re-check-in. **Re-measure** 25/50/100 before claiming improvement — do not invent numbers.

| Rung (agents) | Tool | Duration (s) | Success % / eps | p50 (s) | p95 (s) | SSE first event (s) | Date (UTC) | Operator |
|---------------|------|--------------|-----------------|---------|---------|---------------------|------------|----------|
| 25 | realtime_load_test (wave) | 93.9 | 100% / 0.27 eps | 14.90 | 17.66 | 0.52 | 2026-09-19 | local lab |
| 50 | realtime_load_test (wave) | 255.4 | 100% / 0.20 eps | 15.80 | 68.84 | (same run) | 2026-09-19 | local lab |
| 100 | realtime_load_test (wave) | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |
| 500 | realtime_load_test (wave) | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |
| 1000 | realtime_load_test (wave) | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |

When measured, copy numbers from the harness JSON / jsonl — **never invent**.

Raw JSON: `data/_capacity_extended.json` (in-proc); HTTP rows in `data/ops/capacity_measurements.jsonl` (gitignored).

## Claim language

| Safe | Unsafe |
|------|--------|
| “Lab load ladder exists; capacity is measured per environment.” | “Supports 5 000 / 100 000 agents” / “enterprise scale proven” |
| “CI may smoke a tiny rung; ops fills this table.” | Publishing empty TBD rows as product proof |
| “In-process aggregator handled N simulated observations on this host.” | Equating simulator eps to production concurrent agents |
| “HTTP wave ladder measured 25/50 agents at 100% success on this lab host.” | Claiming production SLO from lab p50/p95 |

See also: `docs/SPRINTS-2-6-PRODUCTION.md` Sprint 6, `docs/SECURAIQ-PRODUCTION-BUILD.md`, `docs/DPDP.md`.
