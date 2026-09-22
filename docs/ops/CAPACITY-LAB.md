# Capacity lab — measure, do not claim

**Honesty:** `scripts/realtime_load_test.py` and `scripts/fleet_simulator.py` are **lab ladders**. Empty tables and unrun harnesses are **not** proof of 5 000 / 100 000 concurrent agents. Do not market those numbers until this table is filled from a real run on owned hardware.

Process-local stage meters (`securaiq_stage_latency_*` / `pipeline_metrics.stage_latency`) exist for ingest/detect/risk/sse — they are **not** commercial SLOs until measured on a sustained lab run against the targets in [PRODUCTION-CONTROL-PLANE.md](../PRODUCTION-CONTROL-PLANE.md).

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

**Baseline (pre-fix):** `python scripts/realtime_load_test.py --server http://127.0.0.1:8080 --ladder --max-agents 50 --workers 4 --persist --sse-sample`  
**Date (UTC):** 2026-09-19 · **Operator:** local lab · **AUTH_ENABLED:** false (lab)  
**Note:** Wave = one check-in per enrolled agent. Latency includes host-control evaluation on check-in. **Not** Redis HA / multi-worker production capacity.

**Root cause (investigated 2026-09-21):** `POST /api/agents/checkin` was an `async` handler calling sync `checkin()` **on the event loop**, while each check-in ran 5 host-control evaluators + `control.evaluating` SSE spam. Concurrent waves serialized on one loop → non-linear p95 (17.7s → 68.8s).

**Mitigations landed:** `asyncio.to_thread(checkin)` on HTTP + WS gateway; `host_control_emit_evaluating=false` by default; fingerprint/interval skip for unchanged control payloads on re-check-in.

#### B.1 — Baseline (before event-loop fix)

| Rung (agents) | Tool | Duration (s) | Success % / eps | p50 (s) | p95 (s) | SSE first event (s) | Date (UTC) | Operator |
|---------------|------|--------------|-----------------|---------|---------|---------------------|------------|----------|
| 25 | realtime_load_test (wave) | 93.9 | 100% / 0.27 eps | 14.90 | 17.66 | 0.52 | 2026-09-19 | local lab |
| 50 | realtime_load_test (wave) | 255.4 | 100% / 0.20 eps | 15.80 | 68.84 | (same run) | 2026-09-19 | local lab |

#### B.2 — Re-measure after `to_thread(checkin)` (2026-09-21)

**Source:** `python scripts/realtime_load_test.py --server http://127.0.0.1:8080 --ladder --max-agents 100 --workers 4 --persist --sse-sample`  
**Date (UTC):** 2026-09-21 · **Operator:** local lab · **AUTH_ENABLED:** false (lab)  
**Result:** 100% success at 25/50/100. The **50-agent p95 cliff is gone** (68.84s → 24.47s). Absolute p50 is still multi-second (host-control work per check-in, workers=4 queueing) — do **not** claim production SLO. 500/1k still unmeasured.

| Rung (agents) | Tool | Duration (s) | Success % / eps | p50 (s) | p95 (s) | SSE first event (s) | Date (UTC) | Operator |
|---------------|------|--------------|-----------------|---------|---------|---------------------|------------|----------|
| 25 | realtime_load_test (wave) | 143.5 | 100% / 0.17 eps | 22.22 | 27.01 | n/a (sample null) | 2026-09-21 | local lab |
| 50 | realtime_load_test (wave) | 248.6 | 100% / 0.20 eps | 19.16 | 24.47 | — | 2026-09-21 | local lab |
| 100 | realtime_load_test (wave) | 574.4 | 100% / 0.17 eps | 21.46 | 34.44 | — | 2026-09-21 | local lab |
| 500 | realtime_load_test (wave) | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |
| 1000 | realtime_load_test (wave) | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |

#### B.3 — Re-measure after CheckinPayload empty-dict fix (2026-09-22)

**Root cause:** `CheckinPayload` defaulted `firewall_status`/`defender_status`/… to `{}`, so `_host_present` was always true and every HTTP check-in ran full host-control evaluators. Fixed: optional None + `truncated` + `model_dump(exclude_none=True)` + meaningful-blob check.

**Source:** `python scripts/realtime_load_test.py --server http://127.0.0.1:8080 --ladder --max-agents 500 --workers 8 --persist --sse-sample`  
**Date (UTC):** 2026-09-22 · **Operator:** local lab · **AUTH_ENABLED:** false · **truncated check-ins**  
**Result:** HTTP **500 measured** at 99.6% success. p50 ≈ 4 s (lab host, SQLite, workers=8) — **not** a production SLO. 1000 still unmeasured.

| Rung (agents) | Tool | Duration (s) | Success % / eps | p50 (s) | p95 (s) | SSE first event (s) | Date (UTC) | Operator |
|---------------|------|--------------|-----------------|---------|---------|---------------------|------------|----------|
| 25 | realtime_load_test (wave) | 14.3 | 96.0% / 1.68 eps | 3.97 | 6.23 | n/a | 2026-09-22 | local lab |
| 50 | realtime_load_test (wave) | 28.3 | 98.0% / 1.73 eps | 4.28 | 6.66 | — | 2026-09-22 | local lab |
| 100 | realtime_load_test (wave) | 53.3 | 100% / 1.88 eps | 4.27 | 5.73 | — | 2026-09-22 | local lab |
| 500 | realtime_load_test (wave) | 250.0 | 99.6% / 1.99 eps | 4.01 | 5.73 | — | 2026-09-22 | local lab |
| 1000 | realtime_load_test (wave) | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |

#### B.4 — HTTP 1000 measured (2026-09-22)

**Source:** `python scripts/realtime_load_test.py --server http://127.0.0.1:8080 --ladder --max-agents 1000 --workers 8 --persist --sse-sample`  
**Date (UTC):** 2026-09-22 · truncated check-ins · AUTH off  
**Result:** HTTP **1000 measured** at 99.3% success. Not a production SLO.

| Rung (agents) | Duration (s) | Success % | p50 (s) | p95 (s) |
|---------------|--------------|-----------|---------|---------|
| 25 | 28.3 | 96.0% | 3.92 | 21.50 |
| 50 | 25.9 | 98.0% | 4.25 | 5.75 |
| 100 | 49.2 | 99.0% | 3.90 | 6.02 |
| 500 | 249.9 | 98.4% | 3.71 | 6.19 |
| 1000 | 498.2 | **99.3%** | 3.86 | 6.01 |

Live verify: `python scripts/live_lab_verify.py --server http://127.0.0.1:8080 --i-own-this-host`

### C) Soft in-process check-in ladder (not HTTP)

**Source:** `app.capacity_soft.soft_checkin_ladder` (truncated check-ins) / pytest  
**Date (UTC):** 2026-09-22 · **Operator:** local lab  
**Honesty:** Exercises enroll+checkin in-process with `truncated: true` (skips host-control evaluators). **Do not** market as HTTP 500+ capacity.

| Rung | Success % | checkin p50 (ms) | checkin p95 (ms) |
|------|-----------|------------------|------------------|
| 100 | 100% | 37.2 | 53.8 |
| 250 | 100% | 44.9 | 73.1 |
| 500 | 100% | 48.6 | 72.1 |
| 1000 | 100% | 55.0 | 81.5 |

```bash
python -c "from app.capacity_soft import soft_checkin_ladder; print(soft_checkin_ladder('USER', [100,250,500,1000]))"
```

When HTTP measured, copy numbers from the harness JSON / jsonl — **never invent**.

Raw JSON: `data/_capacity_extended.json` (in-proc); HTTP rows in `data/ops/capacity_measurements.jsonl` (gitignored).

Phase-1 leftovers board: `GET /api/admin/ops/phase1-remaining` · one-shot: `python scripts/phase1_ops_complete_lab.py`

## Claim language

| Safe | Unsafe |
|------|--------|
| “Lab load ladder exists; capacity is measured per environment.” | “Supports 5 000 / 100 000 agents” / “enterprise scale proven” |
| “CI may smoke a tiny rung; ops fills this table.” | Publishing empty TBD rows as product proof |
| “In-process aggregator handled N simulated observations on this host.” | Equating simulator eps to production concurrent agents |
| “HTTP wave ladder measured 25/50/100 agents at 100% success on this lab host; 50-agent p95 cliff fixed after check-in offload.” | Claiming production SLO from lab p50/p95 |

See also: `docs/SPRINTS-2-6-PRODUCTION.md` Sprint 6, `docs/SECURAIQ-PRODUCTION-BUILD.md`, `docs/DPDP.md`, [RELEASE-GATES.md](../RELEASE-GATES.md).
