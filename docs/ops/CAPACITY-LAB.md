# Capacity lab — measure, do not claim

**Honesty:** `scripts/realtime_load_test.py` is a **lab ladder**. Empty tables and unrun harnesses are **not** proof of 5 000 concurrent agents. Do not market 5k until this table is filled from a real run.

## Harness

```bash
# Soft ladder (default top 1000) — NOT a production SLO
python scripts/realtime_load_test.py --server http://HOST:8080 --admin-token "$TOKEN" --ladder --persist

# Extend rungs to 2500 / 5000 ONLY when the lab can enroll that many agents
python scripts/realtime_load_test.py --server http://HOST:8080 --admin-token "$TOKEN" --to-5k --persist --sse-sample
```

Results append to `data/ops/capacity_measurements.jsonl` when `--persist` is set.

## Last measured run (fill after ops)

| Rung (agents) | Duration (s) | Success % | p50 check-in (ms) | p95 check-in (ms) | SSE first event (s) | Date (UTC) | Operator |
|---------------|--------------|-----------|-------------------|-------------------|---------------------|------------|----------|
| 100 | _TBD_ | _TBD_ | _TBD_ | _TBD_ | _TBD_ | _unmeasured_ | _TBD_ |
| 500 | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |
| 1000 | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |
| 2500 | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |
| 5000 | _TBD_ | _TBD_ | _TBD_ | _TBD_ | — | _unmeasured_ | _TBD_ |

When measured, copy numbers from the harness JSON / jsonl — **never invent**.

## Claim language

| Safe | Unsafe |
|------|--------|
| “Lab load ladder exists; capacity is measured per environment.” | “Supports 5 000 agents” / “enterprise scale proven” |
| “CI may smoke a tiny rung; ops fills this table.” | Publishing empty TBD rows as product proof |

See also: `docs/SPRINTS-2-6-PRODUCTION.md` Sprint 6, `docs/SECURAIQ-PRODUCTION-BUILD.md`.
