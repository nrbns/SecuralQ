# Lab Redis Sentinel — measured failover note

**Honesty:** Lab stub only (compose `--profile redis-ha`, quorum=1).  
**Not** Redis Cluster / multi-AZ / commercial HA certification.

## How to measure (ops)

```bash
docker compose --profile redis-ha up -d
python scripts/realtime_phase1_proof.py --check-sentinel

# Preferred: inject stop + wait for promote + record reconnect timing
python scripts/sentinel_failover_measure.py --inject-stop --record

# Or manual:
# docker compose stop redis-primary
# python scripts/sentinel_failover_measure.py --record
python scripts/realtime_phase1_proof.py --check-sentinel
```

Measurements append to `data/ops/sentinel_failover_measurements.jsonl`.

Confirm after promote:

1. `reconnect_after_failover()` succeeds  
2. Worker B `XAUTOCLAIM` reclaim  
3. SSE clients still receive events (no soft-poll)

## Last measured run

### Live Docker inject

| Field | Value |
|-------|--------|
| Date (UTC) | _unmeasured — Docker not on this Windows lab; run `--inject-stop --record` where compose HA is up_ |
| Environment | docker compose redis-ha lab stub |
| Time to Sentinel promote + client reconnect | _TBD seconds_ |
| XAUTOCLAIM reclaim observed | _TBD_ |
| SSE continuity | _TBD_ |
| Operator | _TBD_ |

### In-process chain (CI / no Docker)

| Field | Value |
|-------|--------|
| Date (UTC) | see latest `### In-process self-test` section below |
| Environment | Python in-process (mocked Redis XAUTOCLAIM + local SSE bus) |
| Reconnect helper | exercised via `reconnect_after_failover()` |
| XAUTOCLAIM reclaim | proven once-only reclaim path |
| SSE continuity | Last-Event-ID replay after simulated disconnect |
| Label | **`simulated: true`** — not a live Sentinel promote |

When measured live, append a dated section below (do not invent numbers).

## Claim language

Safe: “Lab Sentinel stub with documented failover procedure; CI proves reconnect + XAUTOCLAIM + SSE resume without requiring live Sentinel.”

Unsafe: “Production Redis HA certified” / “multi-AZ failover SLO”.

## CI vs ops

| Mode | Command | Proves |
|------|---------|--------|
| Dry-run | `python scripts/sentinel_failover_measure.py --dry-run` | Script + docs path exist |
| Pipeline self-test | `python scripts/sentinel_failover_measure.py --pipeline-self-test` | Measurement jsonl + in-process failover chain (row marked `simulated: true`) |
| Metrics | `python scripts/sentinel_failover_measure.py --metrics-only` | Streams/DLQ snapshot when Redis up (no failover) |
| Measured | `--inject-stop --record` | Lab reconnect timing + optional stream metrics |

Fill `events_sent` / `events_lost` / `duplicates` / `replayed` only from a live worker run — never invent.

Also: `python scripts/realtime_ops_remaining_proof.py` bundles Sentinel self-test + multiworker soak + signing scaffolds for CI.

### In-process self-test 2026-09-19T06:34:49.349136+00:00

- simulated: `true`
- chain_ok: `True`
- reconnect_ms: `407.0`
- xautoclaim_reclaim_ok: `True`
- sse_resume_ok: `True`
- live_redis_ping: `False` error=`redis_not_configured`
- disclaimer: in-process only — not Docker Sentinel promote
