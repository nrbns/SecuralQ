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

## Last measured run (fill after ops)

| Field | Value |
|-------|--------|
| Date (UTC) | _unmeasured — run `scripts/sentinel_failover_measure.py --record`_ |
| Environment | docker compose redis-ha lab stub |
| Time to Sentinel promote + client reconnect | _TBD seconds_ |
| XAUTOCLAIM reclaim observed | _TBD_ |
| SSE continuity | _TBD_ |
| Operator | _TBD_ |

When measured, append a dated section below (do not invent numbers).

## Claim language

Safe: “Lab Sentinel stub with documented failover procedure; CI proves once-only / XAUTOCLAIM / SSE replay without requiring live Sentinel.”

Unsafe: “Production Redis HA certified” / “multi-AZ failover SLO”.

## CI vs ops

| Mode | Command | Proves |
|------|---------|--------|
| Dry-run | `python scripts/sentinel_failover_measure.py --dry-run` | Script + docs path exist |
| Metrics | `python scripts/sentinel_failover_measure.py --metrics-only` | Streams/DLQ snapshot when Redis up (no failover) |
| Measured | `--inject-stop --record` | Lab reconnect timing + optional stream metrics |

Fill `events_sent` / `events_lost` / `duplicates` / `replayed` only from a live worker run — never invent.
