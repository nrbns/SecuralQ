# Lab Redis Sentinel — measured failover note

**Honesty:** Lab stub only (compose `--profile redis-ha`, quorum=1).  
**Not** Redis Cluster / multi-AZ / commercial HA certification.

## How to measure (ops)

```bash
docker compose --profile redis-ha up -d
python scripts/realtime_phase1_proof.py --check-sentinel

# Inject a stream event while API + event workers are up, then:
docker compose stop redis-primary

# Time until check-sentinel succeeds again:
python scripts/sentinel_failover_measure.py --record
python scripts/realtime_phase1_proof.py --check-sentinel
```

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
