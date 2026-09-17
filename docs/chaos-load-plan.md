# Chaos / load test plan (#232)

Authorized lab / staging only — never against third-party systems.

## Goals

- Confirm SSE + Redis Streams stay correct under concurrent check-ins
- Confirm API rate limits return 429 without process crash
- Confirm DLQ fills and admin replay works under poison events

## Scripts already in repo

| Script | Purpose |
|--------|---------|
| `scripts/agent_gateway_load.py` | Concurrent gateway / check-in load |
| `scripts/realtime_multiworker_smoke.py` | Multi-worker SSE + DLQ smoke |
| `scripts/sentinel_failover_measure.py` | Measure (not claim) Sentinel failover |
| `scripts/realtime_acceptance_demo.py --local` | Golden loop correctness |

## Suggested staging runbook

1. Baseline: `python scripts/realtime_acceptance_demo.py --local`
2. Load: `python scripts/agent_gateway_load.py` (raise workers gradually)
3. Fail a Redis replica / pause consumer → confirm XAUTOCLAIM + DLQ
4. Record p50/p99 latency and error rate; attach to release notes
5. Stop: tear down load generators; purge demo DLQ if needed

Success = no data loss on acked sequences, no cross-tenant bleed, process stays up.
