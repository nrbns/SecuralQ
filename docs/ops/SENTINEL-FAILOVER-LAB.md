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
| Date (UTC) | 2026-09-22T17:31:03Z |
| Environment | docker compose redis-ha lab stub (Docker Desktop Windows) |
| Time to promote | 18755.4 ms (`reconnect_ms` / `promote_wait_ms`) |
| Measure path | `docker exec` on compose network (host redis-py cannot reach Docker-internal master IPs) |
| Promote method | `replicaof_no_one_lab_assist` after Sentinel `NOGOODSLAVE` (automatic select_slave can stall on Desktop after `compose stop`) |
| failover_forced | `true` — still a live promote, not simulated |
| XAUTOCLAIM reclaim observed | not filled this run (worker soak separate) |
| SSE continuity | not filled this run (in-process self-test covers resume) |
| Operator | lab host |
| Log | `data/ops/sentinel_failover_measurements.jsonl` mode=`inject_stop` ok=`true` |

**Honesty:** Lab quorum=1 + optional `REPLICAOF NO ONE` assist ≠ multi-AZ commercial HA. EV Authenticode and cloud Object Lock remain separate ops gates.

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

### In-process self-test 2026-09-22T09:45:19.434927+00:00

- simulated: `true`
- chain_ok: `True`
- reconnect_ms: `577.4`
- xautoclaim_reclaim_ok: `True`
- sse_resume_ok: `True`
- live_redis_ping: `False` error=`redis_not_configured`
- disclaimer: in-process only — not Docker Sentinel promote

### In-process self-test 2026-09-22T10:53:42.246714+00:00

- simulated: `true`
- chain_ok: `True`
- reconnect_ms: `510.9`
- xautoclaim_reclaim_ok: `True`
- sse_resume_ok: `True`
- live_redis_ping: `False` error=`redis_not_configured`
- disclaimer: in-process only — not Docker Sentinel promote

### In-process self-test 2026-09-22T11:16:43.435084+00:00

- simulated: `true`
- chain_ok: `True`
- reconnect_ms: `469.9`
- xautoclaim_reclaim_ok: `True`
- sse_resume_ok: `True`
- live_redis_ping: `False` error=`redis_not_configured`
- disclaimer: in-process only — not Docker Sentinel promote

### In-process self-test 2026-09-22T11:24:31.958001+00:00

- simulated: `true`
- chain_ok: `True`
- reconnect_ms: `1742.7`
- xautoclaim_reclaim_ok: `True`
- sse_resume_ok: `True`
- live_redis_ping: `False` error=`redis_not_configured`
- disclaimer: in-process only — not Docker Sentinel promote

### In-process self-test 2026-09-22T11:30:27.018770+00:00

- simulated: `true`
- chain_ok: `True`
- reconnect_ms: `665.6`
- xautoclaim_reclaim_ok: `True`
- sse_resume_ok: `True`
- live_redis_ping: `False` error=`redis_not_configured`
- disclaimer: in-process only — not Docker Sentinel promote

### In-process self-test 2026-09-22T11:47:38.921367+00:00

- simulated: `true`
- chain_ok: `True`
- reconnect_ms: `929.3`
- xautoclaim_reclaim_ok: `True`
- sse_resume_ok: `True`
- live_redis_ping: `False` error=`redis_not_configured`
- disclaimer: in-process only — not Docker Sentinel promote

### In-process self-test 2026-09-22T11:48:38.584704+00:00

- simulated: `true`
- chain_ok: `True`
- reconnect_ms: `373.3`
- xautoclaim_reclaim_ok: `True`
- sse_resume_ok: `True`
- live_redis_ping: `False` error=`redis_not_configured`
- disclaimer: in-process only — not Docker Sentinel promote

### In-process self-test 2026-09-22T11:52:27.345753+00:00

- simulated: `true`
- chain_ok: `True`
- reconnect_ms: `1220.6`
- xautoclaim_reclaim_ok: `True`
- sse_resume_ok: `True`
- live_redis_ping: `False` error=`redis_not_configured`
- disclaimer: in-process only — not Docker Sentinel promote

### In-process self-test 2026-09-22T12:05:08.408487+00:00

- simulated: `true`
- chain_ok: `True`
- reconnect_ms: `2450.8`
- xautoclaim_reclaim_ok: `True`
- sse_resume_ok: `True`
- live_redis_ping: `False` error=`redis_not_configured`
- disclaimer: in-process only — not Docker Sentinel promote

### In-process self-test 2026-09-22T12:15:50.485415+00:00

- simulated: `true`
- chain_ok: `True`
- reconnect_ms: `841.2`
- xautoclaim_reclaim_ok: `True`
- sse_resume_ok: `True`
- live_redis_ping: `False` error=`redis_not_configured`
- disclaimer: in-process only — not Docker Sentinel promote

### Measurement 2026-09-22T13:55:56.551514+00:00

- reconnect_ok: `False`
- reconnect_ms: `3028.7`
- promote_wait_ms: `91737.4`
- inject_stop: `True` stop_ms=`3174.9`
- dlq_count: `None` stream_length=`None`
- error: `No master found for 'mymaster' : Redis<ConnectionPool<Connection<host=127.0.0.1,port=26379,db=0>>> - TimeoutError('Timeout connecting to server')`
- log: `data/ops/sentinel_failover_measurements.jsonl`
- disclaimer: lab proof only — not multi-AZ commercial HA

### Measurement 2026-09-22T14:00:50.398981+00:00

- reconnect_ok: `False`
- reconnect_ms: `3037.0`
- promote_wait_ms: `90796.7`
- inject_stop: `True` stop_ms=`4596.0`
- dlq_count: `None` stream_length=`None`
- error: `No master found for 'mymaster' : Redis<ConnectionPool<Connection<host=127.0.0.1,port=26379,db=0>>> - TimeoutError('Timeout reading from socket')`
- log: `data/ops/sentinel_failover_measurements.jsonl`
- disclaimer: lab proof only — not multi-AZ commercial HA

### In-process self-test 2026-09-22T14:06:37.079250+00:00

- simulated: `true`
- chain_ok: `True`
- reconnect_ms: `0.4`
- xautoclaim_reclaim_ok: `True`
- sse_resume_ok: `True`
- live_redis_ping: `False` error=`Timeout connecting to server`
- disclaimer: in-process only — not Docker Sentinel promote

### In-process self-test 2026-09-22T17:21:24.188839+00:00

- simulated: `true`
- chain_ok: `True`
- reconnect_ms: `0.7`
- xautoclaim_reclaim_ok: `True`
- sse_resume_ok: `True`
- live_redis_ping: `False` error=`Timeout connecting to server`
- disclaimer: in-process only — not Docker Sentinel promote

### Measurement 2026-09-22T17:23:21.923670+00:00

- reconnect_ok: `False`
- reconnect_ms: `None`
- promote_wait_ms: `90674.5`
- inject_stop: `True` stop_ms=`1157.8`
- dlq_count: `None` stream_length=`None`
- error: `promote_timeout_docker_exec`
- log: `data/ops/sentinel_failover_measurements.jsonl`
- disclaimer: lab proof only — not multi-AZ commercial HA

### Measurement 2026-09-22T17:28:17.909815+00:00

- reconnect_ok: `False`
- reconnect_ms: `None`
- promote_wait_ms: `90795.3`
- via: `docker_exec` failover_forced=`False`
- inject_stop: `True` stop_ms=`929.8`
- dlq_count: `None` stream_length=`None`
- error: `promote_timeout_docker_exec`
- log: `data/ops/sentinel_failover_measurements.jsonl`
- disclaimer: lab proof only — not multi-AZ commercial HA

### Measurement 2026-09-22T17:31:03.226643+00:00

- reconnect_ok: `True`
- reconnect_ms: `18755.4`
- promote_wait_ms: `18755.4`
- via: `docker_exec` failover_forced=`True`
- inject_stop: `True` stop_ms=`1227.5`
- dlq_count: `None` stream_length=`None`
- error: `None`
- log: `data/ops/sentinel_failover_measurements.jsonl`
- disclaimer: lab proof only — not multi-AZ commercial HA
