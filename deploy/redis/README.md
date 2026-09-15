# Lab Redis Sentinel stub

**Not** a production HA / Cluster certification.

## Start

```bash
docker compose --profile redis-ha up -d
```

Host-side ports (localhost only):

| Service | Port |
|---------|------|
| Sentinel | `127.0.0.1:26379` |
| Primary (direct) | `127.0.0.1:6380` |

App settings:

```bash
# Prefer Sentinel (leave REDIS_URL empty)
REDIS_SENTINEL_HOSTS=127.0.0.1:26379   # or redis-sentinel:26379 in compose network
REDIS_SENTINEL_MASTER=mymaster
```

## Measured failover checklist

```bash
python scripts/realtime_phase1_proof.py --check-sentinel
# stop primary — Sentinel promotes replica (quorum=1 lab stub)
docker compose stop redis-primary
python scripts/realtime_phase1_proof.py --check-sentinel
```

Then confirm API workers reclaim pending via `XAUTOCLAIM` and SSE clients still receive events.

## CI vs ops

| Claim | Where proven |
|-------|----------------|
| Once-only security action / reclaim / DLQ / SSE replay | `tests/test_realtime_phase1_proof.py` + durability tests |
| Firewall closed loop | `scripts/realtime_acceptance_demo.py --local` |
| Sentinel failover timing | This compose profile + ops checklist above |
