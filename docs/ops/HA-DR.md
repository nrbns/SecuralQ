# HA / DR (Phase B foundations)

**Honesty:** SQLite file-copy RTO/RPO can be published from this host. Postgres restore and API/Redis/Postgres cluster-kill RTO stay ops. Never market the lab milliseconds as a control-plane SLO.

**Surface:** `GET /api/ops/measured` · `python scripts/backup_restore_drill.py --record`

## Measured on this host (SQLite lab)

**Date (UTC):** 2026-09-24 · **Operator:** local lab · **Source:** `python scripts/backup_restore_drill.py --record`

| Metric | Value | Scope |
|--------|-------|-------|
| Backup | 3.727 ms | Closed SQLite file copy (8192 bytes) |
| Restore | 10.694 ms | File copy into dest data dir |
| Verify | 3.246 ms | Marker row present |
| **RTO (restore + verify)** | **13.94 ms** | Usable lab DB — not control-plane SLO |
| **RPO** | **0 ms** | Closed-file copy (no WAL mutation during backup) |
| Restart reclaim | 172.814 ms | In-process running→pending (1 probe job) |
| Postgres restore | unpublished | ops |
| Cluster kill (API + Redis + DB) | unpublished | ops |
| Process-kill @5k HTTP | unpublished | ops |

Raw JSONL: `data/ops/ha_dr_measurements.jsonl`, `data/ops/restart_reclaim_measurements.jsonl` (gitignored).

## Targets (draft — not replaced by the lab file-copy)

| Metric | Draft lab target | Notes |
|--------|------------------|-------|
| RPO (Postgres) | ≤ 24h | Daily backup of `DATABASE_URL` / volume |
| RTO (control plane) | ≤ 4h | Restore DB + Redis + restart API/workers |
| Redis durability | Streams + AOF where configured | Lab Sentinel stub ≠ Cluster |
| Evidence objects | Local `DATA_DIR` / future object storage | Export before wipe |

## Backup

```bash
# Postgres example (production)
pg_dump "$DATABASE_URL" > backup-$(date -u +%Y%m%d).sql

# SQLite lab
cp data/securaiq.db "data/backups/securaiq-$(date -u +%Y%m%d).db"
```

## Restore (checklist)

1. Stop API / event workers  
2. Restore Postgres or SQLite file  
3. Restore Redis (or accept stream rebuild from producers)  
4. Start Redis (Sentinel profile if used)  
5. Start API + event workers  
6. `GET /health` + `GET /ready` + one agent check-in  
7. Run `python scripts/realtime_acceptance_demo.py --local` on a lab agent  

## Incident procedure (short)

1. Page on-call; freeze deploys  
2. Capture `/metrics` lag, DLQ depth, offline agents  
3. Prefer failover (Sentinel) before full restore  
4. After restore: verify tenant isolation smoke + license validate  

## Related

- `deploy/redis/README.md`  
- `docs/ops/SENTINEL-FAILOVER-LAB.md`  
- `app/production_profile.py`
