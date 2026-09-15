# HA / DR (Phase B foundations)

**Honesty:** Documented targets and lab procedures — not a published enterprise SLO until measured restore drills exist.

## Targets (draft — revise after first restore drill)

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
