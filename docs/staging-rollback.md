# Staging deploy + rollback (#245)

## Staging

1. Deploy from `securaiq/main` (or a release tag) to the staging compose stack:
   ```bash
   docker compose --profile saas up -d --build
   ```
2. Run migrations / export if moving off SQLite:
   ```bash
   alembic upgrade head
   python scripts/sqlite_to_postgres_export.py --help
   ```
3. Gate checks before promoting:
   ```bash
   pytest -v tests/test_master_checklist_p0.py tests/test_master_checklist_phases.py
   python scripts/realtime_acceptance_demo.py --local --firewall-only
   python scripts/backup_restore_drill.py
   ```

## Rollback

| Layer | How |
|-------|-----|
| App image | Redeploy previous image tag / git SHA; keep `DATABASE_URL` unchanged |
| Agent binary | Use signed `agent_upgrade` with `previous_sha256` (see `app/agent_updates.py`) |
| DB | Restore from last successful `scripts/backup_restore_drill.py` artifact |
| Secrets | Keep prior `data/.secret.key.pre-rotate` until all nodes healthy after `scripts/rotate_secrets.py` |

Do not claim zero-downtime HA unless Redis Sentinel failover has been **measured** with `scripts/sentinel_failover_measure.py` (not assumed).

## Canary agents

Use patch campaign rings (`ring_index`) so a bad agent build hits a small cohort first. Abort the campaign before approving later rings if verification fails.
