# SecuraIQ — Backups & Disaster Recovery

Was **not started** per `docs/launch-readiness.md`. This is the working runbook plus the
scripts that implement it (`scripts/backup.sh` / `scripts/backup.ps1`,
`scripts/restore.sh`).

## What gets backed up

| Item | Path | Method |
|------|------|--------|
| SQLite workspace DB | `data/securaiq.db` | Online `sqlite3 .backup` (safe under WAL — no need to stop the app) |
| Vector index | `data/chroma/` | Archived (`tar.gz` / `.zip`) |
| Uploaded evidence/files | `data/uploads/` | Archived (`tar.gz` / `.zip`) |
| Secrets (`.env`) | — | **Deliberately excluded.** Back up via your secrets manager / password vault, never alongside app-data backups, so a leaked backup archive doesn't also leak API keys. |

## Running a backup

```bash
bash scripts/backup.sh                # writes to ./backups/<UTC timestamp>/
bash scripts/backup.sh /mnt/nas/backups  # or a custom destination
```

```powershell
.\scripts\backup.ps1
```

## Scheduling it

**Linux/macOS (cron)** — nightly at 02:00, keep 14 days:

```cron
0 2 * * * cd /path/to/SecuralQ && bash scripts/backup.sh /var/backups/securaiq >> /var/log/securaiq-backup.log 2>&1
```

Add a retention line (or use `find -mtime +14 -delete` on the backup root) — the scripts do not prune old backups themselves.

**Windows (Task Scheduler)** — create a daily trigger running:

```
powershell.exe -File "C:\path\to\SecuralQ\scripts\backup.ps1" -BackupRoot "D:\Backups\SecuraIQ"
```

## Restoring

```bash
bash scripts/restore.sh backups/20260728T020000Z
```

This overwrites the live DB/index/uploads — it prompts for confirmation. Restart the app afterward.

## Targets (alpha/beta defaults — tighten for production)

| Metric | Target |
|--------|--------|
| RPO (Recovery Point Objective) | ≤ 24h (nightly backup) — reduce to hourly once running real client engagements |
| RTO (Recovery Time Objective) | ≤ 30 min (restore script + restart) |
| Backup retention | 14 days rolling, plus 1 monthly snapshot kept 6 months |
| Off-host copy | Required — a backup on the same disk as the live DB is not a backup. Ship to S3/NAS/off-site. |

## Postgres path (once the SaaS profile is used)

Once `DATABASE_URL` is set (see `docs/postgres-migration.md`), use `pg_dump`/`pg_basebackup` (or your managed Postgres provider's automated backups) instead of the SQLite scripts above — they only cover the SQLite alpha/beta path.

## Encryption at rest

SQLite here is **not encrypted on disk** by default (would require migrating to SQLCipher, a heavier native dependency — not done here to keep the alpha stack simple). For anything beyond local dogfooding:

- Put `data/` on an encrypted volume (LUKS on Linux, BitLocker on Windows, or your cloud provider's encrypted-disk option). This is the practical alpha/beta answer and requires no code change — it's a deploy-time decision only you can make for your infrastructure.
- Secrets (`.env`) are additionally encrypted at rest by SecuraIQ itself when `ENV_SECRET_ENCRYPTION_KEY` is set — see `app/secrets_crypto.py` and `docs/beta-deploy.md` § Secrets encryption.
- Full DB-level encryption (SQLCipher) is a real migration, not a config flag — track it alongside the Postgres move rather than bolting it onto SQLite.

## What this doesn't cover

- Automated failover / multi-region — out of scope for a single-process alpha.
- Point-in-time recovery finer than your backup interval (WAL checkpointing is not continuously shipped anywhere).
