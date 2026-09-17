# SecuraIQ — Postgres Migration

**Status:** Dual-backend `get_conn()` shipped (Phase 2 MVP). **SQLite remains the default.** Full Alembic/SQLAlchemy (Phase 1) is still optional.

## Why migrate

- Multi-tenant SaaS concurrency
- Connection pooling for background jobs
- Enterprise backup/restore expectations

## Runtime selection

| `DATABASE_URL` | Backend |
|----------------|---------|
| empty / unset | SQLite at `DATA_DIR/securaiq.db` |
| `postgresql://…` or `postgres://…` | Postgres via `psycopg` |

```bash
pip install 'psycopg[binary]'
# docker compose --profile postgres up -d postgres
export DATABASE_URL=postgresql://securaiq:securaiq@127.0.0.1:5432/securaiq
```

Call sites keep SQLite-style `?` placeholders; the Postgres adapter rewrites to `%s`.

## Compose profiles

```bash
docker compose --profile postgres up -d postgres
docker compose --profile saas up -d
```

## Migration plan

| Phase | Work | Status |
|-------|------|--------|
| 1 | Alembic + SQLAlchemy models | Partial — `alembic/` baseline + `scripts/db_migrate_and_run.py`; full DDL still `init_schema()` |
| 2 | Dual-backend `get_conn()` | **Done (MVP)** |
| 3 | Data export/import SQLite → Postgres | **Partial** — `scripts/sqlite_to_postgres_export.py` (row export SQL/JSON) |
| 4 | CI matrix against Postgres | Planned |
| 5 | Default Compose SaaS profile to Postgres | Planned |

## SQLite → Postgres row export (#227)

```bash
python scripts/sqlite_to_postgres_export.py --sqlite data/securaiq.db --out data/exports/sqlite_export.sql
python scripts/sqlite_to_postgres_export.py --sqlite data/securaiq.db --json-dir data/exports/json
```

Apply the SQL against a Postgres DB that already has schema from `init_schema` / Alembic. This is a **row dump**, not a substitute for a full Alembic revision chain.

## Backup / restore drill (#229)

```bash
python scripts/backup_restore_drill.py
```

CI-safe SQLite copy→restore→verify. Ops still own Postgres `pg_dump` / PITR drills (see `docs/backup-dr.md`).

## MVP limits

- Prefer a **fresh** Postgres database (`init_schema` CREATE TABLE IF NOT EXISTS).
- Some older modules may still use SQLite-only `PRAGMA`; core tenancy/engagements use portable `table_columns()`.
- Do not flip production to Postgres until Phase 3–4 are green.

## Service layer (related)

Domain facades live under `app/services/` (`assets`, `findings`, `risk`, `engagements`, `tenancy`, `tool_policy`). SQL owners remain `enterprise.py` / `workspace.py`.

## Engagement scope (tool policy)

`engagements.scope_json` stores an allowlist (`["10.0.0.0/8","*.lab.local"]`). When non-empty, tool runs with that `engagement_id` are blocked if the target is out of scope.

## Rollback

Keep a SQLite backup of `data/securaiq.db` before cutover. Lab/alpha partners should stay on SQLite until the PG path is CI-green.
