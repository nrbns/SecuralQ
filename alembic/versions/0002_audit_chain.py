"""Audit hash-chain columns (#239) — additive, idempotent on Postgres/SQLite."""

from alembic import op

revision = "0002_audit_chain"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Best-effort additive columns; init_schema / audit_chain.ensure also migrate.
    conn = op.get_bind()
    dialect = conn.dialect.name
    if dialect == "postgresql":
        op.execute("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT ''")
        op.execute("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS entry_hash TEXT NOT NULL DEFAULT ''")
        op.execute(
            """
            INSERT INTO securaiq_schema_meta (key, value, updated_at)
            VALUES ('audit_chain', '0002_audit_chain', EXTRACT(EPOCH FROM NOW()))
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
            """
        )
    else:
        # SQLite: IF NOT EXISTS for columns is limited — ignore duplicate errors
        try:
            op.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass
        try:
            op.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass


def downgrade() -> None:
    # Non-destructive downgrade — leave columns in place
    pass
