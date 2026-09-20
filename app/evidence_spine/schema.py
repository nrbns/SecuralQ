"""Schema for Evidence Spine control mappings and observation ledger."""

from __future__ import annotations

from app.db import get_conn


def ensure_evidence_spine_schema() -> None:
    """Idempotent — safe across test DB swaps (no sticky global)."""
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS evidence_control_map (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            evidence_id TEXT NOT NULL,
            framework_id TEXT NOT NULL DEFAULT '',
            control_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'supports',
            -- satisfies | supports | documents | verifies
            created_at REAL NOT NULL,
            UNIQUE(user_id, evidence_id, framework_id, control_id)
        );
        CREATE INDEX IF NOT EXISTS idx_ecm_control
            ON evidence_control_map(user_id, framework_id, control_id);
        CREATE INDEX IF NOT EXISTS idx_ecm_evidence
            ON evidence_control_map(user_id, evidence_id);

        CREATE TABLE IF NOT EXISTS evidence_observations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            data_source TEXT NOT NULL DEFAULT 'agent',
            -- agent | document | scan | cloud | human
            source_ref TEXT NOT NULL DEFAULT '',
            -- agent_id / file_id / scanner id
            check_id TEXT NOT NULL DEFAULT '',
            control_hint TEXT NOT NULL DEFAULT '',
            result TEXT NOT NULL DEFAULT 'unknown',
            summary TEXT NOT NULL DEFAULT '',
            detail_json TEXT NOT NULL DEFAULT '{}',
            content_hash TEXT NOT NULL DEFAULT '',
            evidence_id TEXT NOT NULL DEFAULT '',
            observed_at REAL NOT NULL,
            expires_at REAL,
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_eobs_user_time
            ON evidence_observations(user_id, observed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_eobs_evidence
            ON evidence_observations(evidence_id);
        """
    )
    c.commit()
