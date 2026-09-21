"""Schema for Evidence Spine control mappings, observation ledger, and vault."""

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
            source_ref TEXT NOT NULL DEFAULT '',
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

        CREATE TABLE IF NOT EXISTS evidence_vault (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            kind TEXT NOT NULL DEFAULT 'document',
            title TEXT NOT NULL DEFAULT '',
            owner_id TEXT NOT NULL DEFAULT '',
            current_evidence_id TEXT NOT NULL DEFAULT '',
            review_status TEXT NOT NULL DEFAULT 'draft',
            retention_days INTEGER,
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_evault_user
            ON evidence_vault(user_id, updated_at DESC);

        CREATE TABLE IF NOT EXISTS evidence_versions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            vault_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            version_num INTEGER NOT NULL DEFAULT 1,
            previous_evidence_id TEXT NOT NULL DEFAULT '',
            content_sha256 TEXT NOT NULL DEFAULT '',
            file_id TEXT NOT NULL DEFAULT '',
            filename TEXT NOT NULL DEFAULT '',
            collector TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT 'declared',
            created_by TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            superseded_at REAL,
            superseded_by TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_ever_vault
            ON evidence_versions(vault_id, version_num DESC);
        CREATE INDEX IF NOT EXISTS idx_ever_evidence
            ON evidence_versions(evidence_id);

        CREATE TABLE IF NOT EXISTS evidence_access_log (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            vault_id TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL,
            actor_id TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_eaccess_ev
            ON evidence_access_log(evidence_id, created_at DESC);
        """
    )
    c.commit()
