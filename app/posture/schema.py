"""Posture engine schema — refresh runs, snapshots, baselines, locks."""

from __future__ import annotations

from app.db import get_conn


def ensure_posture_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS posture_refresh_runs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            trigger TEXT NOT NULL DEFAULT 'scheduled',
            status TEXT NOT NULL DEFAULT 'queued',
            refresh_type TEXT NOT NULL DEFAULT 'posture',
            scope_json TEXT NOT NULL DEFAULT '{}',
            started_at REAL,
            completed_at REAL,
            duration_ms INTEGER,
            assets_checked INTEGER NOT NULL DEFAULT 0,
            controls_checked INTEGER NOT NULL DEFAULT 0,
            vulnerabilities_checked INTEGER NOT NULL DEFAULT 0,
            compliance_checked INTEGER NOT NULL DEFAULT 0,
            evidence_checked INTEGER NOT NULL DEFAULT 0,
            risk_recalculated INTEGER NOT NULL DEFAULT 0,
            findings_created INTEGER NOT NULL DEFAULT 0,
            stale_assets INTEGER NOT NULL DEFAULT 0,
            errors_json TEXT NOT NULL DEFAULT '[]',
            stages_json TEXT NOT NULL DEFAULT '[]',
            metrics_json TEXT NOT NULL DEFAULT '{}',
            previous_snapshot_id TEXT NOT NULL DEFAULT '',
            snapshot_id TEXT NOT NULL DEFAULT '',
            evidence_id TEXT NOT NULL DEFAULT '',
            content_hash TEXT NOT NULL DEFAULT '',
            idempotency_key TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_posture_run_user
            ON posture_refresh_runs(user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_posture_run_status
            ON posture_refresh_runs(status, updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_posture_run_idem
            ON posture_refresh_runs(idempotency_key, status);

        CREATE TABLE IF NOT EXISTS posture_snapshots (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            run_id TEXT NOT NULL DEFAULT '',
            risk_score REAL,
            risk_band TEXT NOT NULL DEFAULT '',
            compliance_percent REAL,
            evidence_fresh_percent REAL,
            asset_health_json TEXT NOT NULL DEFAULT '{}',
            posture_scores_json TEXT NOT NULL DEFAULT '{}',
            counts_json TEXT NOT NULL DEFAULT '{}',
            attention_json TEXT NOT NULL DEFAULT '[]',
            content_hash TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_posture_snap_user
            ON posture_snapshots(user_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS posture_baselines (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            name TEXT NOT NULL DEFAULT 'Baseline',
            version INTEGER NOT NULL DEFAULT 1,
            snapshot_id TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_posture_base_user
            ON posture_baselines(user_id, updated_at DESC);

        CREATE TABLE IF NOT EXISTS posture_locks (
            lock_key TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            org_id TEXT,
            acquired_at REAL NOT NULL,
            expires_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS posture_org_settings (
            user_id TEXT PRIMARY KEY,
            org_id TEXT,
            interval_sec INTEGER NOT NULL DEFAULT 1800,
            jitter_sec INTEGER NOT NULL DEFAULT 60,
            enabled INTEGER NOT NULL DEFAULT 1,
            deep_scan_excluded INTEGER NOT NULL DEFAULT 1,
            meta_json TEXT NOT NULL DEFAULT '{}',
            updated_at REAL NOT NULL
        );
        """
    )
    c.commit()
