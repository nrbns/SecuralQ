"""CMMC assessment schema — objectives, method evidence, CUI program, version stamps."""

from __future__ import annotations

from app.db import get_conn


def ensure_cmmc_assessment_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS cmmc_assessment_objectives (
            id TEXT PRIMARY KEY,
            framework_id TEXT NOT NULL,
            framework_version TEXT NOT NULL DEFAULT '',
            control_id TEXT NOT NULL,
            objective_key TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL DEFAULT 'examine',
            determination_hint TEXT NOT NULL DEFAULT '',
            sort_order INTEGER NOT NULL DEFAULT 0,
            seed_source TEXT NOT NULL DEFAULT 'securaiq_scaffold',
            created_at REAL NOT NULL,
            UNIQUE(framework_id, control_id, objective_key)
        );
        CREATE INDEX IF NOT EXISTS idx_cmmc_obj_ctrl
            ON cmmc_assessment_objectives(framework_id, control_id);

        CREATE TABLE IF NOT EXISTS cmmc_objective_status (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            objective_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'unknown',
            evidence_ids_json TEXT NOT NULL DEFAULT '[]',
            reviewer TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            assessed_at REAL,
            freshness_status TEXT NOT NULL DEFAULT 'unknown',
            updated_at REAL NOT NULL,
            UNIQUE(user_id, objective_id)
        );
        CREATE INDEX IF NOT EXISTS idx_cmmc_obj_st_user
            ON cmmc_objective_status(user_id, framework_id, control_id);

        CREATE TABLE IF NOT EXISTS cmmc_method_evidence (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            objective_id TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            detail_json TEXT NOT NULL DEFAULT '{}',
            evidence_id TEXT NOT NULL DEFAULT '',
            result TEXT NOT NULL DEFAULT 'unknown',
            collected_at REAL NOT NULL,
            reviewer TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_cmmc_meth_user
            ON cmmc_method_evidence(user_id, framework_id, control_id);

        CREATE TABLE IF NOT EXISTS cmmc_cui_program (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            name TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            boundary_notes TEXT NOT NULL DEFAULT '',
            categories_json TEXT NOT NULL DEFAULT '[]',
            external_providers_json TEXT NOT NULL DEFAULT '[]',
            data_flows_json TEXT NOT NULL DEFAULT '[]',
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_cmmc_cui_user
            ON cmmc_cui_program(user_id, updated_at DESC);

        CREATE TABLE IF NOT EXISTS cmmc_poam_items (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            finding_id TEXT NOT NULL DEFAULT '',
            weakness TEXT NOT NULL DEFAULT '',
            risk_level TEXT NOT NULL DEFAULT 'medium',
            owner TEXT NOT NULL DEFAULT '',
            due_at REAL,
            milestone_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'open',
            evidence_ids_json TEXT NOT NULL DEFAULT '[]',
            remediation_id TEXT NOT NULL DEFAULT '',
            closed_at REAL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_cmmc_poam_user
            ON cmmc_poam_items(user_id, framework_id, status);
        """
    )
    c.commit()
