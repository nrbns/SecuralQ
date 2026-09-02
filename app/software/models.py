"""Normalized software inventory schema (SQLite / Postgres via app.db)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.db import get_conn

# Patch posture labels (never guess latest version — UNKNOWN when unresolved)
PATCH_UP_TO_DATE = "up_to_date"
PATCH_UPDATE_AVAILABLE = "update_available"
PATCH_SECURITY_UPDATE = "security_update"
PATCH_CRITICAL = "critical_security_update"
PATCH_KEV = "exploited_kev"
PATCH_EOL = "end_of_life"
PATCH_UNKNOWN = "unknown"

PATCH_LABELS: dict[str, str] = {
    PATCH_UP_TO_DATE: "Up to date",
    PATCH_UPDATE_AVAILABLE: "Update available",
    PATCH_SECURITY_UPDATE: "Security update",
    PATCH_CRITICAL: "Critical security update",
    PATCH_KEV: "Exploited (KEV)",
    PATCH_EOL: "End of life",
    PATCH_UNKNOWN: "Unknown",
}


@dataclass
class InstallationRecord:
    """Canonical row produced by any InventorySource."""

    asset_id: str
    asset_name: str
    product: str
    version: str = ""
    vendor: str = ""
    publisher: str = ""
    architecture: str = ""
    install_path: str = ""
    source: str = "manual"
    source_id: str = ""
    last_seen: float | None = None
    install_date: str = ""
    raw_status: str = ""
    severity: str = "info"
    cve: str = ""
    detail: str = ""
    port: int | None = None
    latest_version: str | None = None
    latest_version_source: str | None = None
    patch_status: str = PATCH_UNKNOWN
    extra: dict[str, Any] = field(default_factory=dict)


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS software_products (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            normalized_name TEXT NOT NULL,
            canonical_id TEXT NOT NULL DEFAULT '',
            publisher TEXT NOT NULL DEFAULT '',
            vendor TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '',
            package_ecosystem TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS software_installations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            asset_id TEXT NOT NULL DEFAULT '',
            asset_name TEXT NOT NULL DEFAULT '',
            software_product_id TEXT NOT NULL,
            version TEXT NOT NULL DEFAULT '',
            architecture TEXT NOT NULL DEFAULT '',
            install_path TEXT NOT NULL DEFAULT '',
            install_date TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            source_id TEXT NOT NULL DEFAULT '',
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'unknown',
            severity TEXT NOT NULL DEFAULT 'info',
            cve TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '',
            port INTEGER,
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS software_versions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            software_product_id TEXT NOT NULL,
            version TEXT NOT NULL,
            release_date TEXT NOT NULL DEFAULT '',
            is_latest INTEGER NOT NULL DEFAULT 0,
            source TEXT NOT NULL DEFAULT '',
            checked_at REAL NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS software_advisories (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            software_product_id TEXT NOT NULL,
            version_range TEXT NOT NULL DEFAULT '',
            cve_id TEXT NOT NULL DEFAULT '',
            cwe TEXT NOT NULL DEFAULT '',
            cvss REAL,
            severity TEXT NOT NULL DEFAULT '',
            epss REAL,
            kev INTEGER NOT NULL DEFAULT 0,
            fixed_version TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            published_at REAL,
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS patch_status (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            asset_id TEXT NOT NULL DEFAULT '',
            software_installation_id TEXT NOT NULL,
            current_version TEXT NOT NULL DEFAULT '',
            target_version TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'unknown',
            reason TEXT NOT NULL DEFAULT '',
            version_source TEXT NOT NULL DEFAULT '',
            checked_at REAL NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS inventory_sources (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            source_key TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            healthy INTEGER NOT NULL DEFAULT 0,
            last_sync REAL,
            last_error TEXT NOT NULL DEFAULT '',
            items_synced INTEGER NOT NULL DEFAULT 0,
            updated_at REAL NOT NULL,
            UNIQUE(user_id, source_key)
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_sw_prod_user ON software_products(user_id, normalized_name)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_sw_inst_user ON software_installations(user_id, asset_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_sw_inst_prod ON software_installations(user_id, software_product_id)"
    )
    c.commit()
