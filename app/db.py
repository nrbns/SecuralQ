"""SQLite / Postgres persistence for users, engagements, chats, audit, memory, files."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from app.config import settings

_lock = threading.Lock()
_conn: Any = None
_backend: str = "sqlite"  # sqlite | postgres


def _db_path() -> Path:
    path = Path(settings.data_dir) / "securaiq.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def using_postgres() -> bool:
    url = (settings.database_url or "").strip().lower()
    return url.startswith("postgres://") or url.startswith("postgresql://")


def current_backend() -> str:
    return "postgres" if using_postgres() else "sqlite"


class _PgCursor:
    """psycopg cursor that accepts SQLite-style `?` placeholders."""

    def __init__(self, cur: Any):
        self._cur = cur

    @staticmethod
    def _rewrite(sql: str) -> str:
        # Rewrite unbound `?` placeholders only (not inside simple quotes).
        out: list[str] = []
        in_str = False
        i = 0
        while i < len(sql):
            ch = sql[i]
            if ch == "'":
                out.append(ch)
                if in_str and i + 1 < len(sql) and sql[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                in_str = not in_str
                i += 1
                continue
            if ch == "?" and not in_str:
                out.append("%s")
                i += 1
                continue
            out.append(ch)
            i += 1
        return "".join(out)

    def execute(self, sql: str, params: Any = None):
        q = self._rewrite(sql)
        if params is None:
            self._cur.execute(q)
        else:
            self._cur.execute(q, params)
        return self

    def executemany(self, sql: str, seq_of_params: Any):
        self._cur.executemany(self._rewrite(sql), seq_of_params)
        return self

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def __getattr__(self, name: str):
        return getattr(self._cur, name)


class _PgConn:
    """Thin adapter so call sites keep using sqlite3-style APIs."""

    def __init__(self, conn: Any):
        self._conn = conn

    def execute(self, sql: str, params: Any = None):
        cur = _PgCursor(self._conn.cursor())
        cur.execute(sql, params)
        return cur

    def executemany(self, sql: str, seq_of_params: Any):
        cur = _PgCursor(self._conn.cursor())
        cur.executemany(sql, seq_of_params)
        return cur

    def executescript(self, script: str):
        # Strip SQLite-only PRAGMAs; run statement-by-statement.
        cleaned = re.sub(r"(?im)^\s*PRAGMA\b.*?;\s*$", "", script)
        cur = self._conn.cursor()
        for stmt in cleaned.split(";"):
            s = stmt.strip()
            if s:
                cur.execute(s)
        return self

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()

    def cursor(self):
        return _PgCursor(self._conn.cursor())

    def __getattr__(self, name: str):
        return getattr(self._conn, name)


def table_columns(conn: Any, table: str) -> set[str]:
    """Portable column listing (PRAGMA on SQLite, information_schema on Postgres)."""
    if current_backend() == "postgres" or isinstance(conn, _PgConn):
        rows = conn.execute(
            """
            SELECT column_name AS name
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = ?
            """,
            (table,),
        ).fetchall()
        out: set[str] = set()
        for r in rows:
            if isinstance(r, dict):
                out.add(str(r.get("name") or r.get("column_name")))
            else:
                out.add(str(r[0]))
        return out
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def get_conn() -> Any:
    global _conn, _backend
    with _lock:
        if _conn is None:
            if using_postgres():
                try:
                    import psycopg
                    from psycopg.rows import dict_row
                except ImportError as exc:
                    raise RuntimeError(
                        "DATABASE_URL is set to Postgres but psycopg is not installed. "
                        "Run: pip install 'psycopg[binary]'"
                    ) from exc
                raw = psycopg.connect(settings.database_url.strip(), row_factory=dict_row)
                _conn = _PgConn(raw)
                _backend = "postgres"
                init_schema(_conn)
            else:
                _conn = sqlite3.connect(str(_db_path()), check_same_thread=False)
                _conn.row_factory = sqlite3.Row
                _conn.execute("PRAGMA journal_mode=WAL;")
                _conn.execute("PRAGMA foreign_keys=ON;")
                _backend = "sqlite"
                init_schema(_conn)
        return _conn


def reset_conn_for_tests() -> None:
    """Drop cached connection (tests that change DATA_DIR / DATABASE_URL)."""
    global _conn, _backend
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
        _conn = None
        _backend = "sqlite"


def init_schema(conn: Any | None = None) -> None:
    c = conn or get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at REAL NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            key_prefix TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS engagements (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            scope_notes TEXT NOT NULL DEFAULT '',
            scope_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'active',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS chats (
            id TEXT PRIMARY KEY,
            engagement_id TEXT REFERENCES engagements(id) ON DELETE SET NULL,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            mode TEXT NOT NULL DEFAULT 'default',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            action TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS memories (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            created_at REAL NOT NULL,
            UNIQUE(engagement_id, key)
        );
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            engagement_id TEXT REFERENCES engagements(id) ON DELETE SET NULL,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            filename TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS gap_assessments (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            engagement_id TEXT,
            framework_id TEXT NOT NULL,
            title TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '',
            result_json TEXT NOT NULL,
            compliance_percent REAL NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS gap_remediations (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL REFERENCES gap_assessments(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL,
            engagement_id TEXT,
            control_id TEXT NOT NULL,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            owner TEXT NOT NULL DEFAULT '',
            due_date TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            recommendation TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            engagement_id TEXT,
            name TEXT NOT NULL,
            asset_type TEXT NOT NULL DEFAULT 'server',
            criticality TEXT NOT NULL DEFAULT 'medium',
            owner TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS risks (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            engagement_id TEXT,
            asset_id TEXT,
            asset_name TEXT NOT NULL DEFAULT '',
            threat TEXT NOT NULL,
            vulnerability TEXT NOT NULL DEFAULT '',
            impact INTEGER NOT NULL DEFAULT 3,
            likelihood INTEGER NOT NULL DEFAULT 3,
            risk_score INTEGER NOT NULL DEFAULT 9,
            owner TEXT NOT NULL DEFAULT '',
            mitigation TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            engagement_id TEXT,
            asset_id TEXT,
            asset_name TEXT NOT NULL DEFAULT '',
            cve TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'medium',
            cvss REAL,
            status TEXT NOT NULL DEFAULT 'open',
            owner TEXT NOT NULL DEFAULT '',
            sla_due TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT 'import',
            raw_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS playbooks (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            engagement_id TEXT,
            title TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'ir',
            severity TEXT NOT NULL DEFAULT 'high',
            steps TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'draft',
            owner TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS campaigns (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            engagement_id TEXT,
            name TEXT NOT NULL,
            campaign_type TEXT NOT NULL DEFAULT 'phishing_sim',
            audience TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'planned',
            sent_count INTEGER NOT NULL DEFAULT 0,
            click_count INTEGER NOT NULL DEFAULT 0,
            report_count INTEGER NOT NULL DEFAULT 0,
            notes TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            engagement_id TEXT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'high',
            status TEXT NOT NULL DEFAULT 'open',
            source TEXT NOT NULL DEFAULT 'manual',
            owner TEXT NOT NULL DEFAULT '',
            playbook_id TEXT,
            summary TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS intel_watch (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'cve',
            value TEXT NOT NULL,
            notes TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS usage_events (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'chat_message',
            quantity INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS action_approvals (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            detail_json TEXT NOT NULL DEFAULT '{}',
            code TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            consumed_at REAL
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            payload_json TEXT NOT NULL DEFAULT '{}',
            result_json TEXT NOT NULL DEFAULT '{}',
            error TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            started_at REAL,
            finished_at REAL
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'info',
            title TEXT NOT NULL,
            body TEXT NOT NULL DEFAULT '',
            link TEXT NOT NULL DEFAULT '',
            read INTEGER NOT NULL DEFAULT 0,
            emailed INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS xdr_events (
            id TEXT PRIMARY KEY,
            vendor TEXT NOT NULL,
            external_id TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'detection',
            severity TEXT NOT NULL DEFAULT 'medium',
            host TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            linked_incident_id TEXT,
            linked_vuln_id TEXT,
            raw_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            UNIQUE(vendor, external_id)
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_events_created ON xdr_events(created_at DESC);
        """
    )
    c.commit()
    _migrate_users(c)
    _migrate_engagements(c)
    _migrate_assets(c)
    _migrate_remediation_plans(c)


def _migrate_users(c: Any) -> None:
    """Lightweight schema migrations for auth/MFA/OIDC."""
    cols = table_columns(c, "users")
    additions = {
        "mfa_secret": "TEXT NOT NULL DEFAULT ''",
        "mfa_enabled": "INTEGER NOT NULL DEFAULT 0",
        "email": "TEXT NOT NULL DEFAULT ''",
        "oidc_sub": "TEXT NOT NULL DEFAULT ''",
        "plan": "TEXT NOT NULL DEFAULT 'free'",
        "stripe_customer_id": "TEXT NOT NULL DEFAULT ''",
    }
    for name, typedef in additions.items():
        if name not in cols:
            c.execute(f"ALTER TABLE users ADD COLUMN {name} {typedef}")
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS mfa_pending (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at REAL NOT NULL,
            created_at REAL NOT NULL
        );
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS oidc_states (
            state TEXT PRIMARY KEY,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL
        );
        """
    )
    c.commit()


def _migrate_engagements(c: Any) -> None:
    """Lifecycle status + structured scope_json for tool policy."""
    cols = table_columns(c, "engagements")
    if "status" not in cols:
        c.execute("ALTER TABLE engagements ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
    cols = table_columns(c, "engagements")
    if "scope_json" not in cols:
        c.execute("ALTER TABLE engagements ADD COLUMN scope_json TEXT NOT NULL DEFAULT '[]'")
    c.commit()


def _migrate_assets(c: Any) -> None:
    """business_criticality is a distinct signal from the existing
    `criticality` column: `criticality` describes how critical the piece of
    infrastructure is (can it be rebuilt easily?), while business_criticality
    describes how critical the business function/data it serves is (a
    forgotten low-spec box holding the customer database is a real example
    of these two diverging). Optional and blank by default — the risk engine
    falls back to `criticality` when it's unset rather than fabricating a
    number, so this is additive, not a behavior change for anyone who never
    sets it.

    service_accounts is the same pattern applied to attack-path Identity
    nodes: there is no real IAM/AD/account-collection data source anywhere
    in this product, so rather than fabricate one, this is an optional,
    user-entered, explicitly-unverified free-text field (e.g. "svc-web-prod,
    deploy-bot"). The attack graph only emits Identity nodes when a user has
    actually filled this in, and always labels them as declared/unverified.
    """
    cols = table_columns(c, "assets")
    if "business_criticality" not in cols:
        c.execute("ALTER TABLE assets ADD COLUMN business_criticality TEXT NOT NULL DEFAULT ''")
    cols = table_columns(c, "assets")
    if "service_accounts" not in cols:
        c.execute("ALTER TABLE assets ADD COLUMN service_accounts TEXT NOT NULL DEFAULT ''")
    c.commit()
    _migrate_asset_dependencies(c)


def _migrate_asset_dependencies(c: Any) -> None:
    """The attack-path graph's connects_to edges. Nothing in this product
    observes real network traffic or application architecture, so there is
    no automatic source of truth for "WEB-01 talks to DB-01" — every edge
    here is either `source='declared'` (a user said so, confidence 1.0) or
    `source='inferred'` (a same-tenant heuristic guess — an internet-exposed
    asset paired with a database-categorized asset, confidence well below
    1.0, always rendered as "unconfirmed"). Declared edges always take
    priority over an inferred edge between the same pair.
    """
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_dependencies (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            engagement_id TEXT,
            org_id TEXT,
            source_asset_id TEXT NOT NULL,
            target_asset_id TEXT NOT NULL,
            relationship TEXT NOT NULL DEFAULT 'connects_to',
            source TEXT NOT NULL DEFAULT 'declared',
            confidence REAL NOT NULL DEFAULT 1.0,
            notes TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_asset_deps_source ON asset_dependencies(user_id, source_asset_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_asset_deps_target ON asset_dependencies(user_id, target_asset_id)"
    )
    c.commit()


def _migrate_remediation_plans(c: Any) -> None:
    """A Remediation Plan is a frozen snapshot of one Risk Reduction
    Simulator group (see app.services.risk_priority.compute_risk_simulation)
    at the moment it was created -- title/cve, how many findings and assets
    it covers, its estimated risk-reduction %, and its real attack-path
    disruption counts from app.services.attack_graph. Snapshotting matters
    because the underlying open-findings set changes over time (new scans,
    resolved vulns); a plan should keep showing what it targeted when a
    security team compared and approved it, not silently drift.

    disruption_band/explanation are DERIVED at creation time from real
    fields only (asset count, business-criticality of affected assets,
    how many have an online, currently-patchable SecuraIQ agent) -- see
    app.services.remediation for the exact, documented formula. Nothing
    here is a model-invented estimate.

    campaign_id links a plan to a real securaiq_patch_campaigns row once
    one exists for it (see app.agents.create_campaign) -- a plan can only
    reach status='executing' once a real campaign is linked; there is no
    automatic multi-asset campaign fabrication here, since campaigns today
    can only represent a package-manager upgrade (SUPPORTED_COMMAND_KINDS
    in app.agents), and guessing that safely across many assets at once is
    not something this product does blindly.
    """
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS remediation_plans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            engagement_id TEXT,
            org_id TEXT,
            group_key TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            cve TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'draft',
            vulns_removed INTEGER NOT NULL DEFAULT 0,
            assets_affected INTEGER NOT NULL DEFAULT 0,
            asset_ids_json TEXT NOT NULL DEFAULT '[]',
            internet_exposed_assets INTEGER NOT NULL DEFAULT 0,
            business_critical_assets INTEGER NOT NULL DEFAULT 0,
            agent_patchable_assets INTEGER NOT NULL DEFAULT 0,
            kev INTEGER NOT NULL DEFAULT 0,
            quick_win INTEGER NOT NULL DEFAULT 0,
            critical_high_count INTEGER NOT NULL DEFAULT 0,
            estimated_risk_reduction_pct REAL NOT NULL DEFAULT 0.0,
            attack_paths_disrupted INTEGER NOT NULL DEFAULT 0,
            business_critical_paths_disrupted INTEGER NOT NULL DEFAULT 0,
            verified_attack_paths_disrupted INTEGER NOT NULL DEFAULT 0,
            disruption_band TEXT NOT NULL DEFAULT 'low',
            explanation TEXT NOT NULL DEFAULT '',
            campaign_id TEXT,
            risk_before REAL,
            risk_after REAL,
            approved_at REAL,
            approved_by TEXT NOT NULL DEFAULT '',
            measured_at REAL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_remediation_plans_user ON remediation_plans(user_id, created_at DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_remediation_plans_group ON remediation_plans(user_id, group_key)")
    cols = table_columns(c, "remediation_plans")
    if "verified_attack_paths_disrupted" not in cols:
        # Added after the initial table: how many of attack_paths_disrupted
        # have EVERY edge verified (declared/confirmed) -- a path with even
        # one inferred hop is not "confirmed", per the graph's evidence
        # contract. Existing rows default to 0 (unknown at the time they
        # were created) rather than silently claiming confirmation.
        c.execute("ALTER TABLE remediation_plans ADD COLUMN verified_attack_paths_disrupted INTEGER NOT NULL DEFAULT 0")
    c.commit()


def new_id() -> str:
    return uuid.uuid4().hex


def now() -> float:
    return time.time()


def row_to_dict(row: Any) -> dict[str, Any] | None:
    if row is None:
        return None
    if isinstance(row, dict):
        return dict(row)
    return dict(row)


def audit(action: str, user_id: str | None = None, detail: dict[str, Any] | None = None) -> None:
    c = get_conn()
    c.execute(
        "INSERT INTO audit_log (id, user_id, action, detail, created_at) VALUES (?, ?, ?, ?, ?)",
        (new_id(), user_id, action, json.dumps(detail or {}), now()),
    )
    c.commit()

    try:
        from app.siem import log_security_event

        log_security_event(action, user_id, detail)
    except Exception:
        pass  # logging/SIEM forwarding must never break the calling workflow
