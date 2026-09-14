"""Signed agent update metadata (server-side).

Builds on the existing agent_upgrade command path. Adds Ed25519-signed release
metadata + previous-version checksum for rollback. Authenticode/package
signing for MSI/DEB remains a separate CI concern.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.config import settings
from app.db import get_conn, new_id, now, table_columns
from app.paths import resource_root


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS agent_updates (
            id TEXT PRIMARY KEY,
            version TEXT NOT NULL,
            platform TEXT NOT NULL DEFAULT 'all',
            download_url TEXT NOT NULL DEFAULT '',
            sha256 TEXT NOT NULL,
            signature TEXT NOT NULL DEFAULT '',
            previous_sha256 TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            published_at REAL NOT NULL,
            revoked_at REAL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_agent_updates_pub ON agent_updates(published_at DESC)"
    )
    c.commit()


def _script_bytes() -> bytes:
    path = resource_root() / "scripts" / "securaiq_agent.py"
    if not path.is_file():
        raise ValueError("Agent script not found on this server")
    return path.read_bytes()


def _script_sha256() -> str:
    return hashlib.sha256(_script_bytes()).hexdigest()


def _sign_release(payload: dict[str, Any]) -> str:
    from app.agent_security import ed25519_sign, generate_ed25519_keypair

    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    priv = (getattr(settings, "agent_ed25519_private_key", "") or "").strip()
    if not priv:
        priv = (getattr(settings, "license_ed25519_private_key", "") or "").strip()
    if not priv:
        # Lab ephemeral — same process only
        priv = generate_ed25519_keypair()["private_b64"]
    return ed25519_sign(body, private_key=priv)


def publish_script_release(
    *,
    version: str,
    notes: str = "",
    previous_sha256: str = "",
    platform: str = "all",
) -> dict[str, Any]:
    """Publish current scripts/securaiq_agent.py as a signed update record."""
    ensure_schema()
    sha = _script_sha256()
    download_url = "/api/agents/install-script"
    meta = {
        "version": version,
        "platform": platform,
        "download_url": download_url,
        "sha256": sha,
        "previous_sha256": previous_sha256 or "",
    }
    sig = _sign_release(meta)
    rid = new_id()
    ts = now()
    c = get_conn()
    c.execute(
        """
        INSERT INTO agent_updates
        (id, version, platform, download_url, sha256, signature, previous_sha256, notes, published_at, revoked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        """,
        (
            rid,
            version,
            platform,
            download_url,
            sha,
            sig,
            previous_sha256 or "",
            notes or "",
            ts,
        ),
    )
    c.commit()
    return get_latest_update(platform=platform) or {}


def _live_agent_version() -> str:
    import re

    path = resource_root() / "scripts" / "securaiq_agent.py"
    if not path.is_file():
        return "unknown"
    m = re.search(r'AGENT_VERSION\s*=\s*"([^"]+)"', path.read_text(encoding="utf-8"))
    return m.group(1) if m else "unknown"


def get_latest_update(*, platform: str = "all") -> dict[str, Any] | None:
    ensure_schema()
    c = get_conn()
    row = c.execute(
        "SELECT * FROM agent_updates WHERE revoked_at IS NULL "
        "AND (platform = ? OR platform = 'all') ORDER BY published_at DESC LIMIT 1",
        (platform,),
    ).fetchone()
    if not row:
        try:
            sha = _script_sha256()
        except ValueError:
            return None
        meta = {
            "version": _live_agent_version(),
            "platform": "all",
            "download_url": "/api/agents/install-script",
            "sha256": sha,
            "previous_sha256": "",
        }
        try:
            sig = _sign_release(meta)
        except Exception:
            sig = ""
        return {
            "id": None,
            "version": meta["version"],
            "platform": "all",
            "download_url": meta["download_url"],
            "sha256": sha,
            "signature": sig,
            "previous_sha256": "",
            "notes": "live script (not published row)",
            "published_at": now(),
            "synthetic": True,
        }
    return dict(row)


def upgrade_payload_from_latest(*, platform: str = "all") -> dict[str, Any]:
    """Payload for agent_upgrade command — sha256 + optional Ed25519 seal + rollback sha."""
    latest = get_latest_update(platform=platform) or {}
    pub = (getattr(settings, "agent_ed25519_public_key", "") or "").strip()
    if not pub:
        pub = (getattr(settings, "license_ed25519_public_key", "") or "").strip()
    plat = latest.get("platform") or platform or "all"
    return {
        "expected_sha256": latest.get("sha256") or _script_sha256(),
        "download_url": latest.get("download_url") or "/api/agents/install-script",
        "version": latest.get("version") or "",
        "platform": plat,
        "signature": latest.get("signature") or "",
        "previous_sha256": latest.get("previous_sha256") or "",
        "alg": "ed25519" if latest.get("signature") else "",
        "signing_public_key": pub,
    }
