"""Many-to-many Evidence ↔ Control mapping."""

from __future__ import annotations

from typing import Any

from app.db import get_conn, new_id, now, row_to_dict
from app.evidence_spine.schema import ensure_evidence_spine_schema
from app.services.evidence import get_evidence

VALID_ROLES = {"satisfies", "supports", "documents", "verifies"}


def link_evidence_to_control(
    user_id: str,
    evidence_id: str,
    *,
    control_id: str,
    framework_id: str = "",
    role: str = "supports",
    org_id: str | None = None,
    propagate_canonical: bool = False,
) -> dict[str, Any]:
    """Attach evidence to a control (idempotent on unique key).

    When ``propagate_canonical=True``, also link as ``supports`` to sibling
    controls under the same canonical registry entry (cross-framework).
    """
    ensure_evidence_spine_schema()
    cid = (control_id or "").strip()
    if not cid:
        raise ValueError("control_id is required")
    ev = get_evidence(user_id, evidence_id)
    if not ev:
        raise ValueError("evidence not found")
    r = (role or "supports").strip().lower()
    if r not in VALID_ROLES:
        raise ValueError(f"role must be one of {sorted(VALID_ROLES)}")
    from app.tenancy import primary_org_id

    oid = org_id or ev.get("org_id") or primary_org_id(user_id)
    fid = (framework_id or "").strip()
    c = get_conn()
    existing = c.execute(
        """
        SELECT * FROM evidence_control_map
        WHERE user_id = ? AND evidence_id = ? AND framework_id = ? AND control_id = ?
        """,
        (user_id, evidence_id, fid, cid),
    ).fetchone()
    if existing:
        c.execute(
            "UPDATE evidence_control_map SET role = ? WHERE id = ?",
            (r, existing["id"]),
        )
        c.commit()
        row = c.execute(
            "SELECT * FROM evidence_control_map WHERE id = ?", (existing["id"],)
        ).fetchone()
        out = row_to_dict(row)
    else:
        mid = new_id()
        c.execute(
            """
            INSERT INTO evidence_control_map
            (id, user_id, org_id, evidence_id, framework_id, control_id, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (mid, user_id, oid, evidence_id, fid, cid, r, now()),
        )
        c.commit()
        out = row_to_dict(
            c.execute("SELECT * FROM evidence_control_map WHERE id = ?", (mid,)).fetchone()
        )
    try:
        from app.realtime_events import publish_aliased

        publish_aliased(
            "evidence.linked",
            aliases=["evidence.updated"],
            evidence_id=evidence_id,
            control_id=cid,
            framework_id=fid,
            role=r,
            user_id=user_id,
        )
    except Exception:
        pass

    if propagate_canonical and fid and out:
        try:
            from app.services.cross_framework_evidence import (
                propagate_evidence_to_canonical_siblings,
            )

            out["canonical_propagation"] = propagate_evidence_to_canonical_siblings(
                user_id,
                evidence_id,
                framework_id=fid,
                control_id=cid,
                role=r,
                org_id=oid,
            )
        except Exception as exc:
            out["canonical_propagation"] = {"ok": False, "error": str(exc)}

    return out  # type: ignore[return-value]


def unlink_evidence_from_control(
    user_id: str,
    evidence_id: str,
    *,
    control_id: str,
    framework_id: str = "",
) -> bool:
    ensure_evidence_spine_schema()
    cur = get_conn().execute(
        """
        DELETE FROM evidence_control_map
        WHERE user_id = ? AND evidence_id = ? AND framework_id = ? AND control_id = ?
        """,
        (user_id, evidence_id, (framework_id or "").strip(), (control_id or "").strip()),
    )
    get_conn().commit()
    return cur.rowcount > 0


def list_evidence_for_control(
    user_id: str,
    *,
    control_id: str,
    framework_id: str = "",
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Evidence rows mapped to a control (with freshness)."""
    ensure_evidence_spine_schema()
    cid = (control_id or "").strip()
    if not cid:
        return []
    fid = (framework_id or "").strip()
    c = get_conn()
    if fid:
        rows = c.execute(
            """
            SELECT m.role AS map_role, m.framework_id AS map_framework_id,
                   m.control_id AS map_control_id, m.created_at AS mapped_at,
                   e.*
            FROM evidence_control_map m
            JOIN securaiq_evidence e ON e.id = m.evidence_id
            WHERE m.user_id = ? AND m.control_id = ? AND m.framework_id = ?
            ORDER BY e.last_seen DESC
            LIMIT ?
            """,
            (user_id, cid, fid, max(1, min(limit, 500))),
        ).fetchall()
    else:
        rows = c.execute(
            """
            SELECT m.role AS map_role, m.framework_id AS map_framework_id,
                   m.control_id AS map_control_id, m.created_at AS mapped_at,
                   e.*
            FROM evidence_control_map m
            JOIN securaiq_evidence e ON e.id = m.evidence_id
            WHERE m.user_id = ? AND m.control_id = ?
            ORDER BY e.last_seen DESC
            LIMIT ?
            """,
            (user_id, cid, max(1, min(limit, 500))),
        ).fetchall()
    from app.services.evidence import freshness_status
    import json

    out: list[dict[str, Any]] = []
    for row in rows:
        d = dict(row)
        try:
            d["detail"] = json.loads(d.get("detail_json") or "{}")
        except Exception:
            d["detail"] = {}
        d["verified"] = bool(d.get("verified"))
        d["freshness_status"] = freshness_status(d)
        d["map_role"] = d.get("map_role") or "supports"
        out.append(d)
    return out


def list_controls_for_evidence(user_id: str, evidence_id: str) -> list[dict[str, Any]]:
    ensure_evidence_spine_schema()
    rows = get_conn().execute(
        """
        SELECT * FROM evidence_control_map
        WHERE user_id = ? AND evidence_id = ?
        ORDER BY created_at DESC
        """,
        (user_id, evidence_id),
    ).fetchall()
    return [row_to_dict(r) for r in rows]
