"""Evidence dependency packs — a control may require multiple evidence slots.

Example:
  Employee security training
    ├── policy document (documents)
    ├── completion report (documents)
    └── observed enrollment signal (satisfies)

If any required slot is missing or stale → control cannot be PASS.
"""

from __future__ import annotations

from typing import Any

from app.db import get_conn, new_id, now, row_to_dict
from app.evidence_spine.mapping import list_evidence_for_control
from app.evidence_spine.schema import ensure_evidence_spine_schema

DEFAULT_PACKS: list[dict[str, Any]] = [
    {
        "framework_id": "",
        "control_id": "AT-2",
        "slots": [
            {"slot_key": "policy", "title": "Security awareness policy", "role": "documents"},
            {"slot_key": "completion", "title": "Training completion report", "role": "documents"},
        ],
    },
    {
        "framework_id": "",
        "control_id": "AC-1",
        "slots": [
            {"slot_key": "policy", "title": "Access control policy", "role": "documents"},
            {"slot_key": "runtime", "title": "Live access/MFA observation", "role": "satisfies"},
        ],
    },
    {
        "framework_id": "",
        "control_id": "host_firewall",
        "slots": [
            {"slot_key": "runtime", "title": "Agent firewall observation", "role": "satisfies"},
        ],
    },
]


def ensure_dependency_schema() -> None:
    ensure_evidence_spine_schema()
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS evidence_requirements (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            framework_id TEXT NOT NULL DEFAULT '',
            control_id TEXT NOT NULL,
            slot_key TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            required_role TEXT NOT NULL DEFAULT 'supports',
            min_count INTEGER NOT NULL DEFAULT 1,
            enabled INTEGER NOT NULL DEFAULT 1,
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            UNIQUE(user_id, framework_id, control_id, slot_key)
        );
        CREATE INDEX IF NOT EXISTS idx_ereq_control
            ON evidence_requirements(user_id, framework_id, control_id);
        """
    )
    c.commit()


def seed_default_packs(user_id: str, *, force: bool = False) -> dict[str, Any]:
    ensure_dependency_schema()
    from app.tenancy import primary_org_id

    oid = primary_org_id(user_id)
    existing = get_conn().execute(
        "SELECT COUNT(*) AS n FROM evidence_requirements WHERE user_id = ?",
        (user_id,),
    ).fetchone()["n"]
    if existing and not force:
        return {"ok": True, "seeded": 0, "note": "packs already present"}
    n = 0
    t = now()
    for pack in DEFAULT_PACKS:
        for slot in pack["slots"]:
            try:
                get_conn().execute(
                    """
                    INSERT OR IGNORE INTO evidence_requirements
                    (id, user_id, org_id, framework_id, control_id, slot_key, title,
                     required_role, min_count, enabled, meta_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, '{}', ?)
                    """,
                    (
                        new_id(),
                        user_id,
                        oid,
                        pack.get("framework_id") or "",
                        pack["control_id"],
                        slot["slot_key"],
                        slot.get("title") or slot["slot_key"],
                        slot.get("role") or "supports",
                        t,
                    ),
                )
                n += 1
            except Exception:
                pass
    get_conn().commit()
    return {"ok": True, "seeded": n}


def list_requirements(
    user_id: str,
    *,
    control_id: str = "",
    framework_id: str = "",
) -> list[dict[str, Any]]:
    ensure_dependency_schema()
    q = "SELECT * FROM evidence_requirements WHERE user_id = ? AND enabled = 1"
    args: list[Any] = [user_id]
    if control_id:
        q += " AND control_id = ?"
        args.append(control_id)
    if framework_id:
        q += " AND (framework_id = ? OR framework_id = '')"
        args.append(framework_id)
    q += " ORDER BY control_id, slot_key"
    return [row_to_dict(r) for r in get_conn().execute(q, args).fetchall()]


def upsert_requirement(
    user_id: str,
    *,
    control_id: str,
    slot_key: str,
    title: str = "",
    framework_id: str = "",
    required_role: str = "supports",
    min_count: int = 1,
) -> dict[str, Any]:
    ensure_dependency_schema()
    from app.tenancy import primary_org_id

    cid = (control_id or "").strip()
    sk = (slot_key or "").strip()
    if not cid or not sk:
        raise ValueError("control_id and slot_key required")
    existing = get_conn().execute(
        """
        SELECT id FROM evidence_requirements
        WHERE user_id = ? AND framework_id = ? AND control_id = ? AND slot_key = ?
        """,
        (user_id, framework_id or "", cid, sk),
    ).fetchone()
    if existing:
        get_conn().execute(
            """
            UPDATE evidence_requirements
            SET title = ?, required_role = ?, min_count = ?, enabled = 1
            WHERE id = ?
            """,
            (
                (title or sk)[:200],
                (required_role or "supports")[:40],
                max(1, int(min_count)),
                existing["id"],
            ),
        )
        get_conn().commit()
        rid = existing["id"]
    else:
        rid = new_id()
        get_conn().execute(
            """
            INSERT INTO evidence_requirements
            (id, user_id, org_id, framework_id, control_id, slot_key, title,
             required_role, min_count, enabled, meta_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, '{}', ?)
            """,
            (
                rid,
                user_id,
                primary_org_id(user_id),
                framework_id or "",
                cid,
                sk,
                (title or sk)[:200],
                (required_role or "supports")[:40],
                max(1, int(min_count)),
                now(),
            ),
        )
        get_conn().commit()
    row = get_conn().execute(
        "SELECT * FROM evidence_requirements WHERE id = ?", (rid,)
    ).fetchone()
    return row_to_dict(row)  # type: ignore[return-value]


def evaluate_dependencies(
    user_id: str,
    *,
    control_id: str,
    framework_id: str = "",
) -> dict[str, Any]:
    """Check whether required evidence slots are satisfied."""
    reqs = list_requirements(user_id, control_id=control_id, framework_id=framework_id)
    if not reqs:
        return {
            "ok": True,
            "control_id": control_id,
            "framework_id": framework_id,
            "required": False,
            "complete": True,
            "slots": [],
            "note": "No evidence dependency pack configured for this control.",
        }
    evidence = list_evidence_for_control(
        user_id, control_id=control_id, framework_id=framework_id, limit=200
    )
    slots_out: list[dict[str, Any]] = []
    missing = 0
    for req in reqs:
        role = (req.get("required_role") or "supports").lower()
        min_n = int(req.get("min_count") or 1)
        matched = []
        for ev in evidence:
            map_role = (ev.get("map_role") or "").lower()
            src = (ev.get("source") or "").lower()
            et = (ev.get("entity_type") or "").lower()
            fresh = (ev.get("freshness_status") or "fresh").lower()
            if fresh in {"expired"}:
                continue
            if role == "documents" and (
                map_role == "documents" or et == "document" or src == "declared"
            ):
                matched.append(ev)
            elif role == "satisfies" and (
                map_role == "satisfies"
                or et in {"observation", "agent_host_control", "control_result"}
                or src == "observed"
            ):
                matched.append(ev)
            elif role == "supports":
                matched.append(ev)
            elif role == "verifies" and map_role == "verifies":
                matched.append(ev)
        ok = len(matched) >= min_n
        if not ok:
            missing += 1
        slots_out.append(
            {
                "slot_key": req.get("slot_key"),
                "title": req.get("title"),
                "required_role": role,
                "min_count": min_n,
                "found": len(matched),
                "satisfied": ok,
                "evidence_ids": [m.get("id") for m in matched[:10]],
            }
        )
    complete = missing == 0
    return {
        "ok": True,
        "control_id": control_id,
        "framework_id": framework_id,
        "required": True,
        "complete": complete,
        "slots": slots_out,
        "missing_slots": missing,
        "note": (
            "All required evidence slots present."
            if complete
            else f"{missing} required evidence slot(s) missing or stale."
        ),
    }
