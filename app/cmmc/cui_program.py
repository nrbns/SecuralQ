"""CUI program — first-class scope container above asset categories."""

from __future__ import annotations

import json
from typing import Any

from app.cmmc.schema import ensure_cmmc_assessment_schema
from app.db import get_conn, new_id, now, row_to_dict


def upsert_cui_program(
    user_id: str,
    *,
    name: str,
    description: str = "",
    boundary_notes: str = "",
    categories: list[str] | None = None,
    external_providers: list[dict[str, Any]] | None = None,
    data_flows: list[dict[str, Any]] | None = None,
    org_id: str | None = None,
    program_id: str | None = None,
) -> dict[str, Any]:
    ensure_cmmc_assessment_schema()
    if not (name or "").strip():
        raise ValueError("name is required")
    from app.tenancy import primary_org_id

    oid = org_id or primary_org_id(user_id)
    t = now()
    if program_id:
        existing = get_conn().execute(
            "SELECT id FROM cmmc_cui_program WHERE id = ? AND user_id = ?",
            (program_id, user_id),
        ).fetchone()
        if not existing:
            raise ValueError("CUI program not found")
        get_conn().execute(
            """
            UPDATE cmmc_cui_program SET
                name = ?, description = ?, boundary_notes = ?,
                categories_json = ?, external_providers_json = ?, data_flows_json = ?,
                updated_at = ?, org_id = COALESCE(?, org_id)
            WHERE id = ?
            """,
            (
                name[:300],
                description[:4000],
                boundary_notes[:4000],
                json.dumps(categories or [])[:4000],
                json.dumps(external_providers or [])[:8000],
                json.dumps(data_flows or [])[:8000],
                t,
                oid,
                program_id,
            ),
        )
        get_conn().commit()
        return get_cui_program(user_id, program_id) or {"id": program_id}

    rid = new_id()
    get_conn().execute(
        """
        INSERT INTO cmmc_cui_program
        (id, user_id, org_id, name, description, boundary_notes, categories_json,
         external_providers_json, data_flows_json, meta_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?)
        """,
        (
            rid,
            user_id,
            oid,
            name[:300],
            description[:4000],
            boundary_notes[:4000],
            json.dumps(categories or [])[:4000],
            json.dumps(external_providers or [])[:8000],
            json.dumps(data_flows or [])[:8000],
            t,
            t,
        ),
    )
    get_conn().commit()
    return get_cui_program(user_id, rid) or {"id": rid}


def get_cui_program(user_id: str, program_id: str) -> dict[str, Any] | None:
    ensure_cmmc_assessment_schema()
    row = get_conn().execute(
        "SELECT * FROM cmmc_cui_program WHERE id = ? AND user_id = ?",
        (program_id, user_id),
    ).fetchone()
    return _hydrate(row_to_dict(row)) if row else None


def list_cui_programs(user_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
    ensure_cmmc_assessment_schema()
    from app.tenancy import tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id)
    rows = get_conn().execute(
        f"SELECT * FROM cmmc_cui_program WHERE {where} ORDER BY updated_at DESC LIMIT ?",
        [*args, max(1, min(limit, 200))],
    ).fetchall()
    return [_hydrate(row_to_dict(r)) for r in rows]


def _hydrate(d: dict[str, Any]) -> dict[str, Any]:
    for key, alias in (
        ("categories_json", "categories"),
        ("external_providers_json", "external_providers"),
        ("data_flows_json", "data_flows"),
        ("meta_json", "meta"),
    ):
        try:
            d[alias] = json.loads(d.get(key) or ("[]" if alias != "meta" else "{}"))
        except Exception:
            d[alias] = [] if alias != "meta" else {}
    return d
