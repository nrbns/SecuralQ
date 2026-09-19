"""SQLite/Postgres-friendly data governance store (declarations + request tracking)."""

from __future__ import annotations

import json
from typing import Any

from app.db import get_conn, new_id, now, row_to_dict

_LEGAL = (
    "Evidence-backed privacy inventory for authorised assessments — not a legal "
    "determination of DPDP/GDPR compliance. SDF applicability defaults to unknown."
)


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS dg_org_privacy_profile (
            user_id TEXT PRIMARY KEY,
            sdf_status TEXT NOT NULL DEFAULT 'unknown',
            jurisdiction TEXT NOT NULL DEFAULT 'IN',
            notes TEXT NOT NULL DEFAULT '',
            meta_json TEXT NOT NULL DEFAULT '{}',
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS dg_data_elements (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            classification TEXT NOT NULL DEFAULT 'personal_data',
            purpose TEXT NOT NULL DEFAULT '',
            source_system TEXT NOT NULL DEFAULT '',
            storage_system TEXT NOT NULL DEFAULT '',
            owner TEXT NOT NULL DEFAULT '',
            retention_days INTEGER,
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_dg_elements_user ON dg_data_elements(user_id, updated_at DESC)"
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS dg_processing_activities (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            purpose TEXT NOT NULL DEFAULT '',
            lawful_basis TEXT NOT NULL DEFAULT '',
            data_element_ids_json TEXT NOT NULL DEFAULT '[]',
            systems_json TEXT NOT NULL DEFAULT '[]',
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS dg_data_flows (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            from_system TEXT NOT NULL DEFAULT '',
            to_system TEXT NOT NULL DEFAULT '',
            data_element_ids_json TEXT NOT NULL DEFAULT '[]',
            processor_id TEXT NOT NULL DEFAULT '',
            cross_border INTEGER NOT NULL DEFAULT 0,
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS dg_processors (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'processor',
            purposes TEXT NOT NULL DEFAULT '',
            data_categories TEXT NOT NULL DEFAULT '',
            contract_ref TEXT NOT NULL DEFAULT '',
            security_requirements TEXT NOT NULL DEFAULT '',
            sub_processors TEXT NOT NULL DEFAULT '',
            offboarded INTEGER NOT NULL DEFAULT 0,
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS dg_retention_policies (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            purpose TEXT NOT NULL DEFAULT '',
            retention_days INTEGER,
            deletion_method TEXT NOT NULL DEFAULT '',
            backup_handling TEXT NOT NULL DEFAULT '',
            data_element_ids_json TEXT NOT NULL DEFAULT '[]',
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS dg_principal_requests (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            request_type TEXT NOT NULL,
            principal_ref TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            sla_due_at REAL,
            received_at REAL NOT NULL,
            closed_at REAL,
            notes TEXT NOT NULL DEFAULT '',
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    c.commit()


def _json_list(val: Any) -> str:
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            if isinstance(parsed, list):
                return json.dumps(parsed)
        except Exception:
            return json.dumps([val] if val else [])
    if isinstance(val, list):
        return json.dumps(val)
    return "[]"


def _row(r: Any) -> dict[str, Any]:
    d = row_to_dict(r) or {}
    for key in (
        "meta_json",
        "data_element_ids_json",
        "systems_json",
    ):
        if key in d and isinstance(d[key], str):
            try:
                d[key.replace("_json", "")] = json.loads(d[key] or ("{}" if "meta" in key else "[]"))
            except Exception:
                d[key.replace("_json", "")] = {} if "meta" in key else []
    if "meta" not in d and "meta_json" in d:
        try:
            d["meta"] = json.loads(d.get("meta_json") or "{}")
        except Exception:
            d["meta"] = {}
    return d


def get_org_privacy_profile(user_id: str) -> dict[str, Any]:
    ensure_schema()
    c = get_conn()
    row = c.execute(
        "SELECT * FROM dg_org_privacy_profile WHERE user_id = ?", (user_id,)
    ).fetchone()
    if not row:
        return {
            "user_id": user_id,
            "sdf_status": "unknown",
            "jurisdiction": "IN",
            "notes": "",
            "meta": {},
            "legal_disclaimer": _LEGAL,
        }
    d = _row(row)
    d["legal_disclaimer"] = _LEGAL
    return d


def set_org_privacy_profile(
    user_id: str,
    *,
    sdf_status: str = "unknown",
    jurisdiction: str = "IN",
    notes: str = "",
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ensure_schema()
    status = (sdf_status or "unknown").strip().lower()
    if status not in {
        "unknown",
        "not_applicable",
        "applicable_pending_review",
        "applicable",
    }:
        status = "unknown"
    ts = now()
    c = get_conn()
    existing = c.execute(
        "SELECT user_id FROM dg_org_privacy_profile WHERE user_id = ?", (user_id,)
    ).fetchone()
    meta_s = json.dumps(meta or {})
    if existing:
        c.execute(
            """
            UPDATE dg_org_privacy_profile
            SET sdf_status=?, jurisdiction=?, notes=?, meta_json=?, updated_at=?
            WHERE user_id=?
            """,
            (status, jurisdiction or "IN", notes or "", meta_s, ts, user_id),
        )
    else:
        c.execute(
            """
            INSERT INTO dg_org_privacy_profile
            (user_id, sdf_status, jurisdiction, notes, meta_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, status, jurisdiction or "IN", notes or "", meta_s, ts),
        )
    c.commit()
    return get_org_privacy_profile(user_id)


def upsert_data_element(user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    ensure_schema()
    eid = str(payload.get("id") or new_id())
    ts = now()
    c = get_conn()
    existing = c.execute(
        "SELECT created_at FROM dg_data_elements WHERE id = ? AND user_id = ?",
        (eid, user_id),
    ).fetchone()
    created = float((row_to_dict(existing) or {}).get("created_at") or ts) if existing else ts
    args = (
        str(payload.get("name") or "").strip() or "unnamed",
        str(payload.get("classification") or "personal_data"),
        str(payload.get("purpose") or ""),
        str(payload.get("source_system") or ""),
        str(payload.get("storage_system") or ""),
        str(payload.get("owner") or ""),
        payload.get("retention_days"),
        json.dumps(payload.get("meta") or {}),
        ts,
    )
    if existing:
        c.execute(
            """
            UPDATE dg_data_elements SET
                name=?, classification=?, purpose=?, source_system=?, storage_system=?,
                owner=?, retention_days=?, meta_json=?, updated_at=?
            WHERE id=? AND user_id=?
            """,
            (*args, eid, user_id),
        )
    else:
        c.execute(
            """
            INSERT INTO dg_data_elements (
                id, user_id, name, classification, purpose, source_system, storage_system,
                owner, retention_days, meta_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (eid, user_id, *args[:-1], created, ts),
        )
    c.commit()
    row = _row(c.execute("SELECT * FROM dg_data_elements WHERE id = ?", (eid,)).fetchone())
    _publish_privacy(user_id, "privacy.inventory.changed", element_id=eid)
    return row


def list_data_elements(user_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
    ensure_schema()
    lim = max(1, min(int(limit or 500), 2000))
    rows = get_conn().execute(
        "SELECT * FROM dg_data_elements WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?",
        (user_id, lim),
    ).fetchall()
    return [_row(r) for r in rows]


def upsert_processing_activity(user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    ensure_schema()
    eid = str(payload.get("id") or new_id())
    ts = now()
    c = get_conn()
    existing = c.execute(
        "SELECT created_at FROM dg_processing_activities WHERE id = ? AND user_id = ?",
        (eid, user_id),
    ).fetchone()
    created = float((row_to_dict(existing) or {}).get("created_at") or ts) if existing else ts
    name = str(payload.get("name") or "").strip() or "activity"
    purpose = str(payload.get("purpose") or "")
    basis = str(payload.get("lawful_basis") or "")
    elems = _json_list(payload.get("data_element_ids") or payload.get("data_elements"))
    systems = _json_list(payload.get("systems"))
    meta_s = json.dumps(payload.get("meta") or {})
    if existing:
        c.execute(
            """
            UPDATE dg_processing_activities SET
                name=?, purpose=?, lawful_basis=?, data_element_ids_json=?,
                systems_json=?, meta_json=?, updated_at=?
            WHERE id=? AND user_id=?
            """,
            (name, purpose, basis, elems, systems, meta_s, ts, eid, user_id),
        )
    else:
        c.execute(
            """
            INSERT INTO dg_processing_activities (
                id, user_id, name, purpose, lawful_basis, data_element_ids_json,
                systems_json, meta_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (eid, user_id, name, purpose, basis, elems, systems, meta_s, created, ts),
        )
    c.commit()
    row = _row(c.execute("SELECT * FROM dg_processing_activities WHERE id = ?", (eid,)).fetchone())
    _publish_privacy(user_id, "privacy.inventory.changed", activity_id=eid)
    return row

def list_processing_activities(user_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
    ensure_schema()
    lim = max(1, min(int(limit or 500), 2000))
    rows = get_conn().execute(
        "SELECT * FROM dg_processing_activities WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?",
        (user_id, lim),
    ).fetchall()
    return [_row(r) for r in rows]


def upsert_data_flow(user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    ensure_schema()
    eid = str(payload.get("id") or new_id())
    ts = now()
    c = get_conn()
    existing = c.execute(
        "SELECT created_at FROM dg_data_flows WHERE id = ? AND user_id = ?",
        (eid, user_id),
    ).fetchone()
    created = float((row_to_dict(existing) or {}).get("created_at") or ts) if existing else ts
    name = str(payload.get("name") or "").strip() or "flow"
    frm = str(payload.get("from_system") or "")
    to = str(payload.get("to_system") or "")
    elems = _json_list(payload.get("data_element_ids"))
    proc = str(payload.get("processor_id") or "")
    xb = 1 if payload.get("cross_border") else 0
    meta_s = json.dumps(payload.get("meta") or {})
    if existing:
        c.execute(
            """
            UPDATE dg_data_flows SET
                name=?, from_system=?, to_system=?, data_element_ids_json=?,
                processor_id=?, cross_border=?, meta_json=?, updated_at=?
            WHERE id=? AND user_id=?
            """,
            (name, frm, to, elems, proc, xb, meta_s, ts, eid, user_id),
        )
    else:
        c.execute(
            """
            INSERT INTO dg_data_flows (
                id, user_id, name, from_system, to_system, data_element_ids_json,
                processor_id, cross_border, meta_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (eid, user_id, name, frm, to, elems, proc, xb, meta_s, created, ts),
        )
    c.commit()
    row = _row(c.execute("SELECT * FROM dg_data_flows WHERE id = ?", (eid,)).fetchone())
    _publish_privacy(user_id, "privacy.inventory.changed", flow_id=eid)
    return row

def list_data_flows(user_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
    ensure_schema()
    lim = max(1, min(int(limit or 500), 2000))
    rows = get_conn().execute(
        "SELECT * FROM dg_data_flows WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?",
        (user_id, lim),
    ).fetchall()
    return [_row(r) for r in rows]


def upsert_processor(user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    ensure_schema()
    eid = str(payload.get("id") or new_id())
    ts = now()
    c = get_conn()
    existing = c.execute(
        "SELECT created_at FROM dg_processors WHERE id = ? AND user_id = ?",
        (eid, user_id),
    ).fetchone()
    created = float((row_to_dict(existing) or {}).get("created_at") or ts) if existing else ts
    vals = (
        str(payload.get("name") or "").strip() or "processor",
        str(payload.get("role") or "processor"),
        str(payload.get("purposes") or ""),
        str(payload.get("data_categories") or ""),
        str(payload.get("contract_ref") or ""),
        str(payload.get("security_requirements") or ""),
        str(payload.get("sub_processors") or ""),
        1 if payload.get("offboarded") else 0,
        json.dumps(payload.get("meta") or {}),
    )
    if existing:
        c.execute(
            """
            UPDATE dg_processors SET
                name=?, role=?, purposes=?, data_categories=?, contract_ref=?,
                security_requirements=?, sub_processors=?, offboarded=?, meta_json=?, updated_at=?
            WHERE id=? AND user_id=?
            """,
            (*vals, ts, eid, user_id),
        )
    else:
        c.execute(
            """
            INSERT INTO dg_processors (
                id, user_id, name, role, purposes, data_categories, contract_ref,
                security_requirements, sub_processors, offboarded, meta_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (eid, user_id, *vals, created, ts),
        )
    c.commit()
    row = _row(c.execute("SELECT * FROM dg_processors WHERE id = ?", (eid,)).fetchone())
    _publish_privacy(user_id, "privacy.processor.changed", processor_id=eid)
    return row

def list_processors(user_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
    ensure_schema()
    lim = max(1, min(int(limit or 500), 2000))
    rows = get_conn().execute(
        "SELECT * FROM dg_processors WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?",
        (user_id, lim),
    ).fetchall()
    return [_row(r) for r in rows]


def upsert_retention_policy(user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    ensure_schema()
    eid = str(payload.get("id") or new_id())
    ts = now()
    c = get_conn()
    existing = c.execute(
        "SELECT created_at FROM dg_retention_policies WHERE id = ? AND user_id = ?",
        (eid, user_id),
    ).fetchone()
    created = float((row_to_dict(existing) or {}).get("created_at") or ts) if existing else ts
    name = str(payload.get("name") or "").strip() or "retention"
    purpose = str(payload.get("purpose") or "")
    days = payload.get("retention_days")
    method = str(payload.get("deletion_method") or "")
    backup = str(payload.get("backup_handling") or "")
    elems = _json_list(payload.get("data_element_ids"))
    meta_s = json.dumps(payload.get("meta") or {})
    if existing:
        c.execute(
            """
            UPDATE dg_retention_policies SET
                name=?, purpose=?, retention_days=?, deletion_method=?, backup_handling=?,
                data_element_ids_json=?, meta_json=?, updated_at=?
            WHERE id=? AND user_id=?
            """,
            (name, purpose, days, method, backup, elems, meta_s, ts, eid, user_id),
        )
    else:
        c.execute(
            """
            INSERT INTO dg_retention_policies (
                id, user_id, name, purpose, retention_days, deletion_method, backup_handling,
                data_element_ids_json, meta_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (eid, user_id, name, purpose, days, method, backup, elems, meta_s, created, ts),
        )
    c.commit()
    row = _row(c.execute("SELECT * FROM dg_retention_policies WHERE id = ?", (eid,)).fetchone())
    _publish_privacy(user_id, "privacy.retention.changed", retention_id=eid)
    return row

def list_retention_policies(user_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
    ensure_schema()
    lim = max(1, min(int(limit or 500), 2000))
    rows = get_conn().execute(
        "SELECT * FROM dg_retention_policies WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?",
        (user_id, lim),
    ).fetchall()
    return [_row(r) for r in rows]


def upsert_principal_request(user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    ensure_schema()
    eid = str(payload.get("id") or new_id())
    ts = now()
    c = get_conn()
    existing = c.execute(
        "SELECT created_at, received_at FROM dg_principal_requests WHERE id = ? AND user_id = ?",
        (eid, user_id),
    ).fetchone()
    ex = row_to_dict(existing) or {}
    created = float(ex.get("created_at") or ts) if existing else ts
    received = float(payload.get("received_at") or ex.get("received_at") or ts)
    rtype = str(payload.get("request_type") or "access")
    pref = str(payload.get("principal_ref") or "")
    status = str(payload.get("status") or "open")
    sla = payload.get("sla_due_at")
    closed = payload.get("closed_at")
    notes = str(payload.get("notes") or "")
    meta_s = json.dumps(payload.get("meta") or {})
    if existing:
        c.execute(
            """
            UPDATE dg_principal_requests SET
                request_type=?, principal_ref=?, status=?, sla_due_at=?, closed_at=?,
                notes=?, meta_json=?, updated_at=?
            WHERE id=? AND user_id=?
            """,
            (rtype, pref, status, sla, closed, notes, meta_s, ts, eid, user_id),
        )
    else:
        c.execute(
            """
            INSERT INTO dg_principal_requests (
                id, user_id, request_type, principal_ref, status, sla_due_at, received_at,
                closed_at, notes, meta_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (eid, user_id, rtype, pref, status, sla, received, closed, notes, meta_s, created, ts),
        )
    c.commit()
    row = _row(c.execute("SELECT * FROM dg_principal_requests WHERE id = ?", (eid,)).fetchone())
    _publish_privacy(user_id, "privacy.request.changed", request_id=eid)
    return row

def list_principal_requests(user_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
    ensure_schema()
    lim = max(1, min(int(limit or 500), 2000))
    rows = get_conn().execute(
        "SELECT * FROM dg_principal_requests WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?",
        (user_id, lim),
    ).fetchall()
    return [_row(r) for r in rows]


def family_posture(user_id: str) -> dict[str, Any]:
    """Aggregate coverage percentages for a DPDP-style dashboard (inventory completeness)."""
    ensure_schema()
    profile = get_org_privacy_profile(user_id)
    elements = list_data_elements(user_id)
    activities = list_processing_activities(user_id)
    flows = list_data_flows(user_id)
    processors = [p for p in list_processors(user_id) if not p.get("offboarded")]
    retention = list_retention_policies(user_id)
    requests = list_principal_requests(user_id)

    def _pct(have: int, need: int = 1) -> int:
        if need <= 0:
            return 100
        return max(0, min(100, int(round(100.0 * min(have, need) / need))))

    # Honest heuristics: presence of declared records, not legal PASS.
    inventory_pct = _pct(len(elements), 1) if elements else 0
    if elements:
        classified = sum(1 for e in elements if (e.get("classification") or "").strip())
        inventory_pct = int(round(100.0 * classified / max(len(elements), 1)))

    notice_proxy = _pct(len(activities), 1)
    consent_proxy = _pct(
        sum(1 for a in activities if "consent" in (a.get("lawful_basis") or "").lower()),
        max(1, len(activities)) if activities else 1,
    ) if activities else 0
    rights_open = sum(1 for r in requests if (r.get("status") or "") == "open")
    rights_pct = 100 if requests and rights_open == 0 else (50 if requests else 0)
    processors_complete = sum(
        1
        for p in processors
        if (p.get("contract_ref") or "").strip() and (p.get("security_requirements") or "").strip()
    )
    processors_pct = int(round(100.0 * processors_complete / max(len(processors), 1))) if processors else 0
    retention_pct = _pct(len(retention), max(1, len(elements))) if elements else (100 if retention else 0)

    gaps: list[str] = []
    if not elements:
        gaps.append("No personal-data inventory elements declared")
    else:
        missing_class = sum(1 for e in elements if not (e.get("classification") or "").strip())
        if missing_class:
            gaps.append(f"{missing_class} systems/elements missing classification")
    incomplete_proc = len(processors) - processors_complete
    if incomplete_proc > 0:
        gaps.append(f"{incomplete_proc} processor records incomplete (contract/security)")
    if elements and not retention:
        gaps.append(f"{len(elements)} elements without a retention policy record")
    if profile.get("sdf_status") == "unknown":
        gaps.append("SDF applicability still unknown — set after legal review (do not auto-declare)")

    scores = {
        "data_inventory": inventory_pct,
        "notice": notice_proxy,
        "consent": consent_proxy,
        "rights": rights_pct,
        "retention": retention_pct,
        "processors": processors_pct,
        "flows_mapped": _pct(len(flows), 1) if flows else 0,
    }
    overall = int(round(sum(scores.values()) / max(len(scores), 1)))
    return {
        "ok": True,
        "overall_percent": overall,
        "families": scores,
        "counts": {
            "data_elements": len(elements),
            "processing_activities": len(activities),
            "data_flows": len(flows),
            "processors": len(processors),
            "retention_policies": len(retention),
            "principal_requests": len(requests),
            "principal_requests_open": rights_open,
        },
        "sdf_status": profile.get("sdf_status"),
        "critical_gaps": gaps,
        "legal_disclaimer": _LEGAL,
        "assessment_kind": "inventory_completeness",
        "note": (
            "Percentages reflect declared data-governance records completeness, "
            "not live control PASS/FAIL and not legal compliance."
        ),
    }


def _publish_privacy(user_id: str, event_type: str, **extra: Any) -> None:
    try:
        from app.realtime_bus import publish

        publish(
            type=event_type,
            event_type=event_type,
            user_id=user_id,
            **extra,
        )
    except Exception:
        pass
    try:
        from app.realtime.fleet_aggregator import publish_fleet_metric

        posture = family_posture(user_id)
        publish_fleet_metric(
            user_id,
            "compliance",
            value=posture.get("overall_percent"),
            assessment_kind="inventory_completeness",
            sdf_status=posture.get("sdf_status"),
        )
    except Exception:
        pass


def dpdp_overview(user_id: str, *, as_of: str | None = None) -> dict[str, Any]:
    """Combined DPDP dashboard payload: inventory posture + phased Rules + gap scores."""
    from app.compliance.effective_dates import framework_commencement_summary
    from app.gap_analysis import list_assessments, load_framework

    posture = family_posture(user_id)
    profile = get_org_privacy_profile(user_id)
    rules = load_framework("dpdp_rules_2025")
    act = load_framework("dpdp_act_2023")
    commencement = framework_commencement_summary(rules, as_of=as_of)

    assessments = list_assessments(user_id)
    fw_scores: list[dict[str, Any]] = []
    for fid in ("dpdp_act_2023", "dpdp_rules_2025"):
        match = next((a for a in assessments if (a.get("framework_id") or "") == fid), None)
        fw_scores.append(
            {
                "framework_id": fid,
                "assessed": bool(match),
                "compliance_percent": (match or {}).get("compliance_percent"),
                "assessment_id": (match or {}).get("id"),
                "updated_at": (match or {}).get("created_at"),
            }
        )

    return {
        "ok": True,
        "family": "India DPDP",
        "jurisdiction": profile.get("jurisdiction") or "IN",
        "sdf_status": profile.get("sdf_status") or "unknown",
        "inventory_posture": posture,
        "commencement": commencement,
        "frameworks": fw_scores,
        "act": {"id": act.get("id"), "name": act.get("name"), "control_count": len(act.get("controls") or [])},
        "rules": {
            "id": rules.get("id"),
            "name": rules.get("name"),
            "control_count": len(rules.get("controls") or []),
            "notified_on": rules.get("notified_on"),
            "phased_commencement": rules.get("phased_commencement"),
        },
        "data_map": {
            "elements": list_data_elements(user_id, limit=200),
            "flows": list_data_flows(user_id, limit=200),
            "processors": list_processors(user_id, limit=200),
            "activities": list_processing_activities(user_id, limit=200),
            "principal_requests": list_principal_requests(user_id, limit=200),
            "retention_policies": list_retention_policies(user_id, limit=200),
        },
        "privacy_center": {
            "sections": [
                "data_inventory",
                "data_classification",
                "processing_activities",
                "data_flows",
                "principal_requests",
                "retention",
                "processors",
                "dpdp_controls",
                "evidence",
            ],
            "note": (
                "Privacy Center is a Compliance surface for declared inventory + DPDP "
                "frameworks — not a legal determination of DPDP compliance."
            ),
        },
        "legal_disclaimer": _LEGAL,
        "hierarchy": [
            "framework",
            "requirement",
            "control",
            "test",
            "data_source",
            "observation",
            "evidence",
            "result",
            "risk",
            "remediation",
            "verification",
        ],
    }
