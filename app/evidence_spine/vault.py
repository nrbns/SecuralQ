"""Evidence Vault — first-class document/object evidence with versioning.

Critical rule: replacing a document creates a NEW evidence version and
supersedes the previous one. Historical evidence is never overwritten.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.db import get_conn, new_id, now, row_to_dict
from app.evidence_spine.ingest import ingest_document_as_evidence
from app.evidence_spine.mapping import link_evidence_to_control
from app.evidence_spine.schema import ensure_evidence_spine_schema
from app.services.evidence import get_evidence, record_evidence

VALID_KINDS = {
    "document",
    "screenshot",
    "certificate",
    "scanner",
    "api_result",
    "manual",
    "generated",
    "observation",
    "cloud",
}
VALID_REVIEW = {"draft", "pending_review", "accepted", "rejected"}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _publish(event_type: str, user_id: str, **extra: Any) -> None:
    try:
        from app.realtime_events import publish_aliased

        aliases = [event_type]
        if event_type.startswith("evidence.") and event_type != "evidence.updated":
            aliases.append("evidence.updated")
        publish_aliased(
            event_type.split(".", 1)[0] if "." in event_type else event_type,
            aliases=aliases,
            user_id=user_id,
            **extra,
        )
    except Exception:
        pass


def _access(
    user_id: str,
    *,
    evidence_id: str,
    action: str,
    vault_id: str = "",
    actor_id: str = "",
    detail: str = "",
) -> None:
    ensure_evidence_spine_schema()
    get_conn().execute(
        """
        INSERT INTO evidence_access_log
        (id, user_id, evidence_id, vault_id, action, actor_id, detail, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            new_id(),
            user_id,
            evidence_id,
            vault_id,
            action[:40],
            actor_id or user_id,
            (detail or "")[:1000],
            now(),
        ),
    )
    get_conn().commit()


def _vault_row(user_id: str, vault_id: str) -> dict[str, Any] | None:
    row = get_conn().execute(
        "SELECT * FROM evidence_vault WHERE id = ? AND user_id = ?",
        (vault_id, user_id),
    ).fetchone()
    if not row:
        return None
    d = row_to_dict(row)
    try:
        d["meta"] = json.loads(d.get("meta_json") or "{}")
    except Exception:
        d["meta"] = {}
    return d


def list_versions(user_id: str, vault_id: str) -> list[dict[str, Any]]:
    ensure_evidence_spine_schema()
    rows = get_conn().execute(
        """
        SELECT * FROM evidence_versions
        WHERE user_id = ? AND vault_id = ?
        ORDER BY version_num DESC
        """,
        (user_id, vault_id),
    ).fetchall()
    return [row_to_dict(r) for r in rows]


def get_vault_item(user_id: str, vault_id: str) -> dict[str, Any] | None:
    ensure_evidence_spine_schema()
    v = _vault_row(user_id, vault_id)
    if not v:
        return None
    versions = list_versions(user_id, vault_id)
    current = get_evidence(user_id, v.get("current_evidence_id") or "") if v.get("current_evidence_id") else None
    return {
        "ok": True,
        "vault": v,
        "current": current,
        "versions": versions,
        "version_count": len(versions),
    }


def list_vault(
    user_id: str,
    *,
    limit: int = 100,
    kind: str = "",
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    ensure_evidence_spine_schema()
    from app.tenancy import tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM evidence_vault WHERE {where}"
    if kind:
        q += " AND kind = ?"
        args.append(kind)
    q += " ORDER BY updated_at DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    rows = get_conn().execute(q, args).fetchall()
    out = []
    for r in rows:
        d = row_to_dict(r)
        try:
            d["meta"] = json.loads(d.get("meta_json") or "{}")
        except Exception:
            d["meta"] = {}
        out.append(d)
    return out


def create_vault_document(
    user_id: str,
    *,
    title: str,
    filename: str,
    data: bytes,
    kind: str = "document",
    owner_id: str = "",
    collector: str = "",
    framework_id: str = "",
    control_id: str = "",
    controls: list[dict[str, str]] | None = None,
    retention_days: int | None = None,
    ttl_sec: int | None = None,
    notes: str = "",
) -> dict[str, Any]:
    """Upload bytes → validated file → Evidence (v1) → vault family."""
    ensure_evidence_spine_schema()
    k = (kind or "document").strip().lower()
    if k not in VALID_KINDS:
        k = "document"
    if not data:
        raise ValueError("empty file")
    from app.tenancy import primary_org_id
    from app.uploads import save_upload

    digest = _sha256(data)
    upload = save_upload(user_id, filename, data, engagement_id=None, ingest=False)
    file_id = str(upload["id"])
    vault_id = new_id()
    oid = primary_org_id(user_id)
    owner = (owner_id or user_id).strip()
    t = now()
    title_s = (title or upload.get("filename") or "Evidence").strip()[:300]

    expires_at = None
    if ttl_sec and ttl_sec > 0:
        expires_at = t + float(ttl_sec)
    elif retention_days and retention_days > 0:
        expires_at = t + float(retention_days) * 86400.0

    spine = ingest_document_as_evidence(
        user_id,
        title=title_s,
        summary=notes or f"Vault document: {upload.get('filename')}",
        file_id=file_id,
        document_id=vault_id,
        control_id=control_id,
        framework_id=framework_id,
        controls=controls,
        owner=owner,
        verified=False,
        detail={
            "vault_id": vault_id,
            "version": 1,
            "content_sha256": digest,
            "filename": upload.get("filename"),
            "collector": collector or "vault_upload",
            "kind": k,
        },
        ttl_sec=int(expires_at - t) if expires_at else None,
    )
    evidence_id = str(spine.get("evidence_id") or "")
    if not evidence_id:
        raise ValueError("failed to create evidence row")

    # Ensure content_sha256 on evidence detail
    try:
        from app.services.evidence import get_evidence as _ge

        ev = _ge(user_id, evidence_id)
        if ev:
            detail = dict(ev.get("detail") or {})
            detail["content_sha256"] = digest
            detail["vault_id"] = vault_id
            detail["version"] = 1
            get_conn().execute(
                "UPDATE securaiq_evidence SET detail_json = ? WHERE id = ?",
                (json.dumps(detail)[:8000], evidence_id),
            )
            get_conn().commit()
    except Exception:
        pass

    get_conn().execute(
        """
        INSERT INTO evidence_vault
        (id, user_id, org_id, kind, title, owner_id, current_evidence_id,
         review_status, retention_days, meta_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?)
        """,
        (
            vault_id,
            user_id,
            oid,
            k,
            title_s,
            owner,
            evidence_id,
            retention_days,
            json.dumps({"notes": notes[:500], "filename": upload.get("filename")})[:4000],
            t,
            t,
        ),
    )
    get_conn().execute(
        """
        INSERT INTO evidence_versions
        (id, user_id, vault_id, evidence_id, version_num, previous_evidence_id,
         content_sha256, file_id, filename, collector, source, created_by, created_at,
         superseded_at, superseded_by)
        VALUES (?, ?, ?, ?, 1, '', ?, ?, ?, ?, 'declared', ?, ?, NULL, '')
        """,
        (
            new_id(),
            user_id,
            vault_id,
            evidence_id,
            digest,
            file_id,
            str(upload.get("filename") or "")[:200],
            (collector or "vault_upload")[:120],
            user_id,
            t,
        ),
    )
    get_conn().commit()
    _access(user_id, evidence_id=evidence_id, action="upload", vault_id=vault_id, detail=digest[:16])
    _publish(
        "evidence.created",
        user_id,
        evidence_id=evidence_id,
        vault_id=vault_id,
        content_sha256=digest,
        version=1,
    )
    return get_vault_item(user_id, vault_id) or {"ok": True, "vault_id": vault_id, "evidence_id": evidence_id}


def supersede_vault_document(
    user_id: str,
    vault_id: str,
    *,
    filename: str,
    data: bytes,
    notes: str = "",
    collector: str = "",
) -> dict[str, Any]:
    """Replace document content by creating version N+1 — never overwrite vN."""
    ensure_evidence_spine_schema()
    vault = _vault_row(user_id, vault_id)
    if not vault:
        raise ValueError("vault item not found")
    if not data:
        raise ValueError("empty file")
    from app.uploads import save_upload

    prev_eid = str(vault.get("current_evidence_id") or "")
    versions = list_versions(user_id, vault_id)
    next_ver = (versions[0]["version_num"] if versions else 0) + 1
    digest = _sha256(data)
    upload = save_upload(user_id, filename, data, engagement_id=None, ingest=False)
    file_id = str(upload["id"])
    t = now()

    # New evidence row (new fingerprint via new summary/version)
    ev = record_evidence(
        user_id,
        entity_type="document",
        entity_id=f"{vault_id}:v{next_ver}",
        source="declared",
        summary=(notes or f"Vault document v{next_ver}: {upload.get('filename')}")[:500],
        confidence=0.75,
        detail={
            "vault_id": vault_id,
            "version": next_ver,
            "previous_evidence_id": prev_eid,
            "content_sha256": digest,
            "filename": upload.get("filename"),
            "file_id": file_id,
            "collector": collector or "vault_supersede",
            "kind": vault.get("kind") or "document",
        },
        verified=False,
        created_by="spine:vault",
        ttl_sec=int(vault["retention_days"] * 86400) if vault.get("retention_days") else None,
    )
    new_eid = str(ev.get("id") or "")
    if not new_eid:
        raise ValueError("failed to create superseding evidence")

    # Copy control mappings from previous version
    if prev_eid:
        maps = get_conn().execute(
            "SELECT framework_id, control_id, role FROM evidence_control_map "
            "WHERE user_id = ? AND evidence_id = ?",
            (user_id, prev_eid),
        ).fetchall()
        for m in maps:
            try:
                link_evidence_to_control(
                    user_id,
                    new_eid,
                    control_id=m["control_id"],
                    framework_id=m["framework_id"] or "",
                    role=m["role"] or "documents",
                )
            except Exception:
                pass
        # Mark previous version superseded
        get_conn().execute(
            """
            UPDATE evidence_versions
            SET superseded_at = ?, superseded_by = ?
            WHERE evidence_id = ? AND user_id = ?
            """,
            (t, new_eid, prev_eid, user_id),
        )

    get_conn().execute(
        """
        INSERT INTO evidence_versions
        (id, user_id, vault_id, evidence_id, version_num, previous_evidence_id,
         content_sha256, file_id, filename, collector, source, created_by, created_at,
         superseded_at, superseded_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'declared', ?, ?, NULL, '')
        """,
        (
            new_id(),
            user_id,
            vault_id,
            new_eid,
            next_ver,
            prev_eid,
            digest,
            file_id,
            str(upload.get("filename") or "")[:200],
            (collector or "vault_supersede")[:120],
            user_id,
            t,
        ),
    )
    get_conn().execute(
        """
        UPDATE evidence_vault
        SET current_evidence_id = ?, review_status = 'draft', updated_at = ?,
            title = CASE WHEN ? != '' THEN ? ELSE title END
        WHERE id = ? AND user_id = ?
        """,
        (new_eid, t, notes[:300], notes[:300] if notes else "", vault_id, user_id),
    )
    get_conn().commit()
    _access(
        user_id,
        evidence_id=new_eid,
        action="supersede",
        vault_id=vault_id,
        detail=f"v{next_ver} sha={digest[:16]} prev={prev_eid[:8]}",
    )
    _publish(
        "evidence.superseded",
        user_id,
        evidence_id=new_eid,
        previous_evidence_id=prev_eid,
        vault_id=vault_id,
        version=next_ver,
        content_sha256=digest,
    )
    return get_vault_item(user_id, vault_id) or {"ok": True}


def set_review_status(
    user_id: str,
    vault_id: str,
    *,
    status: str,
    note: str = "",
    reviewed_by: str = "",
) -> dict[str, Any]:
    ensure_evidence_spine_schema()
    st = (status or "").strip().lower()
    if st not in VALID_REVIEW:
        raise ValueError(f"status must be one of {sorted(VALID_REVIEW)}")
    vault = _vault_row(user_id, vault_id)
    if not vault:
        raise ValueError("vault item not found")
    eid = str(vault.get("current_evidence_id") or "")
    t = now()
    get_conn().execute(
        "UPDATE evidence_vault SET review_status = ?, updated_at = ? WHERE id = ? AND user_id = ?",
        (st, t, vault_id, user_id),
    )
    get_conn().commit()
    action = "review" if st == "pending_review" else st
    if eid:
        _access(user_id, evidence_id=eid, action=action, vault_id=vault_id, detail=note[:200])
        if st == "accepted":
            try:
                from app.services.evidence import confirm_evidence

                confirm_evidence(user_id, eid, confirmed_by=reviewed_by or user_id)
            except Exception:
                pass
            _publish("evidence.verified", user_id, evidence_id=eid, vault_id=vault_id)
        elif st == "rejected":
            _publish("evidence.rejected", user_id, evidence_id=eid, vault_id=vault_id, note=note[:200])
        else:
            _publish("evidence.updated", user_id, evidence_id=eid, vault_id=vault_id, review_status=st)
    # Human attestation — Who/What/When/Evidence/Decision (not a bare checkbox)
    if st in {"accepted", "rejected"}:
        try:
            from app.services.human_attestation import record_attestation

            meta = {}
            try:
                meta = json.loads(vault.get("meta_json") or "{}")
            except Exception:
                meta = {}
            record_attestation(
                user_id,
                subject_type="vault",
                subject_id=vault_id,
                decision="approved" if st == "accepted" else "rejected",
                title=str(vault.get("title") or "Vault evidence review"),
                submitted_by=str(vault.get("owner_id") or ""),
                reviewed_by=reviewed_by or user_id,
                comment=note,
                evidence_ids=[eid] if eid else [],
                framework_id=str(meta.get("framework_id") or ""),
                control_id=str(meta.get("control_id") or ""),
                meta={"vault_id": vault_id, "review_status": st},
            )
        except Exception:
            pass
    return get_vault_item(user_id, vault_id) or {"ok": True}


def log_access(
    user_id: str,
    evidence_id: str,
    *,
    action: str = "view",
    vault_id: str = "",
) -> None:
    _access(user_id, evidence_id=evidence_id, action=action, vault_id=vault_id)
