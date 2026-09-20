"""Ingest Observation and Document into Evidence Store + control map."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.db import get_conn, new_id, now
from app.evidence_spine.mapping import link_evidence_to_control
from app.evidence_spine.schema import ensure_evidence_spine_schema
from app.services.evidence import record_evidence


def _hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _store_observation(
    user_id: str,
    *,
    obs_id: str,
    data_source: str,
    source_ref: str,
    check_id: str,
    control_hint: str,
    result: str,
    summary: str,
    detail: dict[str, Any],
    content_hash: str,
    evidence_id: str,
    expires_at: float | None,
    org_id: str | None,
) -> None:
    ensure_evidence_spine_schema()
    c = get_conn()
    c.execute(
        """
        INSERT INTO evidence_observations
        (id, user_id, org_id, data_source, source_ref, check_id, control_hint,
         result, summary, detail_json, content_hash, evidence_id, observed_at,
         expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            obs_id,
            user_id,
            org_id,
            data_source,
            source_ref[:200],
            check_id[:120],
            control_hint[:120],
            result[:40],
            summary[:500],
            json.dumps(detail or {})[:8000],
            content_hash,
            evidence_id,
            now(),
            expires_at,
            now(),
        ),
    )
    c.commit()


def ingest_observation_as_evidence(
    user_id: str,
    *,
    result: str,
    summary: str,
    data_source: str = "agent",
    source_ref: str = "",
    check_id: str = "",
    agent_id: str = "",
    asset_id: str = "",
    hostname: str = "",
    test_name: str = "",
    controls: list[dict[str, str]] | None = None,
    detail: dict[str, Any] | None = None,
    expires_at: float | None = None,
    role: str = "satisfies",
) -> dict[str, Any]:
    """Server/agent signal → Observation → Evidence → control map.

    ``controls`` items: ``{"framework_id": "...", "control_id": "..."}``.
    """
    ensure_evidence_spine_schema()
    st = (result or "unknown").strip().lower() or "unknown"
    obs_id = new_id()
    test = (test_name or check_id or "observation").strip()
    entity_id = f"{agent_id or source_ref or 'fleet'}:{test}"
    body = {
        "observation_id": obs_id,
        "data_source": data_source,
        "source_ref": source_ref or agent_id,
        "agent_id": agent_id,
        "asset_id": asset_id,
        "hostname": hostname,
        "check_id": check_id or test,
        "test_name": test,
        "result": st,
        "observed_at": now(),
        "expires_at": expires_at,
        **(detail or {}),
    }
    body["content_hash"] = _hash(
        {
            "test": test,
            "result": st,
            "agent_id": agent_id,
            "observation_id": obs_id,
        }
    )
    ev = record_evidence(
        user_id,
        entity_type="observation",
        entity_id=entity_id,
        source="observed",
        summary=(summary or f"{test}:{st}")[:500],
        confidence=0.9 if st in {"pass", "fail"} else 0.6,
        detail=body,
        expires_at=expires_at,
        created_by=f"spine:{data_source}",
    )
    eid = str(ev.get("id") or "")
    _store_observation(
        user_id,
        obs_id=obs_id,
        data_source=data_source,
        source_ref=source_ref or agent_id,
        check_id=check_id or test,
        control_hint=(controls[0]["control_id"] if controls else ""),
        result=st,
        summary=summary or f"{test}:{st}",
        detail=body,
        content_hash=body["content_hash"],
        evidence_id=eid,
        expires_at=expires_at,
        org_id=ev.get("org_id"),
    )
    links: list[dict[str, Any]] = []
    for ctl in controls or []:
        cid = (ctl.get("control_id") or "").strip()
        if not cid:
            continue
        try:
            links.append(
                link_evidence_to_control(
                    user_id,
                    eid,
                    control_id=cid,
                    framework_id=(ctl.get("framework_id") or "").strip(),
                    role=role if st in {"pass", "fail"} else "supports",
                    org_id=ev.get("org_id"),
                )
            )
        except Exception:
            pass
    return {
        "ok": True,
        "observation_id": obs_id,
        "evidence": ev,
        "evidence_id": eid,
        "links": links,
        "content_hash": body["content_hash"],
    }


def ingest_document_as_evidence(
    user_id: str,
    *,
    title: str,
    summary: str = "",
    file_id: str = "",
    document_id: str = "",
    control_id: str = "",
    framework_id: str = "",
    controls: list[dict[str, str]] | None = None,
    owner: str = "",
    verified: bool = True,
    detail: dict[str, Any] | None = None,
    ttl_sec: int | None = None,
) -> dict[str, Any]:
    """Uploaded / approved document → Evidence (declared) → control map.

    Documents are first-class evidence, not bare attachments. They typically
    *support* or *document* a control; they do not alone prove live host PASS.
    """
    ensure_evidence_spine_schema()
    ref = document_id or file_id or new_id()
    body = {
        "document_id": document_id,
        "file_id": file_id,
        "title": title,
        "owner": owner,
        "data_source": "document",
        "ingested_at": now(),
        **(detail or {}),
    }
    body["content_hash"] = _hash(
        {"title": title, "file_id": file_id, "document_id": document_id, "ref": ref}
    )
    ev = record_evidence(
        user_id,
        entity_type="document",
        entity_id=str(ref),
        source="declared",
        summary=(summary or title or "Document evidence")[:500],
        confidence=0.75,
        detail=body,
        verified=verified,
        ttl_sec=ttl_sec,
        created_by="spine:document",
    )
    eid = str(ev.get("id") or "")
    ctl_list = list(controls or [])
    if control_id and not any(
        (c.get("control_id") or "").strip() == control_id.strip() for c in ctl_list
    ):
        ctl_list.append({"control_id": control_id, "framework_id": framework_id or ""})
    links: list[dict[str, Any]] = []
    for ctl in ctl_list:
        cid = (ctl.get("control_id") or "").strip()
        if not cid:
            continue
        try:
            links.append(
                link_evidence_to_control(
                    user_id,
                    eid,
                    control_id=cid,
                    framework_id=(ctl.get("framework_id") or "").strip(),
                    role="documents",
                    org_id=ev.get("org_id"),
                )
            )
        except Exception:
            pass
    return {
        "ok": True,
        "evidence": ev,
        "evidence_id": eid,
        "links": links,
        "content_hash": body["content_hash"],
        "note": (
            "Document evidence supports governance/policy claims. "
            "It does not alone prove a live host control is PASS."
        ),
    }
