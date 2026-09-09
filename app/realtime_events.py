"""REALTIME v1 helpers + job→SSE domain mapping.

``normalize_event`` / ``build_event`` implement Task A publish-path contract
shaping used by ``realtime_bus.publish``. ``publish_job_completion`` remains the
background-job → domain event mapper for live UI refresh.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any

from app.event_schema import (
    EVENT_VERSION,
    domain_payload,
    resolve_event_type,
    validate_event,
)


def _utc_iso(ts: float | None = None) -> str:
    t = time.time() if ts is None else float(ts)
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _environment_default() -> str:
    try:
        from app.config import settings

        return str(getattr(settings, "deployment_mode", None) or "lab").strip() or "lab"
    except Exception:
        return "lab"


def build_event(
    event_type: str,
    *,
    data: dict[str, Any] | None = None,
    organization_id: str | None = None,
    org_id: str | None = None,
    agent_id: str | None = None,
    asset_id: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    environment: str | None = None,
    evidence_ids: list[Any] | None = None,
    event_id: str | None = None,
    sequence: int | None = None,
    generated_at: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Construct a contract-shaped event (then pass through ``normalize_event``)."""
    payload: dict[str, Any] = {"event_type": str(event_type).strip(), **extra}
    if data:
        payload["data"] = dict(data)
    oid = organization_id if organization_id is not None else org_id
    if oid is not None:
        payload["organization_id"] = oid
        payload["org_id"] = oid
    if agent_id is not None:
        payload["agent_id"] = agent_id
    if asset_id is not None:
        payload["asset_id"] = asset_id
    if severity is not None:
        payload["severity"] = severity
    if source is not None:
        payload["source"] = source
    if environment is not None:
        payload["environment"] = environment
    if evidence_ids is not None:
        payload["evidence_ids"] = list(evidence_ids)
    if event_id is not None:
        payload["event_id"] = event_id
    if sequence is not None:
        payload["sequence"] = sequence
    if generated_at is not None:
        payload["generated_at"] = generated_at
    return normalize_event(payload)


def normalize_event(raw: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
    """Normalize a publish payload to the REALTIME v1 envelope.

    Dual-writes for SSE/UI backward compatibility:
    - ``type`` ↔ ``event_type``
    - ``org_id`` ↔ ``organization_id``
    - ``seq`` ↔ ``sequence``

    Domain fields remain at the top level (existing UI reads ``push.severity``,
    ``push.job_id``, etc.) and are also mirrored under ``data``.
    """
    payload = dict(raw or {})
    payload.update(kwargs)

    now = time.time()
    payload.setdefault("ts", now)

    event_type = resolve_event_type(payload)
    if not event_type:
        event_type = "unknown"
    payload["event_type"] = event_type
    payload["type"] = event_type  # SSE consumers key off ``type``

    payload["event_version"] = int(payload.get("event_version") or EVENT_VERSION)

    eid = str(payload.get("event_id") or "").strip() or uuid.uuid4().hex
    payload["event_id"] = eid

    # org dual-write
    org = payload.get("organization_id")
    if org is None or str(org).strip() == "":
        org = payload.get("org_id")
    if org is not None and str(org).strip() != "":
        org_s = str(org).strip()
        payload["organization_id"] = org_s
        payload["org_id"] = org_s

    # sequence dual-write (millis best-effort; Streams append order when REDIS_URL set)
    seq_val = payload.get("sequence")
    if seq_val is None:
        seq_val = payload.get("seq")
    if seq_val is None:
        seq_val = int(float(payload["ts"]) * 1000)
    try:
        seq_int = int(seq_val)
    except (TypeError, ValueError):
        seq_int = int(now * 1000)
    payload["sequence"] = seq_int
    payload["seq"] = seq_int

    if not payload.get("generated_at"):
        payload["generated_at"] = _utc_iso(float(payload["ts"]))
    # Bus receive time — always refresh on publish normalize
    payload["received_at"] = _utc_iso(now)

    if not payload.get("environment"):
        payload["environment"] = _environment_default()

    if payload.get("severity") is not None:
        payload["severity"] = str(payload["severity"]).strip().lower()

    evidence = payload.get("evidence_ids")
    if evidence is None:
        payload["evidence_ids"] = []
    elif not isinstance(evidence, list):
        payload["evidence_ids"] = [evidence]

    # Mirror domain fields into data without dropping top-level keys (SSE compat).
    existing_data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    mirrored = domain_payload(payload)
    merged_data = {**mirrored, **existing_data}
    payload["data"] = merged_data

    return payload


def publish_job_completion(
    kind: str,
    result: dict[str, Any] | None,
    *,
    job_id: str,
    status: str = "done",
) -> None:
    """Emit domain-specific realtime events when a background job finishes."""
    try:
        from app.realtime_bus import publish
    except Exception:
        return

    result = result if isinstance(result, dict) else {}
    kind = (kind or "").strip()
    uid = str(result.get("user_id") or "local")

    # Universal tool pulse — frontend routes all job/tool kinds through live refresh
    publish(
        type="tool",
        kind=kind,
        status=status,
        job_id=job_id,
        user_id=uid,
    )

    if status != "done":
        return

    base: dict[str, Any] = {"job_id": job_id, "kind": kind, "user_id": uid}

    if kind == "xdr_sync":
        publish(
            type="xdr_batch",
            new=int(result.get("new") or result.get("ingested") or 0),
            **base,
        )
    elif kind == "wazuh_sync":
        publish(
            type="siem",
            source="wazuh",
            agents=int(result.get("agents") or 0),
            alerts=int(result.get("alerts") or 0),
            **base,
        )
    elif kind == "openaudit_sync":
        publish(
            type="inventory",
            source="openaudit",
            devices_total=int(result.get("devices") or result.get("devices_total") or 0),
            **base,
        )
    elif kind == "lan_inventory_audit":
        publish(
            type="inventory",
            source="lan",
            action="lan_refresh",
            count=int(result.get("hosts") or 0),
            **base,
        )
        publish(type="asset", action="lan_refresh", count=int(result.get("hosts") or 0), **base)
    elif kind == "thehive_sync":
        publish(
            type="thehive",
            imported=int(result.get("imported") or result.get("cases") or 0),
            **base,
        )
        publish(type="incident", source="thehive", count=int(result.get("imported") or 0), **base)
    elif kind == "cloud_posture_sync":
        publish(
            type="cloud",
            imported=int(result.get("imported") or result.get("total") or 0),
            **base,
        )
        publish(
            type="vuln_batch",
            source="cloud",
            count=int(result.get("imported") or result.get("total") or 0),
            **base,
        )
    elif kind == "sonarqube_sync":
        publish(
            type="vuln_batch",
            source="sonarqube",
            count=int(result.get("imported") or 0),
            **base,
        )
    elif kind == "hardeningkitty_audit":
        publish(
            type="vuln_batch",
            source="hardening",
            count=int(result.get("imported") or 0),
            **base,
        )
        publish(
            type="hardening",
            score=result.get("score"),
            imported=int(result.get("imported") or 0),
            **base,
        )
    elif kind == "kev_sync":
        publish(
            type="intel",
            source="kev_sync",
            count=int(result.get("count") or 0),
            **base,
        )
    elif kind == "software_sync_all":
        publish(type="software_inventory", scheduled=True, **base)
    elif kind == "scan_execute":
        publish(
            type="scan",
            scan_id=result.get("scan_id"),
            status="completed",
            findings=int(result.get("findings") or 0),
            **base,
        )
    elif kind == "combo_assessment":
        publish(type="combo", workflow="combo_assessment", **base)
    elif kind == "report_export":
        publish(type="notification", title="Executive report ready", **base)


__all__ = [
    "build_event",
    "normalize_event",
    "publish_job_completion",
    "validate_event",
]
