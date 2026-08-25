"""Map background jobs and tool runs to SSE push events for live UI refresh."""

from __future__ import annotations

from typing import Any


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
