"""REALTIME v1 Task C — event processor (Streams consumer + lab hooks).

When ``REDIS_URL`` is set, a background consumer reads the durable Redis Stream
(``REDIS_STREAM_KEY``) via consumer group ``securaiq-workers`` and runs sync
handlers per message.

Without Redis (lab default), ``on_local_publish`` is invoked from
``realtime_bus.publish`` for the same handler set — no-op-safe.

Handlers only act when scope is clear (``user_id`` on the event, or recoverable
from ``agent_id`` via ``securaiq_agents``). They must not invent detections,
must not raise out of handlers, and must tag follow-on publishes with
``_from_processor=True`` to avoid recursion.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Callable

_log = logging.getLogger("securaiq.event_processor")

CONSUMER_GROUP = "securaiq-workers"
CONSUMER_NAME = f"worker-{os.getpid()}"

# Dashboard-relevant types that get a processor hook.
HOOK_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "agent_threat",
        "vuln",
        "software.vulnerability.changed",
        "remediation",
        "agent_command",
        "incident",
        "gap",
    }
)

_HIGH_SEV = frozenset({"high", "critical"})

# Status / lifecycle tokens that mean verified / done / failed for remediation
# and agent_command side-effects (notify only on verified / failed).
_VERIFIED_TOKENS = frozenset({"verified", "VERIFIED"})
_DONE_TOKENS = frozenset({"done", "completed", "COMPLETED"})
_FAILED_TOKENS = frozenset(
    {
        "failed",
        "error",
        "timeout",
        "rejected",
        "verification_failed",
        "FAILED",
        "TIMEOUT",
        "REJECTED",
    }
)

_processor_task: asyncio.Task | None = None
_started = False
# Guard against handler → publish → handler recursion on the lab path.
_in_handler = False

Handler = Callable[[dict[str, Any]], None]


def _redis_configured() -> bool:
    try:
        from app.config import settings

        return bool((getattr(settings, "redis_url", "") or "").strip())
    except Exception:
        return False


def _stream_key() -> str:
    try:
        from app.realtime_bus import _stream_key as bus_stream_key

        return bus_stream_key()
    except Exception:
        return "securaiq:events"


def _resolve_user_id(event: dict[str, Any]) -> str:
    """Return user_id from the event, or look up securaiq_agents by agent_id."""
    uid = str(event.get("user_id") or "").strip()
    if uid:
        return uid
    aid = str(event.get("agent_id") or "").strip()
    if not aid:
        return ""
    try:
        from app.db import get_conn

        row = get_conn().execute(
            "SELECT user_id FROM securaiq_agents WHERE id = ?", (aid,)
        ).fetchone()
        if not row:
            return ""
        return str(row["user_id"] if hasattr(row, "keys") else row[0] or "").strip()
    except Exception:
        return ""


def _event_title(event: dict[str, Any], default: str = "SecuraIQ event") -> str:
    for key in ("title", "message", "summary", "name"):
        v = str(event.get(key) or "").strip()
        if v:
            return v[:200]
    et = str(event.get("event_type") or event.get("type") or "event").strip()
    return f"{default}: {et}"[:200]


def _entity_id(*candidates: Any) -> str:
    for c in candidates:
        v = str(c or "").strip()
        if v:
            return v
    return ""


def _safe_notify(user_id: str, kind: str, title: str, body: str = "", link: str = "") -> None:
    try:
        from app.notifications import notify

        notify(user_id, kind, title, body, link=link)
    except Exception as exc:
        _log.debug("notify skipped: %s", exc)


def _safe_record_evidence(
    user_id: str,
    *,
    entity_type: str,
    entity_id: str,
    source: str,
    summary: str,
    detail: dict[str, Any] | None = None,
    confidence: float = 0.7,
) -> dict[str, Any] | None:
    if not entity_type or not entity_id:
        return None
    try:
        from app.services.evidence import record_evidence

        return record_evidence(
            user_id,
            entity_type=entity_type,
            entity_id=entity_id,
            source=source,
            summary=summary[:500],
            detail=detail or {},
            confidence=confidence,
            created_by="event_processor",
        )
    except Exception as exc:
        _log.debug("record_evidence skipped: %s", exc)
        return None


def _safe_publish(**kwargs: Any) -> None:
    try:
        from app.realtime_bus import publish

        kwargs.setdefault("_from_processor", True)
        publish(**kwargs)
    except Exception as exc:
        _log.debug("follow-on publish skipped: %s", exc)


def _publish_evidence_hint(
    user_id: str,
    *,
    evidence: dict[str, Any] | None,
    entity_type: str,
    entity_id: str,
    summary: str,
) -> None:
    payload: dict[str, Any] = {
        "type": "evidence",
        "user_id": user_id,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "summary": summary[:120],
        "_from_processor": True,
    }
    if evidence and evidence.get("id"):
        payload["id"] = evidence["id"]
        payload["evidence_id"] = evidence["id"]
    _safe_publish(**payload)


def _maybe_publish_org_risk(user_id: str, *, reason: str = "") -> None:
    """Cheap org risk hint — only when compute_org_risk_score returns a score."""
    try:
        from app.services.risk_priority import compute_org_risk_score

        result = compute_org_risk_score(user_id)
    except Exception as exc:
        _log.debug("compute_org_risk_score skipped: %s", exc)
        return
    if not isinstance(result, dict) or result.get("score") is None:
        return
    _safe_publish(
        type="risk",
        user_id=user_id,
        score=result.get("score"),
        band=result.get("band"),
        total_open=result.get("total_open"),
        reason=reason or "event_processor",
        _from_processor=True,
    )


def _terminal_kind(event: dict[str, Any]) -> str | None:
    """Return 'verified' | 'done' | 'failed' when status/lifecycle indicates terminal."""
    tokens = {
        str(event.get("lifecycle") or "").strip(),
        str(event.get("status") or "").strip(),
        str(event.get("verification_status") or "").strip(),
        str(event.get("action") or "").strip(),
    }
    tokens |= {t.lower() for t in tokens if t}
    tokens |= {t.upper() for t in tokens if t}
    if tokens & _VERIFIED_TOKENS:
        return "verified"
    if tokens & _FAILED_TOKENS:
        return "failed"
    if tokens & _DONE_TOKENS:
        return "done"
    return None


def _handle_agent_threat(event: dict[str, Any]) -> None:
    user_id = _resolve_user_id(event)
    if not user_id:
        _log.debug("agent_threat skipped — no user_id (event_id=%s)", event.get("event_id"))
        return

    threat_id = _entity_id(event.get("id"), event.get("threat_id"))
    agent_id = _entity_id(event.get("agent_id"))
    entity_type = "threat" if threat_id else "agent"
    entity_id = threat_id or agent_id
    if not entity_id:
        return

    title = _event_title(event, default="Agent threat")
    sev = str(event.get("severity") or "").strip().lower()
    body = f"Severity: {sev or 'unknown'}"
    if event.get("hostname"):
        body += f" · Host: {event.get('hostname')}"
    if event.get("category"):
        body += f" · {event.get('category')}"

    # Prefer high/critical for inbox noise control.
    if sev in _HIGH_SEV:
        _safe_notify(user_id, "agent_threat", title, body, link="/#agents")

    evidence = _safe_record_evidence(
        user_id,
        entity_type=entity_type,
        entity_id=entity_id,
        source="observed",
        summary=title,
        detail={
            "event_id": event.get("event_id"),
            "severity": sev,
            "agent_id": agent_id or None,
        },
        confidence=0.7,
    )
    _publish_evidence_hint(
        user_id, evidence=evidence, entity_type=entity_type, entity_id=entity_id, summary=title
    )
    # Thin risk dashboard hint (no inventing detections — severity from the event).
    if sev in _HIGH_SEV:
        hint: dict[str, Any] = {
            "type": "risk",
            "user_id": user_id,
            "severity": sev,
            "reason": "agent_threat",
            "entity_type": entity_type,
            "entity_id": entity_id,
            "_from_processor": True,
        }
        if evidence and evidence.get("id"):
            hint["evidence_id"] = evidence["id"]
        _safe_publish(**hint)


def _vuln_entity_id(event: dict[str, Any]) -> str:
    eid = _entity_id(event.get("id"), event.get("vuln_id"), event.get("entity_id"), event.get("cve"))
    if eid:
        return eid
    changes = event.get("changes")
    if isinstance(changes, list) and changes:
        c0 = changes[0] if isinstance(changes[0], dict) else {}
        return _entity_id(c0.get("cve"), c0.get("id"), c0.get("vuln_id"), c0.get("installation_id"))
    return ""


def _handle_vuln(event: dict[str, Any]) -> None:
    user_id = _resolve_user_id(event)
    if not user_id:
        return

    entity_id = _vuln_entity_id(event)
    title = _event_title(event, default="Vulnerability update")
    evidence = None
    if entity_id:
        evidence = _safe_record_evidence(
            user_id,
            entity_type="vulnerability",
            entity_id=entity_id,
            source="derived",
            summary=title,
            detail={"event_id": event.get("event_id"), "severity": event.get("severity")},
            confidence=0.7,
        )
        _publish_evidence_hint(
            user_id,
            evidence=evidence,
            entity_type="vulnerability",
            entity_id=entity_id,
            summary=title,
        )

    _maybe_publish_org_risk(user_id, reason="vuln")


def _handle_remediation_or_command(event: dict[str, Any]) -> None:
    user_id = _resolve_user_id(event)
    if not user_id:
        return

    kind = _terminal_kind(event)
    if not kind:
        return

    et = str(event.get("event_type") or event.get("type") or "").strip()
    entity_id = _entity_id(event.get("id"), event.get("command_id"), event.get("remediation_id"))
    if not entity_id:
        return

    if et == "agent_command":
        entity_type = "command"
        source = "observed"
        link = "/#agents"
        notify_kind = "system"
    else:
        entity_type = "remediation"
        source = "observed"
        link = "/#remediation"
        notify_kind = "remediation_due"

    title = _event_title(event, default=f"{entity_type} {kind}")
    summary = f"{title} ({kind})"
    evidence = _safe_record_evidence(
        user_id,
        entity_type=entity_type,
        entity_id=entity_id,
        source=source,
        summary=summary,
        detail={
            "event_id": event.get("event_id"),
            "status": event.get("status"),
            "lifecycle": event.get("lifecycle"),
            "verification_status": event.get("verification_status"),
            "terminal": kind,
        },
        confidence=0.7,
    )
    _publish_evidence_hint(
        user_id, evidence=evidence, entity_type=entity_type, entity_id=entity_id, summary=summary
    )

    if kind in ("verified", "failed"):
        body = f"Status: {event.get('status') or event.get('lifecycle') or kind}"
        _safe_notify(user_id, notify_kind, summary, body, link=link)


def _handle_light_evidence(event: dict[str, Any], *, entity_type: str) -> None:
    """incident / gap — evidence only when user_id + entity id are present."""
    user_id = _resolve_user_id(event)
    if not user_id:
        return
    entity_id = _entity_id(event.get("id"), event.get("entity_id"), event.get("assessment_id"))
    if not entity_id:
        return
    title = _event_title(event, default=entity_type)
    evidence = _safe_record_evidence(
        user_id,
        entity_type=entity_type,
        entity_id=entity_id,
        source="derived",
        summary=title,
        detail={"event_id": event.get("event_id"), "severity": event.get("severity")},
        confidence=0.6,
    )
    if evidence:
        _publish_evidence_hint(
            user_id, evidence=evidence, entity_type=entity_type, entity_id=entity_id, summary=title
        )


def process_event(event: dict[str, Any] | None) -> None:
    """Run the registered handler for ``event`` (sync, never raises)."""
    global _in_handler
    if not event or not isinstance(event, dict):
        return
    if event.get("_from_processor"):
        return
    et = str(event.get("event_type") or event.get("type") or "").strip()
    if not et:
        return
    handler = HANDLERS.get(et)
    if handler is None:
        return
    if _in_handler:
        return
    _in_handler = True
    try:
        handler(event)
    except Exception as exc:
        _log.debug("handler %s failed: %s", et, exc)
    finally:
        _in_handler = False


def on_local_publish(event: dict[str, Any] | None) -> None:
    """Lab hook after ``publish`` when Redis Streams consumer is not the authority.

    Skipped when ``REDIS_URL`` is set so each event is processed once via the
    consumer group (multi-worker safe). Failures are swallowed.
    """
    if _redis_configured():
        return
    try:
        process_event(event)
    except Exception:
        pass


HANDLERS: dict[str, Handler] = {
    "agent_threat": _handle_agent_threat,
    "vuln": _handle_vuln,
    "software.vulnerability.changed": _handle_vuln,
    "remediation": _handle_remediation_or_command,
    "agent_command": _handle_remediation_or_command,
    "incident": lambda e: _handle_light_evidence(e, entity_type="incident"),
    "gap": lambda e: _handle_light_evidence(e, entity_type="gap"),
}


async def _ensure_consumer_group(client: Any, stream: str) -> None:
    try:
        await client.xgroup_create(name=stream, groupname=CONSUMER_GROUP, id="0", mkstream=True)
        _log.info("created Redis Streams group %s on %s", CONSUMER_GROUP, stream)
    except Exception as exc:
        # BUSYGROUP = already exists — expected on restart
        if "BUSYGROUP" not in str(exc).upper():
            _log.debug("xgroup_create: %s", exc)


async def _streams_consumer_loop() -> None:
    url = ""
    try:
        from app.config import settings

        url = (getattr(settings, "redis_url", "") or "").strip()
    except Exception:
        return
    if not url:
        return
    try:
        import redis.asyncio as aioredis
    except Exception:
        _log.debug("redis.asyncio unavailable — event processor idle")
        return

    stream = _stream_key()
    backoff = 2.0
    while True:
        client = None
        try:
            client = aioredis.from_url(url, decode_responses=True)
            await _ensure_consumer_group(client, stream)
            backoff = 2.0
            while True:
                rows = await client.xreadgroup(
                    groupname=CONSUMER_GROUP,
                    consumername=CONSUMER_NAME,
                    streams={stream: ">"},
                    count=20,
                    block=5000,
                )
                if not rows:
                    continue
                for _stream_name, messages in rows:
                    for msg_id, fields in messages:
                        payload: dict[str, Any] = {}
                        raw = fields.get("payload") if isinstance(fields, dict) else None
                        if isinstance(raw, str):
                            try:
                                loaded = json.loads(raw)
                                if isinstance(loaded, dict):
                                    payload = loaded
                            except Exception:
                                payload = {}
                        try:
                            process_event(payload)
                        except Exception:
                            pass
                        try:
                            await client.xack(stream, CONSUMER_GROUP, msg_id)
                        except Exception:
                            pass
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _log.debug("streams consumer reconnect: %s", exc)
            await asyncio.sleep(backoff)
            backoff = min(60.0, backoff * 2)
        finally:
            if client is not None:
                try:
                    await client.aclose()
                except Exception:
                    try:
                        await client.close()
                    except Exception:
                        pass


def start_processor(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Start the Streams consumer as a non-blocking background task (idempotent)."""
    global _processor_task, _started
    if not _redis_configured():
        return
    if _started and _processor_task is not None and not _processor_task.done():
        return
    try:
        running = loop or asyncio.get_running_loop()
    except RuntimeError:
        return
    try:
        _processor_task = running.create_task(_streams_consumer_loop())
        _started = True
        _log.info("event processor Streams consumer started (%s)", CONSUMER_NAME)
    except Exception as exc:
        _log.debug("event processor start skipped: %s", exc)
        _processor_task = None
        _started = False


def processor_status() -> dict[str, Any]:
    running = _processor_task is not None and not _processor_task.done()
    return {
        "redis_configured": _redis_configured(),
        "consumer_group": CONSUMER_GROUP if _redis_configured() else None,
        "consumer_name": CONSUMER_NAME if _redis_configured() else None,
        "task_running": running,
        "hook_types": sorted(HOOK_EVENT_TYPES),
        "mode": "redis_streams" if _redis_configured() else "local_publish_hooks",
    }


def reset_processor_for_tests() -> None:
    """Test helper — clear started flag (does not cancel a live Redis loop)."""
    global _processor_task, _started, _in_handler
    _started = False
    _processor_task = None
    _in_handler = False
