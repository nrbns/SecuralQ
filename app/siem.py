"""Security event logging + optional SIEM forwarding.

Was "not started" per docs/launch-readiness.md — audit events only ever
lived in the local `audit_log` SQLite table, with no structured log output
and no forwarding path for customers running their own SIEM. This adds both:

  * every audit() call now also emits a structured JSON line to stdout
    (trivially shippable by any log collector — Vector, Fluent Bit, Filebeat,
    Docker's own log driver, journald, etc.), and
  * optional direct forwarding to a syslog target or an HTTP sink (generic
    webhook or Splunk HEC), gated behind SIEM_FORWARD_ENABLED so it's fully
    inert until an operator configures it.

Forwarding is always best-effort and non-blocking — a SIEM outage must never
break the request that triggered the audit event.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import threading
import time
from typing import Any

from app.config import settings

_logger = logging.getLogger("securaiq.security")
_logger.setLevel(logging.INFO)
if not _logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(_handler)
    _logger.propagate = False

_syslog_handler: "logging.handlers.SysLogHandler | None" = None


def _get_syslog_handler() -> "logging.handlers.SysLogHandler | None":
    global _syslog_handler
    if _syslog_handler is None and settings.siem_syslog_host:
        try:
            _syslog_handler = logging.handlers.SysLogHandler(
                address=(settings.siem_syslog_host, settings.siem_syslog_port),
            )
        except Exception:
            return None
    return _syslog_handler


def _forward_http(payload: dict[str, Any]) -> None:
    try:
        import httpx

        headers = {"Content-Type": "application/json"}
        body: dict[str, Any] = payload
        if settings.siem_hec_token:
            headers["Authorization"] = f"Splunk {settings.siem_hec_token}"
            body = {"event": payload, "sourcetype": "_json"}
        httpx.post(settings.siem_forward_url, json=body, headers=headers, timeout=5.0)
    except Exception:
        pass


def _forward_azure_sentinel(payload: dict[str, Any]) -> None:
    try:
        from app.connectors import azure_sentinel

        if not azure_sentinel.is_configured():
            return
        event = {
            "TimeGenerated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(payload.get("ts") or time.time())),
            "Product": "securaiq",
            "Action": payload.get("action"),
            "UserId": payload.get("user_id"),
            "Detail": json.dumps(payload.get("detail") or {}, default=str)[:32000],
        }
        azure_sentinel.send_events_sync([event])
    except Exception:
        pass


def log_security_event(action: str, user_id: str | None, detail: dict[str, Any] | None = None) -> None:
    """Structured JSON audit line — call this from app.db.audit() so every
    existing audit() call site in the codebase gets this for free."""
    event = {
        "ts": time.time(),
        "product": "securaiq",
        "action": action,
        "user_id": user_id,
        "detail": detail or {},
    }
    try:
        line = json.dumps(event, ensure_ascii=False, default=str)
    except Exception:
        line = json.dumps({"ts": event["ts"], "action": action, "user_id": user_id})

    _logger.info(line)

    if not settings.siem_forward_enabled:
        return

    handler = _get_syslog_handler()
    if handler is not None:
        try:
            record = logging.LogRecord(
                "securaiq.siem", logging.INFO, __file__, 0, line, None, None
            )
            handler.emit(record)
        except Exception:
            pass

    if settings.siem_forward_url:
        threading.Thread(target=_forward_http, args=(event,), daemon=True).start()

    if settings.siem_azure_sentinel_enabled:
        threading.Thread(target=_forward_azure_sentinel, args=(event,), daemon=True).start()
