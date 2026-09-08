"""SecuraIQ SIEM API — branded console backed by a Wazuh manager when configured.

Primary routes: /api/siem/*
Compat alias:   /api/wazuh/* (webhooks / older clients)
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from app.auth import AuthUser
from app.commercial_api import require_user
from app.config import settings
from app.connectors import wazuh as wazuh_conn
from app.db import audit
from app.wazuh import list_agents
from app.wazuh import status as wazuh_status
from app.xdr import ingest_detections, list_events

# Shared route table (no prefix) — mounted under /api/siem and /api/wazuh
router = APIRouter(tags=["securaiq-siem"])


def _require_ingest_secret(header_val: str | None) -> None:
    secret = (settings.ingest_webhook_secret or "").strip()
    if secret:
        if (header_val or "").strip() != secret:
            raise HTTPException(status_code=401, detail="Invalid ingest secret")
        return
    if settings.auth_enabled:
        raise HTTPException(
            status_code=503,
            detail="Set INGEST_WEBHOOK_SECRET for push ingest when auth is enabled",
        )


def normalize_siem_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Map a manager / Integrator alert payload into an XDR detection row."""
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    rule_id = str(rule.get("id") or alert.get("id") or alert.get("external_id") or "")
    ts = str(alert.get("id") or alert.get("timestamp") or rule_id)
    external_id = str(alert.get("external_id") or f"siem:{rule_id}:{ts}")
    level = int(rule.get("level") or alert.get("level") or 5)
    if level >= 12:
        severity = "critical"
    elif level >= 10:
        severity = "high"
    elif level >= 7:
        severity = "medium"
    else:
        severity = "low"
    host = (
        agent.get("name")
        or agent.get("ip")
        or alert.get("host")
        or data.get("srcip")
        or ""
    )
    title = (
        rule.get("description")
        or alert.get("title")
        or alert.get("full_log")
        or f"SIEM rule {rule_id or 'alert'}"
    )
    return {
        "vendor": "wazuh",
        "external_id": external_id[:200],
        "kind": "siem_alert",
        "severity": severity,
        "host": str(host)[:200],
        "title": str(title)[:300],
        "description": str(alert.get("full_log") or "")[:2000],
        "raw": alert,
    }


# Back-compat name used by older imports / tests
_normalize_wazuh_alert = normalize_siem_alert


@router.get("/status")
async def get_status(user: Annotated[AuthUser, Depends(require_user)]):
    st = wazuh_status()
    if st.get("configured"):
        st["ping"] = await wazuh_conn.ping()
    else:
        st["ping"] = {"ok": False, "error": "not_configured"}
    st["webhook_path"] = "/api/siem/webhook"
    st["webhook_path_compat"] = "/api/wazuh/webhook"
    st["ingest_secret_set"] = bool((settings.ingest_webhook_secret or "").strip())
    st["product"] = "SecuraIQ SIEM"
    st["brand"] = "SecuraIQ"
    return st


@router.get("/overview")
async def get_overview(user: Annotated[AuthUser, Depends(require_user)]):
    """SecuraIQ SIEM console summary (agents, manager, groups, rules, SCA, FIM)."""
    st = wazuh_status()
    if not st.get("configured"):
        return {
            "configured": False,
            "product": "SecuraIQ SIEM",
            "brand": "SecuraIQ",
            "overview": {"ok": False, "error": "not_configured"},
            "groups": [],
            "rules": {"total": 0, "rules": []},
            "sca": [],
            "fim": [],
            "agents_cached": list_agents(limit=50),
            "alerts": list_events(user.id, limit=12, vendor="wazuh"),
        }
    overview = await wazuh_conn.fetch_manager_overview()
    groups = await wazuh_conn.fetch_groups(limit=40)
    rules = await wazuh_conn.fetch_rules_summary(limit=15)
    sca = await wazuh_conn.fetch_sca_summary(limit=20)
    fim = await wazuh_conn.fetch_fim_summary(limit=15)
    return {
        "configured": True,
        "product": "SecuraIQ SIEM",
        "brand": "SecuraIQ",
        "indexer_configured": st.get("indexer_configured"),
        "base_url": st.get("base_url"),
        "overview": overview,
        "groups": groups,
        "rules": rules,
        "sca": sca,
        "fim": fim,
        "agents_cached": list_agents(limit=50),
        "alerts": list_events(user.id, limit=20, vendor="wazuh"),
    }


@router.post("/sync")
async def trigger_sync(user: Annotated[AuthUser, Depends(require_user)]):
    from app.jobs import enqueue_job

    job = enqueue_job("wazuh_sync", {"user_id": user.id}, engine="auto")
    return {"job": job, "product": "SecuraIQ SIEM"}


@router.get("/agents")
async def get_agents(user: Annotated[AuthUser, Depends(require_user)], limit: int = 100):
    return {"agents": list_agents(limit=limit), "product": "SecuraIQ SIEM"}


@router.get("/alerts")
async def get_alerts(user: Annotated[AuthUser, Depends(require_user)], limit: int = 50):
    return {"events": list_events(user.id, limit=limit, vendor="wazuh"), "product": "SecuraIQ SIEM"}


@router.get("/groups")
async def get_groups(user: Annotated[AuthUser, Depends(require_user)], limit: int = 50):
    if not wazuh_conn.is_configured():
        return {"groups": [], "product": "SecuraIQ SIEM"}
    return {"groups": await wazuh_conn.fetch_groups(limit=limit), "product": "SecuraIQ SIEM"}


@router.get("/modules")
async def get_modules(user: Annotated[AuthUser, Depends(require_user)]):
    """SCA + FIM + rules modules for the SecuraIQ SIEM console."""
    if not wazuh_conn.is_configured():
        return {"sca": [], "fim": [], "rules": {"total": 0, "rules": []}, "product": "SecuraIQ SIEM"}
    return {
        "sca": await wazuh_conn.fetch_sca_summary(limit=25),
        "fim": await wazuh_conn.fetch_fim_summary(limit=20),
        "rules": await wazuh_conn.fetch_rules_summary(limit=20),
        "product": "SecuraIQ SIEM",
    }


@router.post("/webhook")
async def siem_webhook(
    request: Request,
    x_securaiq_ingest: Annotated[str | None, Header(alias="X-SecuraIQ-Ingest")] = None,
):
    """Inbound SIEM Integrator / custom hook — upserts into xdr_events.

    Accepts a single alert object, ``{"alerts":[...]}``, or a list.
    """
    _require_ingest_secret(x_securaiq_ingest)
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON") from exc

    raw_alerts: list[Any]
    if isinstance(body, list):
        raw_alerts = body
    elif isinstance(body, dict):
        if "rule" in body or "agent" in body or "full_log" in body:
            raw_alerts = [body]
        else:
            raw_alerts = body.get("alerts") or body.get("detections") or body.get("events") or []
    else:
        raise HTTPException(status_code=400, detail="Expected object or list")

    items = [normalize_siem_alert(a) for a in raw_alerts if isinstance(a, dict)]
    result = ingest_detections(items, user_id="local")
    audit("siem_webhook", "local", {"new": result.get("new"), "total": result.get("total")})
    return {"ok": True, "product": "SecuraIQ SIEM", **result}


# Alias for older call sites
wazuh_webhook = siem_webhook
