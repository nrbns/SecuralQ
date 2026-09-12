"""Internal SecuraIQ Admin Health — component status for operators."""

from __future__ import annotations

from typing import Any

from app.config import settings
from app.db import current_backend, get_conn, using_postgres


def _status(ok: bool, detail: str = "", degraded: bool = False) -> dict[str, Any]:
    if ok and not degraded:
        state = "green"
    elif ok and degraded:
        state = "yellow"
    else:
        state = "red"
    return {"status": state, "ok": ok, "detail": detail}


def collect_admin_health() -> dict[str, Any]:
    components: dict[str, dict[str, Any]] = {}

    # API process itself
    components["api"] = _status(True, "process up")

    # Database
    try:
        c = get_conn()
        c.execute("SELECT 1").fetchone()
        backend = current_backend()
        prod = (settings.deployment_mode or "").lower() in {"production", "prod", "commercial", "saas", "cloud"}
        if prod and backend != "postgres":
            components["database"] = _status(False, f"production requires postgres; got {backend}")
        else:
            components["database"] = _status(True, f"backend={backend}")
    except Exception as exc:
        components["database"] = _status(False, str(exc)[:200])

    # Redis (optional) + Streams durability snapshot
    redis_url = (settings.redis_url or "").strip()
    sentinel_hosts = (getattr(settings, "redis_sentinel_hosts", "") or "").strip()
    if not redis_url and not sentinel_hosts:
        components["redis"] = _status(True, "not configured (in-process bus)", degraded=True)
        components["event_bus"] = _status(True, "mode=in_process", degraded=True)
    else:
        try:
            from app.redis_client import get_sync_redis, describe_backend

            r = get_sync_redis(decode_responses=True, socket_connect_timeout=1.5, socket_timeout=1.5)
            if r is None:
                raise RuntimeError("redis client unavailable")
            try:
                r.ping()
                backend = describe_backend()
                detail = f"ping ok mode={backend.get('mode')}"
                if backend.get("sentinel_hosts"):
                    detail += f" master={backend.get('sentinel_master')}"
                components["redis"] = _status(True, detail[:200])
            finally:
                try:
                    r.close()
                except Exception:
                    pass
        except Exception as exc:
            components["redis"] = _status(False, str(exc)[:200])
        try:
            from app.realtime_bus import backend_status
            from app.event_processor import stream_monitor_snapshot

            bus = backend_status() or {}
            snap = stream_monitor_snapshot() or {}
            thr = bus.get("throughput") or {}
            mode = bus.get("mode") or "unknown"
            detail = (
                f"mode={mode} stream_len={snap.get('stream_length')} "
                f"pending={snap.get('pending_count')} dlq={snap.get('dlq_length')} "
                f"lag={snap.get('consumer_group_lag')} "
                f"eps={thr.get('events_per_sec')} bp={thr.get('backpressure_active')}"
            )
            degraded = mode not in ("redis_streams_fanout", "redis_streams+pubsub")
            if thr.get("backpressure_active"):
                degraded = True
            components["event_bus"] = _status(True, detail[:240], degraded=degraded)
        except Exception as exc:
            components["event_bus"] = _status(False, str(exc)[:200])

    # Agent gateway
    try:
        gw_on = bool(getattr(settings, "agent_gateway_enabled", True))
        components["agent_gateway"] = _status(
            True,
            "enabled" if gw_on else "disabled",
            degraded=not gw_on,
        )
    except Exception:
        components["agent_gateway"] = _status(True, "unknown", degraded=True)

    # Agent crypto posture (RT-17) — warn when production lacks mandatory seals
    try:
        prod = (settings.deployment_mode or "").lower() in {
            "production",
            "prod",
            "commercial",
            "saas",
            "cloud",
        }
        require_sig = bool(getattr(settings, "agent_require_command_signature", False))
        require_replay = bool(getattr(settings, "agent_require_replay_protection", False))
        if prod and (not require_sig or not require_replay):
            components["agent_crypto"] = _status(
                True,
                "production should set AGENT_REQUIRE_COMMAND_SIGNATURE=true and "
                "AGENT_REQUIRE_REPLAY_PROTECTION=true (mTLS still separate)",
                degraded=True,
            )
        elif require_sig:
            components["agent_crypto"] = _status(
                True,
                f"require_signature={require_sig} require_replay={require_replay}",
            )
        else:
            components["agent_crypto"] = _status(
                True,
                "lab soft seals (HMAC default; RT-17 off)",
                degraded=True,
            )
    except Exception as exc:
        components["agent_crypto"] = _status(True, str(exc)[:120], degraded=True)

    # AI gateway (config readiness — not a live model call)
    backend = settings.model_backend
    if backend == "ollama":
        components["ai_gateway"] = _status(True, f"backend={backend}", degraded=False)
    elif backend in {"openai", "openrouter", "groq", "together", "fireworks"}:
        key_map = {
            "openai": settings.openai_api_key,
            "openrouter": settings.openrouter_api_key,
            "groq": settings.groq_api_key,
            "together": settings.together_api_key,
            "fireworks": settings.fireworks_api_key,
        }
        ok = bool(key_map.get(backend))
        components["ai_gateway"] = _status(ok, f"backend={backend}", degraded=not ok)
    else:
        components["ai_gateway"] = _status(True, f"backend={backend}", degraded=True)

    # Workers — Prefect optional
    if settings.prefect_enabled:
        components["workers"] = _status(True, "prefect enabled", degraded=True)
    else:
        components["workers"] = _status(True, "local asyncio jobs", degraded=True)

    # Integrations — configured count only
    configured = 0
    for flag in (
        settings.wazuh_base_url,
        settings.jira_base_url,
        settings.slack_webhook_url,
        settings.crowdstrike_client_id,
        settings.defender_client_id,
        settings.sentinelone_api_token,
        settings.sophos_client_id,
        settings.sonarqube_base_url,
    ):
        if (flag or "").strip():
            configured += 1
    components["integrations"] = _status(
        True,
        f"{configured} connector(s) configured",
        degraded=configured == 0,
    )

    # Billing
    if settings.stripe_secret_key and settings.stripe_webhook_secret:
        components["billing"] = _status(True, "stripe keys set")
    elif settings.billing_enforcement_enabled:
        components["billing"] = _status(False, "enforcement on but Stripe keys missing")
    else:
        components["billing"] = _status(True, "soft / not enforced", degraded=True)

    overall = "green"
    if any(c["status"] == "red" for c in components.values()):
        overall = "red"
    elif any(c["status"] == "yellow" for c in components.values()):
        overall = "yellow"

    return {
        "overall": overall,
        "deployment_mode": settings.deployment_mode,
        "postgres_required": bool(getattr(settings, "require_postgres_in_production", True)),
        "using_postgres": using_postgres(),
        "components": components,
    }
