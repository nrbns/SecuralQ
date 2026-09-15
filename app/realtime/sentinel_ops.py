"""Redis Sentinel health helpers for lab HA (not Cluster certification)."""

from __future__ import annotations

from typing import Any


def invalidate_redis_clients() -> None:
    """Drop process-local cached Redis clients after failover / config change."""
    try:
        from app.redis_client import reset_clients_for_tests

        reset_clients_for_tests()
    except Exception:
        pass


def ping_master(*, timeout: float = 1.5) -> dict[str, Any]:
    """Ping the current master (URL or Sentinel). Invalidates cache on failure."""
    out: dict[str, Any] = {
        "ok": False,
        "mode": "none",
        "ping": None,
        "error": None,
    }
    try:
        from app.redis_client import (
            connection_mode,
            describe_backend,
            get_sync_redis,
            redis_enabled,
        )

        out["mode"] = connection_mode()
        out["backend"] = describe_backend()
        if not redis_enabled():
            out["error"] = "redis_not_configured"
            return out
        client = get_sync_redis(
            decode_responses=True,
            socket_connect_timeout=timeout,
            socket_timeout=timeout,
            cached=False,
        )
        if client is None:
            out["error"] = "client_unavailable"
            invalidate_redis_clients()
            return out
        try:
            out["ping"] = bool(client.ping())
            out["ok"] = bool(out["ping"])
        except Exception as exc:
            out["error"] = str(exc)[:300]
            invalidate_redis_clients()
        finally:
            try:
                client.close()
            except Exception:
                pass
    except Exception as exc:
        out["error"] = str(exc)[:300]
        invalidate_redis_clients()
    return out


def sentinel_ready_report() -> dict[str, Any]:
    """Describe whether Sentinel settings are present and master is reachable."""
    try:
        from app.redis_client import connection_mode, describe_backend, sentinel_hosts

        hosts = sentinel_hosts()
        base = {
            "sentinel_configured": bool(hosts),
            "mode": connection_mode(),
            "backend": describe_backend(),
            "disclaimer": (
                "lab Sentinel stub — measured failover is an ops proof, "
                "not a marketing HA claim"
            ),
        }
        if not hosts:
            base["reachable"] = False
            base["hint"] = (
                "docker compose --profile redis-ha up -d && "
                "REDIS_SENTINEL_HOSTS=127.0.0.1:26379 REDIS_SENTINEL_MASTER=mymaster"
            )
            return base
        ping = ping_master()
        base["reachable"] = bool(ping.get("ok"))
        base["ping"] = ping
        return base
    except Exception as exc:
        return {
            "sentinel_configured": False,
            "reachable": False,
            "error": str(exc)[:300],
            "disclaimer": "lab Sentinel stub — not HA certification",
        }
