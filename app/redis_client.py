"""Shared Redis client factory — plain URL or Redis Sentinel.

Lab default: ``REDIS_URL=redis://...`` via ``from_url``.

HA lab stub: set ``REDIS_SENTINEL_HOSTS=host:26379,...`` and
``REDIS_SENTINEL_MASTER=mymaster`` (optional password). Sentinel takes
precedence when hosts are configured.

Not a production HA proof — callers still must reconnect on failover.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

_log = logging.getLogger("securaiq.redis_client")

_sync_client: Any = None
_sync_client_key: str | None = None


def redis_url() -> str:
    try:
        from app.config import settings

        return (getattr(settings, "redis_url", "") or "").strip()
    except Exception:
        return ""


def sentinel_hosts() -> list[tuple[str, int]]:
    try:
        from app.config import settings

        raw = (getattr(settings, "redis_sentinel_hosts", "") or "").strip()
    except Exception:
        return []
    out: list[tuple[str, int]] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "://" in part:
            part = urlparse(part).netloc or part
        if ":" in part:
            host, _, port_s = part.rpartition(":")
            try:
                out.append((host.strip() or "127.0.0.1", int(port_s)))
            except ValueError:
                continue
        else:
            out.append((part, 26379))
    return out


def sentinel_master() -> str:
    try:
        from app.config import settings

        return (getattr(settings, "redis_sentinel_master", "") or "mymaster").strip() or "mymaster"
    except Exception:
        return "mymaster"


def sentinel_password() -> str | None:
    try:
        from app.config import settings

        pw = (getattr(settings, "redis_sentinel_password", "") or "").strip()
        return pw or None
    except Exception:
        return None


def redis_enabled() -> bool:
    return bool(sentinel_hosts() or redis_url())


def connection_mode() -> str:
    if sentinel_hosts():
        return "sentinel"
    if redis_url():
        return "url"
    return "none"


def _client_cache_key() -> str:
    if sentinel_hosts():
        hosts = ",".join(f"{h}:{p}" for h, p in sentinel_hosts())
        return f"sentinel:{hosts}:{sentinel_master()}"
    return f"url:{redis_url()}"


def reset_clients_for_tests() -> None:
    """Drop cached sync client (tests / settings reload)."""
    global _sync_client, _sync_client_key
    if _sync_client is not None:
        try:
            _sync_client.close()
        except Exception:
            pass
    _sync_client = None
    _sync_client_key = None


def get_sync_redis(
    *,
    decode_responses: bool = True,
    socket_connect_timeout: float = 0.5,
    socket_timeout: float = 0.5,
    cached: bool = False,
) -> Any | None:
    """Return a sync Redis client, or None when Redis is not configured.

    ``cached=True`` reuses one process-local client for health/metrics.
    Publish paths should prefer ``cached=False`` (short-lived) unless callers
    manage lifecycle.
    """
    global _sync_client, _sync_client_key
    if not redis_enabled():
        return None

    key = _client_cache_key()
    if cached and _sync_client is not None and _sync_client_key == key:
        return _sync_client

    hosts = sentinel_hosts()
    try:
        if hosts:
            from redis.sentinel import Sentinel

            sent = Sentinel(
                hosts,
                socket_connect_timeout=socket_connect_timeout,
                socket_timeout=socket_timeout,
                password=sentinel_password(),
            )
            client = sent.master_for(
                sentinel_master(),
                decode_responses=decode_responses,
                socket_connect_timeout=socket_connect_timeout,
                socket_timeout=socket_timeout,
                password=sentinel_password(),
            )
        else:
            import redis

            client = redis.from_url(
                redis_url(),
                decode_responses=decode_responses,
                socket_connect_timeout=socket_connect_timeout,
                socket_timeout=socket_timeout,
            )
    except Exception as exc:
        _log.debug("redis sync client failed: %s", exc)
        return None

    if cached:
        if _sync_client is not None and _sync_client_key != key:
            try:
                _sync_client.close()
            except Exception:
                pass
        _sync_client = client
        _sync_client_key = key
    return client


async def get_async_redis(*, decode_responses: bool = True) -> Any | None:
    """Create an async Redis client (caller owns close/aclose)."""
    if not redis_enabled():
        return None
    hosts = sentinel_hosts()
    try:
        if hosts:
            from redis.asyncio.sentinel import Sentinel as AsyncSentinel

            sent = AsyncSentinel(
                hosts,
                socket_connect_timeout=1.5,
                socket_timeout=5.0,
                password=sentinel_password(),
            )
            return sent.master_for(
                sentinel_master(),
                decode_responses=decode_responses,
                password=sentinel_password(),
            )
        import redis.asyncio as aioredis

        return aioredis.from_url(redis_url(), decode_responses=decode_responses)
    except Exception as exc:
        _log.debug("redis async client failed: %s", exc)
        return None


def describe_backend() -> dict[str, Any]:
    return {
        "enabled": redis_enabled(),
        "mode": connection_mode(),
        "url_set": bool(redis_url()),
        "sentinel_hosts": [f"{h}:{p}" for h, p in sentinel_hosts()],
        "sentinel_master": sentinel_master() if sentinel_hosts() else None,
    }
