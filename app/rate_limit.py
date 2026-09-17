"""Distributed auth rate limiting — Redis when available, in-memory fallback."""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window limiter keyed by client IP + path class.

    Auth/MFA paths use Redis INCR+EXPIRE when Redis is configured so multiple
    API replicas share the same counter. Other paths keep the in-memory
    sliding window (lab / single-instance friendly).

    #234 — when X-API-Key / X-SecuraIQ-Key is present, also apply a per-key
    bucket (and optional org quota api_per_minute overlay).
    """

    def __init__(
        self,
        app,
        *,
        per_minute: int = 120,
        auth_per_minute: int = 30,
        chat_per_minute: int = 40,
        api_key_per_minute: int = 600,
    ):
        super().__init__(app)
        self.per_minute = max(10, per_minute)
        self.auth_per_minute = max(5, auth_per_minute)
        self.chat_per_minute = max(5, chat_per_minute)
        self.api_key_per_minute = max(30, api_key_per_minute)
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def _limit_for(self, path: str) -> int:
        if (
            path.startswith("/api/auth/login")
            or path.startswith("/api/auth/register")
            or path.startswith("/api/auth/mfa")
            or path.startswith("/api/auth/password-reset")
        ):
            return self.auth_per_minute
        if path.startswith("/api/chat") or path.startswith("/api/tools/run"):
            return self.chat_per_minute
        return self.per_minute

    def _is_auth_path(self, path: str) -> bool:
        return path.startswith("/api/auth/")

    def _allow_memory(self, key: str, limit: int) -> bool:
        now = time.time()
        window = 60.0
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def _allow_redis(self, key: str, limit: int) -> bool | None:
        """Return True/False if Redis handled it, or None to fall back to memory."""
        try:
            from app.redis_client import get_sync_redis, redis_enabled

            if not redis_enabled():
                return None
            r = get_sync_redis(cached=True)
            if r is None:
                return None
            rkey = f"securaiq:ratelimit:{key}"
            n = r.incr(rkey)
            if n == 1:
                r.expire(rkey, 60)
            return int(n) <= limit
        except Exception:
            return None

    def _allow(self, key: str, limit: int, *, prefer_redis: bool = False) -> bool:
        if prefer_redis:
            redis_result = self._allow_redis(key, limit)
            if redis_result is not None:
                return redis_result
        return self._allow_memory(key, limit)

    def _api_key_fingerprint(self, request: Request) -> str | None:
        raw = (
            request.headers.get("x-securaiq-key")
            or request.headers.get("x-hackgpt-key")
            or request.headers.get("x-api-key")
            or ""
        ).strip()
        if not raw:
            auth = request.headers.get("authorization") or ""
            if auth.lower().startswith("bearer ") and len(auth) > 20:
                raw = auth[7:].strip()
        if not raw or len(raw) < 8:
            return None
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if not path.startswith("/api/"):
            return await call_next(request)
        if path in {"/api/health", "/api/realtime", "/api/status/public"}:
            return await call_next(request)
        client = request.client.host if request.client else "unknown"
        # Local lab: don't throttle this machine's own UI/scripts by IP
        if client not in {"127.0.0.1", "::1", "localhost"}:
            limit = self._limit_for(path)
            bucket = (
                "auth"
                if self._is_auth_path(path)
                else ("chat" if "chat" in path or "tools" in path else "api")
            )
            key = f"{client}:{bucket}"
            if not self._allow(key, limit, prefer_redis=bucket == "auth"):
                return JSONResponse(
                    {"detail": f"Rate limit exceeded ({limit}/min). Retry shortly."},
                    status_code=429,
                    headers={"Retry-After": "60"},
                )

        # #234 per-key / tenant API throttle
        fp = self._api_key_fingerprint(request)
        if fp:
            key_limit = self.api_key_per_minute
            org_hdr = (request.headers.get("x-securaiq-org") or "").strip()
            if org_hdr:
                try:
                    from app.tenant_quotas import get_quotas

                    key_limit = int(get_quotas(org_hdr).get("api_per_minute") or key_limit)
                except Exception:
                    pass
            if not self._allow(f"apikey:{fp}", key_limit, prefer_redis=True):
                return JSONResponse(
                    {"detail": f"API key rate limit exceeded ({key_limit}/min)."},
                    status_code=429,
                    headers={"Retry-After": "60"},
                )
        return await call_next(request)
