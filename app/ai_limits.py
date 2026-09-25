"""Demo-safe AI limits — concurrency 1, short timeout, optional hard off.

Does not unload Ollama. Chat is gated so a scan + dashboard stay usable.
"""

from __future__ import annotations

import asyncio
from typing import Any

_sem: asyncio.Semaphore | None = None


def demo_ai_blocked() -> str | None:
    from app.config import settings

    if getattr(settings, "demo_disable_ai", False):
        return (
            "AI is off for this demo so scans and the dashboard stay responsive. "
            "Set DEMO_DISABLE_AI=false in .env when you want chat."
        )
    return None


def ai_concurrency() -> int:
    from app.config import settings

    try:
        return max(1, min(int(getattr(settings, "ai_max_concurrency", 1) or 1), 4))
    except (TypeError, ValueError):
        return 1


def ai_timeout_sec() -> float:
    from app.config import settings

    try:
        return max(5.0, min(float(getattr(settings, "ai_timeout_sec", 20.0) or 20.0), 120.0))
    except (TypeError, ValueError):
        return 20.0


def ai_limits_status() -> dict[str, Any]:
    from app.config import settings

    return {
        "demo_disable_ai": bool(getattr(settings, "demo_disable_ai", False)),
        "ai_max_concurrency": ai_concurrency(),
        "ai_timeout_sec": ai_timeout_sec(),
        "model_backend": getattr(settings, "model_backend", "ollama"),
        "router_enabled": bool(getattr(settings, "router_enabled", True)),
        "local_tools_auto": bool(getattr(settings, "local_tools_auto", True)),
    }


def _semaphore() -> asyncio.Semaphore:
    global _sem
    n = ai_concurrency()
    if _sem is None or getattr(_sem, "_value", n) > n:
        _sem = asyncio.Semaphore(n)
    return _sem


async def run_ai_limited(coro):
    """Run an AI coroutine with demo concurrency + timeout."""
    blocked = demo_ai_blocked()
    if blocked:
        raise RuntimeError(blocked)
    async with _semaphore():
        return await asyncio.wait_for(coro, timeout=ai_timeout_sec())
