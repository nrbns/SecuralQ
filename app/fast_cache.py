"""Short TTL cache + a reserved thread pool for cheap reads.

Heavy dashboard/software work uses the default executor. Cheap GETs (orgs,
lite KPIs, risks) use this pool so they are not queued behind a 6–10s
dashboard compute. Lab-only — not a 5k/100k claim.
"""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, TypeVar

T = TypeVar("T")

_STORE: dict[str, tuple[float, float, Any]] = {}
_LITE_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="sq-fast")


def cache_get(key: str) -> Any | None:
    hit = _STORE.get(key)
    if not hit:
        return None
    ts, ttl, val = hit
    if time.monotonic() - ts > ttl:
        return None
    return val


def cache_set(key: str, val: Any, ttl: float) -> Any:
    _STORE[key] = (time.monotonic(), float(ttl), val)
    return val


def cache_clear(prefix: str = "") -> None:
    if not prefix:
        _STORE.clear()
        return
    for k in list(_STORE):
        if k.startswith(prefix):
            _STORE.pop(k, None)


async def run_fast(fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    loop = asyncio.get_running_loop()
    if kwargs:
        return await loop.run_in_executor(_LITE_POOL, lambda: fn(*args, **kwargs))
    return await loop.run_in_executor(_LITE_POOL, fn, *args)
