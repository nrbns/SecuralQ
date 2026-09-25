"""Dedicated executor for CPU-heavy scan ingest — not the default asyncio pool.

Scanner binaries stay OS subprocesses. Parse / normalize / PDF must not sit on
the uvicorn event loop. Do not wrap whole jobs in asyncio.to_thread (deadlock
risk with nested to_thread + Postgres async).
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, TypeVar

T = TypeVar("T")

_CPU = ThreadPoolExecutor(max_workers=2, thread_name_prefix="sq-cpu")


async def run_cpu(fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    loop = asyncio.get_running_loop()
    if kwargs:
        return await loop.run_in_executor(_CPU, lambda: fn(*args, **kwargs))
    return await loop.run_in_executor(_CPU, fn, *args)
