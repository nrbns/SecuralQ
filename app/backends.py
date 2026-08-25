"""Reachability checks for local model backends."""

from __future__ import annotations

import httpx

from app.config import settings
from app.hermes_client import hermes_reachable

__all__ = ["openai_compat_reachable", "hermes_reachable"]


async def openai_compat_reachable() -> bool:
    url = f"{settings.openai_compat_base_url.rstrip('/')}/models"
    headers = {"Authorization": f"Bearer {settings.openai_compat_api_key}"}
    timeout = httpx.Timeout(connect=1.5, read=2.0, write=2.0, pool=2.0)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            return (await client.get(url, headers=headers)).status_code == 200
    except httpx.HTTPError:
        return False
