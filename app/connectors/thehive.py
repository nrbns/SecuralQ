"""TheHive REST connector — case management for authorized IR labs.

TheHive 4: Authorization header = API key
TheHive 5: Authorization: Bearer <api-key>

Env:
  THEHIVE_BASE_URL=https://thehive.lab
  THEHIVE_API_KEY=...
  THEHIVE_VERIFY_SSL=false
"""

from __future__ import annotations

from typing import Any

import httpx

from app.config import settings


def is_configured() -> bool:
    return bool((settings.thehive_base_url or "").strip() and (settings.thehive_api_key or "").strip())


def _verify() -> bool:
    return bool(getattr(settings, "thehive_verify_ssl", False))


def _headers() -> dict[str, str]:
    key = (settings.thehive_api_key or "").strip()
    # Prefer Bearer (TheHive 5); TheHive 4 also accepts raw key — try Bearer first in callers
    return {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }


def _headers_v4() -> dict[str, str]:
    key = (settings.thehive_api_key or "").strip()
    return {"Authorization": key, "Content-Type": "application/json"}


async def ping() -> dict[str, Any]:
    if not is_configured():
        return {"ok": False, "error": "not_configured"}
    base = settings.thehive_base_url.rstrip("/")
    async with httpx.AsyncClient(timeout=20.0, verify=_verify()) as client:
        for headers in (_headers(), _headers_v4()):
            try:
                # TheHive 5: /api/v1/user/current  | TheHive 4: /api/user/current
                for path in ("/api/v1/user/current", "/api/user/current"):
                    resp = await client.get(f"{base}{path}", headers=headers)
                    if resp.status_code < 400:
                        data = resp.json() if resp.content else {}
                        return {
                            "ok": True,
                            "path": path,
                            "user": (data.get("login") or data.get("name") or data.get("id") or "ok"),
                        }
            except Exception as exc:  # noqa: BLE001
                last = str(exc)
                continue
    return {"ok": False, "error": locals().get("last") or "auth_failed"}


async def fetch_cases(limit: int = 50) -> list[dict[str, Any]]:
    if not is_configured():
        return []
    base = settings.thehive_base_url.rstrip("/")
    limit = max(1, min(int(limit), 200))
    async with httpx.AsyncClient(timeout=30.0, verify=_verify()) as client:
        for headers in (_headers(), _headers_v4()):
            # TheHive 5 query API
            try:
                resp = await client.post(
                    f"{base}/api/v1/query",
                    headers=headers,
                    json={
                        "query": [
                            {"_name": "listCase"},
                            {"_name": "page", "from": 0, "to": limit},
                        ]
                    },
                )
                if resp.status_code < 400:
                    raw = resp.json()
                    items = raw if isinstance(raw, list) else (raw.get("data") or [])
                    return [_normalize_case(x) for x in items]
            except Exception:
                pass
            # TheHive 4 list
            try:
                resp = await client.get(
                    f"{base}/api/case",
                    headers=headers,
                    params={"range": f"0-{limit}"},
                )
                if resp.status_code < 400:
                    raw = resp.json()
                    items = raw if isinstance(raw, list) else []
                    return [_normalize_case(x) for x in items]
            except Exception:
                pass
    return []


def _normalize_case(item: dict[str, Any]) -> dict[str, Any]:
    # TheHive 5 nests under _id / title / severity / stage / status
    cid = str(item.get("_id") or item.get("id") or item.get("caseId") or "")
    title = item.get("title") or item.get("name") or "Case"
    sev = item.get("severity")
    if isinstance(sev, int):
        sev_label = {1: "low", 2: "medium", 3: "high", 4: "critical"}.get(sev, "medium")
    else:
        sev_label = str(sev or "medium").lower()
    status = str(item.get("status") or item.get("stage") or "Open")
    return {
        "case_id": cid,
        "title": str(title)[:300],
        "severity": sev_label,
        "status": status[:80],
        "description": str(item.get("description") or "")[:2000],
        "tags": item.get("tags") or [],
        "raw": item,
    }


async def create_case(*, title: str, description: str = "", severity: int = 2) -> dict[str, Any]:
    if not is_configured():
        raise ValueError("TheHive is not configured")
    base = settings.thehive_base_url.rstrip("/")
    body = {
        "title": title[:200],
        "description": description or title,
        "severity": max(1, min(int(severity), 4)),
    }
    async with httpx.AsyncClient(timeout=25.0, verify=_verify()) as client:
        for headers in (_headers(), _headers_v4()):
            for path in ("/api/v1/case", "/api/case"):
                resp = await client.post(f"{base}{path}", headers=headers, json=body)
                if resp.status_code < 400:
                    return _normalize_case(resp.json() if resp.content else body)
        raise ValueError(f"TheHive create failed: {resp.status_code} {resp.text[:300]}")
