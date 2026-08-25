"""Microsoft Defender for Cloud / Azure Resource Graph findings (authorized tenants).

Uses Entra ID client credentials:
  AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
  Optional: AZURE_SUBSCRIPTION_ID
"""

from __future__ import annotations

from typing import Any

import httpx

from app.config import settings


def is_configured() -> bool:
    return bool(
        (settings.azure_tenant_id or "").strip()
        and (settings.azure_client_id or "").strip()
        and (settings.azure_client_secret or "").strip()
    )


async def _token() -> str:
    tid = settings.azure_tenant_id.strip()
    url = f"https://login.microsoftonline.com/{tid}/oauth2/v2.0/token"
    data = {
        "client_id": settings.azure_client_id,
        "client_secret": settings.azure_client_secret,
        "scope": "https://management.azure.com/.default",
        "grant_type": "client_credentials",
    }
    async with httpx.AsyncClient(timeout=25.0) as client:
        resp = await client.post(url, data=data)
    if resp.status_code >= 400:
        raise ValueError(f"Azure token failed {resp.status_code}: {resp.text[:300]}")
    return str((resp.json() or {}).get("access_token") or "")


async def ping() -> dict[str, Any]:
    if not is_configured():
        return {"ok": False, "error": "not_configured"}
    try:
        tok = await _token()
        return {"ok": bool(tok), "vendor": "azure_defender"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:300]}


async def fetch_findings(limit: int = 50) -> list[dict[str, Any]]:
    if not is_configured():
        return []
    tok = await _token()
    sub = (settings.azure_subscription_id or "").strip()
    if not sub:
        return []
    # List secure score / assessments (subset)
    url = (
        f"https://management.azure.com/subscriptions/{sub}"
        f"/providers/Microsoft.Security/assessments?api-version=2020-01-01"
    )
    async with httpx.AsyncClient(timeout=40.0) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {tok}"})
    if resp.status_code >= 400:
        raise ValueError(f"Azure assessments failed {resp.status_code}: {resp.text[:300]}")
    items = ((resp.json() or {}).get("value") or [])[: max(1, min(limit, 200))]
    out = []
    for it in items:
        props = it.get("properties") or {}
        status = ((props.get("status") or {}).get("code") or "").lower()
        if status in {"healthy", "notapplicable"}:
            continue
        name = it.get("name") or it.get("id") or "assessment"
        display = (props.get("displayName") or name)[:240]
        sev = str((props.get("metadata") or {}).get("severity") or "medium").lower()
        out.append(
            {
                "id": str(it.get("id") or name)[:200],
                "title": display,
                "severity": sev if sev in {"critical", "high", "medium", "low"} else "medium",
                "status": status or "unhealthy",
                "source": "azure_defender",
                "resource": str(props.get("resourceDetails") or "")[:300],
            }
        )
    return out
