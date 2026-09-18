"""Microsoft Sentinel outbound SIEM forwarding.

Ships SecuraIQ's own security/audit events to a customer's Microsoft
Sentinel workspace using the Azure Monitor **Logs Ingestion API** — the
modern replacement for the now-deprecated HTTP Data Collector API. This
module does not create any Azure resources (Data Collection Endpoint, Data
Collection Rule, custom table) — the operator provisions those in Azure
first (standard Sentinel onboarding) and gives SecuraIQ the DCE URL + DCR
immutable id + an Entra ID app registration with the "Monitoring Metrics
Publisher" role on that DCR. This module only authenticates (real OAuth2
client-credentials flow) and posts events to them.

is_configured() / ping() reflect exactly what's set and reachable — no
"connected" claim without a real token exchange or a real HTTP round trip.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from app.config import settings

_token_lock = threading.Lock()
_token_cache: dict[str, Any] = {"token": "", "expires_at": 0.0}


def _tenant_id() -> str:
    return (settings.siem_azure_tenant_id or settings.azure_tenant_id or "").strip()


def _client_id() -> str:
    return (settings.siem_azure_client_id or settings.azure_client_id or "").strip()


def _client_secret() -> str:
    return (settings.siem_azure_client_secret or settings.azure_client_secret or "").strip()


def is_configured() -> bool:
    return bool(
        _tenant_id()
        and _client_id()
        and _client_secret()
        and (settings.siem_azure_dce_url or "").strip()
        and (settings.siem_azure_dcr_immutable_id or "").strip()
    )


def _get_token_sync() -> str:
    """Real OAuth2 client-credentials token fetch, cached until ~60s before
    expiry. Thread-safe — log_security_event can call this from several
    background forwarding threads at once."""
    with _token_lock:
        now = time.time()
        if _token_cache["token"] and _token_cache["expires_at"] > now + 60:
            return _token_cache["token"]

        import httpx

        tid = _tenant_id()
        url = f"https://login.microsoftonline.com/{tid}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": _client_id(),
            "client_secret": _client_secret(),
            "scope": "https://monitor.azure.com/.default",
        }
        resp = httpx.post(url, data=data, timeout=10.0)
        resp.raise_for_status()
        body = resp.json()
        token = body.get("access_token") or ""
        expires_in = int(body.get("expires_in") or 3600)
        _token_cache["token"] = token
        _token_cache["expires_at"] = now + expires_in
        return token


def _ingestion_url() -> str:
    dce = (settings.siem_azure_dce_url or "").rstrip("/")
    dcr = (settings.siem_azure_dcr_immutable_id or "").strip()
    stream = (settings.siem_azure_stream_name or "Custom-SecuraIQEvents_CL").strip()
    return f"{dce}/dataCollectionRules/{dcr}/streams/{stream}?api-version=2023-01-01"


def send_events_sync(events: list[dict[str, Any]]) -> dict[str, Any]:
    """POST a batch of events to the configured Sentinel Data Collection
    Rule. Synchronous — this is what the background forwarding thread in
    app.siem calls; ping()/test routes wrap this in asyncio.to_thread."""
    if not is_configured():
        return {"ok": False, "error": "not_configured"}
    if not events:
        return {"ok": True, "sent": 0}
    try:
        import httpx

        token = _get_token_sync()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        resp = httpx.post(_ingestion_url(), json=events, headers=headers, timeout=10.0)
        resp.raise_for_status()
        return {"ok": True, "sent": len(events)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:500]}


async def ping() -> dict[str, Any]:
    """Real connectivity check: acquire a token, then send a single
    heartbeat event through the actual ingestion pipeline. If the DCR/stream
    name is wrong this fails for real instead of reporting a fake 'ok'."""
    if not is_configured():
        return {"ok": False, "error": "not_configured"}
    import asyncio

    try:
        result = await asyncio.to_thread(
            send_events_sync,
            [
                {
                    "TimeGenerated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "Product": "securaiq",
                    "Action": "siem_connection_test",
                }
            ],
        )
        if result.get("ok"):
            return {"ok": True, "vendor": "azure_sentinel"}
        return {"ok": False, "error": result.get("error") or "send failed"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:300]}
