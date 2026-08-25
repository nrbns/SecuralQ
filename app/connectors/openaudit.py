"""Open-AudIT inventory connector (Firstwave / community).

Cookie session: POST {base}/logon with username + password, then GET collections
with Accept: application/json.

Docs: https://docs.community.firstwave.com/wiki/spaces/OA/pages/3163947960/The+Open-AudIT+API
Download: https://www.open-audit.org/download_thanks.php

Setup (.env / Settings):
  OPENAUDIT_BASE_URL=http://192.168.56.10
  OPENAUDIT_USER=admin
  OPENAUDIT_PASSWORD=...
  OPENAUDIT_API_PREFIX=/open-audit/index.php   # v5 default
  OPENAUDIT_VERIFY_SSL=false
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from app.config import settings

_UA = {"User-Agent": "SecuraIQ-OpenAudit/1.0", "Accept": "application/json"}


def is_configured() -> bool:
    return bool(
        (getattr(settings, "openaudit_base_url", "") or "").strip()
        and (getattr(settings, "openaudit_user", "") or "").strip()
        and (getattr(settings, "openaudit_password", "") or "").strip()
    )


def _verify() -> bool:
    return bool(getattr(settings, "openaudit_verify_ssl", False))


def api_root() -> str:
    raw = (getattr(settings, "openaudit_base_url", "") or "").strip().rstrip("/")
    prefix = (getattr(settings, "openaudit_api_prefix", "") or "/open-audit/index.php").strip()
    if prefix and not prefix.startswith("/"):
        prefix = "/" + prefix
    prefix = prefix.rstrip("/")
    lower = raw.lower()
    if "/open-audit/" in lower or lower.endswith("/omk/open-audit"):
        return raw
    return f"{raw}{prefix}"


def _attrs(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    attrs = item.get("attributes")
    if isinstance(attrs, dict):
        return attrs
    return item


def _clean_ip(raw: str) -> str:
    """Open-AudIT often stores padded IPs like 010.000.000.001."""
    text = (raw or "").strip()
    if not text:
        return ""
    parts = text.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            return ".".join(str(int(p)) for p in parts)
        except ValueError:
            return text
    return text


def _normalize_device(item: Any) -> dict[str, Any] | None:
    attrs = _attrs(item)
    if not attrs and not isinstance(item, dict):
        return None
    did = str(
        (item.get("id") if isinstance(item, dict) else "")
        or attrs.get("id")
        or attrs.get("system_id")
        or attrs.get("device_id")
        or ""
    )
    hostname = str(
        attrs.get("hostname")
        or attrs.get("name")
        or attrs.get("dns_hostname")
        or attrs.get("sysName")
        or ""
    ).strip()
    ip = _clean_ip(str(attrs.get("ip") or attrs.get("man_ip_address") or attrs.get("ip_padded") or ""))
    if not did and not hostname and not ip:
        return None
    dtype = str(attrs.get("type") or attrs.get("man_type") or "device").strip() or "device"
    status = str(attrs.get("status") or attrs.get("man_status") or "").strip().lower()
    os_family = str(attrs.get("os_family") or attrs.get("man_os_family") or attrs.get("os_name") or "").strip()
    domain = str(attrs.get("domain") or "").strip()
    description = str(attrs.get("description") or attrs.get("man_description") or "").strip()
    manufacturer = str(attrs.get("manufacturer") or "").strip()
    model = str(attrs.get("model") or "").strip()
    name = hostname or ip or f"device-{did}"
    return {
        "device_id": did or name,
        "name": name,
        "hostname": hostname,
        "ip": ip,
        "type": dtype,
        "status": status,
        "os": os_family,
        "domain": domain,
        "description": description,
        "manufacturer": manufacturer,
        "model": model,
        "raw": attrs if attrs else item,
    }


def _extract_list(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        return data["data"]
    for key in ("devices", "items", "rows", "networks", "discoveries"):
        val = payload.get(key)
        if isinstance(val, list):
            return val
    return []


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=30.0, verify=_verify(), follow_redirects=True, headers=dict(_UA))


async def _logon(client: httpx.AsyncClient) -> None:
    root = api_root()
    user = (settings.openaudit_user or "").strip()
    password = settings.openaudit_password or ""
    payload = {"username": user, "password": password}
    resp = await client.post(f"{root}/logon", data=payload, params={"format": "json"})
    if resp.status_code >= 400:
        resp = await client.post(f"{root}/logon", json=payload, params={"format": "json"})
    if resp.status_code >= 400:
        raise ValueError(f"Open-AudIT logon failed {resp.status_code}: {resp.text[:240]}")
    text = (resp.text or "")[:1200].lower()
    if 'name="username"' in text and 'name="password"' in text and "devices" not in text:
        raise ValueError("Open-AudIT logon rejected (check username/password)")


async def _get(client: httpx.AsyncClient, path: str, params: dict[str, Any] | None = None) -> Any:
    root = api_root()
    q = {"format": "json", **(params or {})}
    resp = await client.get(f"{root}{path}", params=q)
    if resp.status_code >= 400:
        raise ValueError(f"Open-AudIT GET {path} failed {resp.status_code}: {resp.text[:240]}")
    ctype = (resp.headers.get("content-type") or "").lower()
    if "json" not in ctype:
        # Some installs ignore Accept and need format=json already set
        try:
            return resp.json()
        except Exception as exc:
            raise ValueError(f"Open-AudIT returned non-JSON for {path}") from exc
    return resp.json()


async def ping() -> dict[str, Any]:
    if not is_configured():
        return {"ok": False, "error": "not_configured"}
    try:
        async with _client() as client:
            await _logon(client)
            payload = await _get(client, "/devices", {"limit": 1})
        total = 0
        if isinstance(payload, dict):
            meta = payload.get("meta") or {}
            total = int(meta.get("total") or meta.get("filtered") or 0)
            if not total:
                total = len(_extract_list(payload))
        else:
            total = len(_extract_list(payload))
        host = urlparse(settings.openaudit_base_url).hostname or ""
        return {"ok": True, "host": host, "devices_hint": total}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:300]}


async def fetch_devices(limit: int = 500) -> list[dict[str, Any]]:
    if not is_configured():
        return []
    async with _client() as client:
        await _logon(client)
        params: dict[str, Any] = {"limit": max(1, min(2000, int(limit)))}
        rich = {
            **params,
            "properties": (
                "devices.id,devices.hostname,devices.name,devices.ip,devices.type,"
                "devices.status,devices.os_family,devices.os_name,devices.domain,"
                "devices.description,devices.manufacturer,devices.model"
            ),
        }
        try:
            payload = await _get(client, "/devices", rich)
        except ValueError:
            payload = await _get(client, "/devices", params)
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in _extract_list(payload):
        row = _normalize_device(item)
        if not row:
            continue
        if (row.get("status") or "") in {"deleted", "removed"}:
            continue
        key = row["device_id"]
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


async def fetch_networks(limit: int = 100) -> list[dict[str, Any]]:
    if not is_configured():
        return []
    try:
        async with _client() as client:
            await _logon(client)
            payload = await _get(client, "/networks", {"limit": max(1, min(500, int(limit)))})
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for item in _extract_list(payload):
        attrs = _attrs(item)
        name = str(attrs.get("name") or (item.get("id") if isinstance(item, dict) else "") or "")
        network = str(attrs.get("network") or attrs.get("subnet") or "")
        if name or network:
            out.append(
                {
                    "id": str((item.get("id") if isinstance(item, dict) else "") or name),
                    "name": name or network,
                    "network": network,
                }
            )
    return out


async def trigger_subnet_discovery(subnet: str, *, name: str = "") -> dict[str, Any]:
    """Best-effort Open-AudIT discovery run for an owned/lab CIDR.

    See https://www.open-audit.org/
    """
    if not is_configured():
        return {"ok": False, "skipped": "not_configured"}
    cidr = (subnet or "").strip()
    if not cidr:
        return {"ok": False, "skipped": "no_subnet"}
    label = (name or f"SecuraIQ {cidr}").strip()[:80]
    body = {
        "data": {
            "type": "discoveries",
            "attributes": {
                "name": label,
                "subnet": cidr,
                "network_address": cidr,
                "type": "subnet",
            },
        }
    }
    try:
        async with _client() as client:
            await _logon(client)
            root = api_root()
            resp = await client.post(
                f"{root}/discoveries",
                json=body,
                params={"format": "json"},
                headers={"Content-Type": "application/json", **_UA},
            )
            if resp.status_code >= 400:
                return {
                    "ok": False,
                    "error": f"create discovery {resp.status_code}: {resp.text[:200]}",
                }
            payload: dict[str, Any] = {}
            try:
                parsed = resp.json()
                if isinstance(parsed, dict):
                    payload = parsed
            except Exception:
                payload = {}
            did = ""
            data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
            if isinstance(data, dict):
                did = str(data.get("id") or (data.get("attributes") or {}).get("id") or "")
            if did:
                await client.post(
                    f"{root}/discoveries/{did}",
                    params={"format": "json", "action": "execute"},
                )
            return {"ok": True, "discovery_id": did or None, "subnet": cidr}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:300]}
