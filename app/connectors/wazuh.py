"""Wazuh manager API connector — agents + alerts for authorized SOC labs.

Auth: POST /security/user/authenticate with HTTP Basic → JWT Bearer.
Alerts: prefer Wazuh Indexer (OpenSearch) when WAZUH_INDEXER_URL is set;
otherwise derive operational signals from disconnected agents and
vulnerability endpoints on the manager API.

Setup (.env / Settings):
  WAZUH_BASE_URL=https://wazuh.example:55000
  WAZUH_USER=wazuh-wui
  WAZUH_PASSWORD=...
  WAZUH_VERIFY_SSL=false   # labs often use self-signed certs
  # Optional Indexer for real alert pull:
  WAZUH_INDEXER_URL=https://indexer.example:9200
  WAZUH_INDEXER_USER=admin
  WAZUH_INDEXER_PASSWORD=...
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from app.config import settings

_token_cache: dict[str, Any] = {"token": "", "expires": 0.0}


def is_configured() -> bool:
    return bool(
        (settings.wazuh_base_url or "").strip()
        and (settings.wazuh_user or "").strip()
        and (settings.wazuh_password or "").strip()
    )


def indexer_configured() -> bool:
    return bool((settings.wazuh_indexer_url or "").strip())


def _verify() -> bool:
    return bool(getattr(settings, "wazuh_verify_ssl", False))


async def _authenticate(client: httpx.AsyncClient) -> str:
    now = time.time()
    if _token_cache["token"] and _token_cache["expires"] > now + 30:
        return str(_token_cache["token"])
    base = settings.wazuh_base_url.rstrip("/")
    resp = await client.post(
        f"{base}/security/user/authenticate",
        params={"raw": "true"},
        auth=(settings.wazuh_user, settings.wazuh_password),
    )
    if resp.status_code >= 400:
        raise ValueError(f"Wazuh auth failed {resp.status_code}: {resp.text[:300]}")
    token = (resp.text or "").strip().strip('"')
    if not token:
        # Some builds return JSON {"data":{"token":"..."}}
        try:
            token = ((resp.json() or {}).get("data") or {}).get("token") or ""
        except Exception:
            token = ""
    if not token:
        raise ValueError("Wazuh auth returned empty token")
    _token_cache["token"] = token
    _token_cache["expires"] = now + 800  # default JWT ~900s
    return token


async def _manager_get(path: str, params: dict[str, Any] | None = None) -> Any:
    base = settings.wazuh_base_url.rstrip("/")
    async with httpx.AsyncClient(timeout=25.0, verify=_verify()) as client:
        token = await _authenticate(client)
        resp = await client.get(
            f"{base}{path}",
            params=params or {},
            headers={"Authorization": f"Bearer {token}"},
        )
    if resp.status_code >= 400:
        raise ValueError(f"Wazuh {path} error {resp.status_code}: {resp.text[:300]}")
    return resp.json()


def _severity_from_level(level: Any) -> str:
    try:
        n = int(level)
    except (TypeError, ValueError):
        return "medium"
    if n >= 12:
        return "critical"
    if n >= 10:
        return "high"
    if n >= 7:
        return "medium"
    return "low"


async def fetch_agents(limit: int = 200) -> list[dict[str, Any]]:
    if not is_configured():
        return []
    data = await _manager_get(
        "/agents",
        {"limit": min(max(limit, 1), 500), "sort": "-lastKeepAlive"},
    )
    items = ((data or {}).get("data") or {}).get("affected_items") or []
    out: list[dict[str, Any]] = []
    for a in items:
        out.append(
            {
                "agent_id": str(a.get("id") or ""),
                "name": a.get("name") or "",
                "ip": a.get("ip") or "",
                "status": a.get("status") or "",
                "os": ((a.get("os") or {}).get("name") or a.get("os", {}).get("uname"))
                if isinstance(a.get("os"), dict)
                else str(a.get("os") or ""),
                "version": a.get("version") or "",
                "group": ",".join(a.get("group") or []) if isinstance(a.get("group"), list) else str(a.get("group") or ""),
                "last_keep_alive": a.get("lastKeepAlive") or "",
                "raw": a,
            }
        )
    return out


async def fetch_syscollector_packages(agent_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
    """Installed packages reported by Wazuh syscollector for one agent."""
    if not is_configured() or not (agent_id or "").strip():
        return []
    aid = str(agent_id).strip()
    data = await _manager_get(
        f"/syscollector/{aid}/packages",
        {"limit": min(max(limit, 1), 500), "sort": "-name"},
    )
    items = ((data or {}).get("data") or {}).get("affected_items") or []
    out: list[dict[str, Any]] = []
    for pkg in items:
        if not isinstance(pkg, dict):
            continue
        name = str(pkg.get("name") or pkg.get("package") or "").strip()
        if not name:
            continue
        out.append(
            {
                "name": name,
                "version": str(pkg.get("version") or "")[:80],
                "vendor": str(pkg.get("vendor") or pkg.get("publisher") or "")[:120],
                "publisher": str(pkg.get("publisher") or pkg.get("vendor") or "")[:120],
                "architecture": str(pkg.get("architecture") or pkg.get("arch") or "")[:32],
                "location": str(pkg.get("location") or pkg.get("install_time") or "")[:200],
                "install_time": str(pkg.get("install_time") or "")[:40],
                "description": str(pkg.get("description") or "")[:300],
            }
        )
    return out


async def _fetch_alerts_from_indexer(limit: int = 100) -> list[dict[str, Any]]:
    url = settings.wazuh_indexer_url.rstrip("/")
    user = (settings.wazuh_indexer_user or settings.wazuh_user or "").strip()
    password = (settings.wazuh_indexer_password or settings.wazuh_password or "").strip()
    body = {
        "size": min(max(limit, 1), 200),
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [{"match_all": {}}]}},
    }
    auth = (user, password) if user and password else None
    async with httpx.AsyncClient(timeout=30.0, verify=_verify()) as client:
        resp = await client.post(
            f"{url}/wazuh-alerts*/_search",
            json=body,
            auth=auth,
            headers={"Content-Type": "application/json"},
        )
    if resp.status_code >= 400:
        raise ValueError(f"Wazuh indexer error {resp.status_code}: {resp.text[:300]}")
    hits = (((resp.json() or {}).get("hits") or {}).get("hits")) or []
    out: list[dict[str, Any]] = []
    for h in hits:
        src = h.get("_source") or {}
        rule = src.get("rule") or {}
        agent = src.get("agent") or {}
        ext = h.get("_id") or src.get("id") or f"{src.get('timestamp')}-{rule.get('id')}"
        out.append(
            {
                "vendor": "wazuh",
                "external_id": str(ext),
                "kind": "siem_alert",
                "severity": _severity_from_level(rule.get("level")),
                "host": agent.get("name") or agent.get("id") or "",
                "title": rule.get("description") or src.get("full_log") or "SecuraIQ SIEM alert",
                "description": f"rule={rule.get('id')} mitre={rule.get('mitre') or rule.get('groups')}",
                "raw": src,
            }
        )
    return out


async def _fetch_signals_from_manager(limit: int = 100) -> list[dict[str, Any]]:
    """Fallback when Indexer is not configured — disconnected agents + vulns."""
    out: list[dict[str, Any]] = []
    agents = await fetch_agents(limit=min(limit, 200))
    for a in agents:
        status = (a.get("status") or "").lower()
        if status in {"disconnected", "never_connected", "pending"}:
            out.append(
                {
                    "vendor": "wazuh",
                    "external_id": f"agent-status-{a.get('agent_id')}-{status}",
                    "kind": "agent_health",
                    "severity": "high" if status == "disconnected" else "medium",
                    "host": a.get("name") or a.get("ip") or "",
                    "title": f"SIEM agent {status}: {a.get('name') or a.get('agent_id')}",
                    "description": f"ip={a.get('ip')} version={a.get('version')} last={a.get('last_keep_alive')}",
                    "raw": a.get("raw") or a,
                }
            )
    try:
        data = await _manager_get("/vulnerability", {"limit": min(limit, 100)})
        items = ((data or {}).get("data") or {}).get("affected_items") or []
        for v in items[:limit]:
            agent = v.get("agent") or {}
            cve = v.get("cve") or v.get("name") or "vuln"
            out.append(
                {
                    "vendor": "wazuh",
                    "external_id": f"vuln-{agent.get('id')}-{cve}",
                    "kind": "vulnerability",
                    "severity": (v.get("severity") or "medium").lower(),
                    "host": agent.get("name") or "",
                    "title": f"{cve}: {v.get('title') or v.get('name') or 'Vulnerability'}",
                    "description": v.get("condition") or v.get("detection_time") or "",
                    "raw": v,
                }
            )
    except Exception:
        pass
    return out[:limit]


async def fetch_detections(limit: int = 100) -> list[dict[str, Any]]:
    """Normalized detections for XDR-style ingestion (vendor=wazuh)."""
    if not is_configured():
        return []
    if indexer_configured():
        try:
            return await _fetch_alerts_from_indexer(limit=limit)
        except Exception:
            # Fall through to manager signals so sync still produces value
            pass
    return await _fetch_signals_from_manager(limit=limit)


async def fetch_manager_overview() -> dict[str, Any]:
    """Aggregate manager health + agent status counts for SecuraIQ SIEM UI."""
    if not is_configured():
        return {"ok": False, "error": "not_configured"}
    out: dict[str, Any] = {"ok": True, "indexer": indexer_configured()}
    try:
        root = await _manager_get("/")
        data = (root or {}).get("data") or {}
        out["title"] = data.get("title") or "Wazuh API"
        out["api_version"] = data.get("api_version") or ""
        out["hostname"] = data.get("hostname") or data.get("node_name") or ""
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:300]}

    try:
        summary = await _manager_get("/agents/summary/status")
        # Wazuh returns connection/status buckets under data
        d = (summary or {}).get("data") or summary or {}
        conn = d.get("connection") or d.get("agent_status") or d
        out["agents"] = {
            "active": int(conn.get("active") or conn.get("Active") or 0),
            "disconnected": int(conn.get("disconnected") or conn.get("Disconnected") or 0),
            "never_connected": int(
                conn.get("never_connected") or conn.get("Never connected") or 0
            ),
            "pending": int(conn.get("pending") or conn.get("Pending") or 0),
            "total": int(conn.get("total") or 0)
            or (
                int(conn.get("active") or 0)
                + int(conn.get("disconnected") or 0)
                + int(conn.get("never_connected") or 0)
                + int(conn.get("pending") or 0)
            ),
        }
    except Exception as exc:
        out["agents_error"] = str(exc)[:200]
        out["agents"] = {"active": 0, "disconnected": 0, "never_connected": 0, "pending": 0, "total": 0}

    try:
        info = await _manager_get("/manager/info")
        mi = ((info or {}).get("data") or {}).get("affected_items") or []
        if mi:
            m0 = mi[0] if isinstance(mi[0], dict) else {}
            out["manager"] = {
                "version": m0.get("version") or "",
                "type": m0.get("type") or "",
                "max_agents": m0.get("max_agents") or "",
                "node_name": m0.get("node_name") or m0.get("name") or "",
            }
    except Exception:
        out["manager"] = {}

    return out


async def fetch_groups(limit: int = 50) -> list[dict[str, Any]]:
    if not is_configured():
        return []
    try:
        data = await _manager_get("/groups", {"limit": min(max(limit, 1), 100)})
        items = ((data or {}).get("data") or {}).get("affected_items") or []
        out: list[dict[str, Any]] = []
        for g in items:
            out.append(
                {
                    "name": g.get("name") or "",
                    "count": int(g.get("count") or g.get("agents") or 0),
                    "mergedSum": g.get("mergedSum") or "",
                    "configSum": g.get("configSum") or "",
                }
            )
        return out
    except Exception:
        return []


async def fetch_rules_summary(limit: int = 20) -> dict[str, Any]:
    if not is_configured():
        return {"total": 0, "rules": []}
    try:
        data = await _manager_get(
            "/rules",
            {"limit": min(max(limit, 1), 50), "sort": "-id"},
        )
        meta = ((data or {}).get("data") or {})
        items = meta.get("affected_items") or []
        total = int(meta.get("total_affected_items") or len(items))
        rules = [
            {
                "id": str(r.get("id") or ""),
                "level": r.get("level"),
                "description": r.get("description") or "",
                "groups": r.get("groups") or [],
            }
            for r in items
        ]
        return {"total": total, "rules": rules}
    except Exception as exc:
        return {"total": 0, "rules": [], "error": str(exc)[:200]}


async def fetch_sca_summary(limit: int = 30) -> list[dict[str, Any]]:
    """Security Configuration Assessment results across agents (best-effort)."""
    if not is_configured():
        return []
    agents = await fetch_agents(limit=min(limit, 40))
    out: list[dict[str, Any]] = []
    for a in agents[:12]:
        aid = a.get("agent_id")
        if not aid or aid == "000":
            continue
        try:
            data = await _manager_get(f"/sca/{aid}", {"limit": 5})
            items = ((data or {}).get("data") or {}).get("affected_items") or []
            for s in items:
                out.append(
                    {
                        "agent_id": aid,
                        "agent_name": a.get("name") or aid,
                        "policy_id": s.get("policy_id") or s.get("name") or "",
                        "name": s.get("name") or s.get("policy_id") or "SCA policy",
                        "score": s.get("score"),
                        "pass": s.get("pass"),
                        "fail": s.get("fail"),
                        "invalid": s.get("invalid"),
                        "total_checks": s.get("total_checks"),
                    }
                )
        except Exception:
            continue
    return out[:limit]


async def fetch_fim_summary(limit: int = 20) -> list[dict[str, Any]]:
    """Recent File Integrity Monitoring events (syscheck) via manager if available."""
    if not is_configured():
        return []
    # Prefer indexer when present — FIM lives in alerts index with syscheck fields
    if indexer_configured():
        try:
            url = settings.wazuh_indexer_url.rstrip("/")
            user = (settings.wazuh_indexer_user or settings.wazuh_user or "").strip()
            password = (settings.wazuh_indexer_password or settings.wazuh_password or "").strip()
            body = {
                "size": min(max(limit, 1), 50),
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"decoder.name": "syscheck_integrity_changed"}},
                            {"term": {"decoder.name": "syscheck_new_entry"}},
                            {"term": {"decoder.name": "syscheck_deleted"}},
                            {"wildcard": {"rule.groups": "*syscheck*"}},
                            {"wildcard": {"rule.groups": "*fim*"}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            }
            auth = (user, password) if user and password else None
            async with httpx.AsyncClient(timeout=30.0, verify=_verify()) as client:
                resp = await client.post(
                    f"{url}/wazuh-alerts*/_search",
                    json=body,
                    auth=auth,
                    headers={"Content-Type": "application/json"},
                )
            if resp.status_code >= 400:
                return []
            hits = (((resp.json() or {}).get("hits") or {}).get("hits")) or []
            out: list[dict[str, Any]] = []
            for h in hits:
                src = h.get("_source") or {}
                syscheck = src.get("syscheck") or {}
                rule = src.get("rule") or {}
                agent = src.get("agent") or {}
                out.append(
                    {
                        "path": syscheck.get("path") or src.get("file") or "",
                        "event": syscheck.get("event") or rule.get("description") or "FIM",
                        "agent": agent.get("name") or "",
                        "severity": _severity_from_level(rule.get("level")),
                        "timestamp": src.get("timestamp") or "",
                    }
                )
            return out
        except Exception:
            return []
    return []


async def ping() -> dict[str, Any]:
    """Lightweight connectivity check for status UI."""
    if not is_configured():
        return {"ok": False, "error": "not_configured"}
    try:
        overview = await fetch_manager_overview()
        if not overview.get("ok"):
            return {"ok": False, "error": overview.get("error") or "unreachable"}
        return {
            "ok": True,
            "title": overview.get("title") or "Wazuh API",
            "api_version": overview.get("api_version") or "",
            "indexer": indexer_configured(),
            "agents": overview.get("agents") or {},
            "manager": overview.get("manager") or {},
        }
    except Exception as exc:
        _token_cache["token"] = ""
        _token_cache["expires"] = 0.0
        return {"ok": False, "error": str(exc)[:300]}
