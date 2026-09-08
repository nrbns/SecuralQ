"""SecuraIQ Web Scanner — ZAP REST API client (daemon mode).

Follows https://www.zaproxy.org/docs/api/ — JSON endpoints:
  http://127.0.0.1:8090/JSON/{component}/{view|action}/{name}/?apikey=…&…

SecuraIQ defaults the daemon to port 8090 so it does not collide with the app on 8080.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx

from app.scanners.zap import _sev_from_zap_risk


def _risk_name_to_code(risk: str | None) -> str:
    r = (risk or "").strip().lower()
    if r == "high":
        return "3"
    if r == "medium":
        return "2"
    if r == "low":
        return "1"
    return "0"


def api_alerts_to_report_json(base_url: str, alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """Convert ZAP API alert rows into baseline-style JSON for ``parse_zap_json``."""
    rows: list[dict[str, Any]] = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        rows.append(
            {
                "name": alert.get("name") or alert.get("alert") or "Web finding",
                "riskcode": alert.get("riskcode") or _risk_name_to_code(str(alert.get("risk") or "")),
                "riskdesc": alert.get("riskdesc") or alert.get("risk") or "",
                "pluginid": str(alert.get("pluginId") or alert.get("pluginid") or ""),
                "engine": "zap_api",
                "instances": alert.get("instances") or (
                    [{"uri": alert.get("url") or alert.get("uri") or base_url}]
                    if (alert.get("url") or alert.get("uri"))
                    else [{}]
                ),
            }
        )
    return {"@version": "ZAP-API", "site": [{"@name": base_url, "alerts": rows}]}


def parse_zap_api_alerts(alerts: list[dict[str, Any]], *, asset: str) -> list[dict[str, Any]]:
    """Normalize ZAP REST ``alert.view.alerts`` rows to scan-engine intermediate dicts."""
    out: list[dict[str, Any]] = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        name = alert.get("name") or alert.get("alert") or "Web finding"
        plugin = alert.get("pluginId") or alert.get("pluginid") or ""
        risk = alert.get("risk") or alert.get("riskdesc") or ""
        riskcode = alert.get("riskcode") or _risk_name_to_code(str(risk))
        host = str(alert.get("url") or alert.get("uri") or asset)[:200]
        out.append(
            {
                "title": str(name)[:300],
                "severity": _sev_from_zap_risk(riskcode, str(risk)),
                "asset_name": host,
                "plugin": str(plugin),
                "evidence": host,
                "engine": "zap_api",
                "raw": {
                    k: v
                    for k, v in alert.items()
                    if k != "instances"
                }
                | {"instances_count": len(alert.get("instances") or []), "engine": "zap_api"},
            }
        )
    return out[:150]


class ZapApiClient:
    def __init__(self, base_url: str, api_key: str = "", timeout: float = 30.0) -> None:
        self.base_url = (base_url or "").rstrip("/") + "/"
        self.api_key = (api_key or "").strip()
        self.timeout = timeout

    def _endpoint(self, component: str, operation: str, name: str) -> str:
        return urljoin(self.base_url, f"JSON/{component}/{operation}/{name}/")

    async def call(
        self,
        component: str,
        operation: str,
        name: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        q: dict[str, Any] = dict(params or {})
        if self.api_key:
            q["apikey"] = self.api_key
        url = self._endpoint(component, operation, name)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(url, params=q)
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict):
                return {"result": data}
            return data

    async def probe(self) -> tuple[bool, str]:
        try:
            data = await self.call("core", "view", "version")
            version = data.get("version") or data.get("Version") or "unknown"
            return True, str(version)
        except Exception as exc:
            return False, str(exc)

    async def access_url(self, url: str) -> None:
        await self.call("core", "action", "accessUrl", params={"url": url, "followRedirects": "true"})

    async def spider_scan(self, url: str) -> str:
        data = await self.call(
            "spider",
            "action",
            "scan",
            params={"url": url, "recurse": "true", "contextName": "", "subtreeOnly": "false"},
        )
        return str(data.get("scan") or data.get("scanId") or "0")

    async def spider_status(self, scan_id: str) -> int:
        data = await self.call("spider", "view", "status", params={"scanId": scan_id})
        try:
            return int(data.get("status") or 0)
        except (TypeError, ValueError):
            return 0

    async def ascan_scan(self, url: str) -> str:
        data = await self.call(
            "ascan",
            "action",
            "scan",
            params={
                "url": url,
                "recurse": "true",
                "inScopeOnly": "false",
                "scanPolicyName": "",
                "method": "",
                "postData": "",
                "contextId": "",
            },
        )
        return str(data.get("scan") or data.get("scanId") or "0")

    async def ascan_status(self, scan_id: str) -> int:
        data = await self.call("ascan", "view", "status", params={"scanId": scan_id})
        try:
            return int(data.get("status") or 0)
        except (TypeError, ValueError):
            return 0

    async def pscan_records_to_scan(self) -> int:
        data = await self.call("pscan", "view", "recordsToScan")
        try:
            return int(data.get("recordsToScan") or 0)
        except (TypeError, ValueError):
            return 0

    async def fetch_alerts(self, baseurl: str, *, page_size: int = 500) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        start = 0
        while True:
            data = await self.call(
                "alert",
                "view",
                "alerts",
                params={"baseurl": baseurl, "start": str(start), "count": str(page_size)},
            )
            batch = data.get("alerts") or []
            if not isinstance(batch, list) or not batch:
                break
            alerts.extend([a for a in batch if isinstance(a, dict)])
            if len(batch) < page_size:
                break
            start += page_size
            if start > 5000:
                break
        return alerts


async def run_zap_api_assessment(
    *,
    target_url: str,
    profile: str,
    evidence_dir: Path,
    base_url: str,
    api_key: str = "",
    timeout_sec: float = 180.0,
    scan_id: str | None = None,
) -> dict[str, Any]:
    """Run spider (+ optional active scan) via ZAP REST API; write evidence JSON."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    trace: list[dict[str, Any]] = []
    client = ZapApiClient(base_url, api_key=api_key)
    prof = (profile or "web").lower()
    run_active = prof in {"vulnerability", "full"}

    async def _emit(step: str, *, pct: int | None = None) -> None:
        if not scan_id:
            return
        try:
            from app.realtime_bus import publish

            payload: dict[str, Any] = {
                "type": "scan",
                "id": scan_id,
                "step": step,
                "status": "active",
                "scanner": "zap_api",
            }
            if pct is not None:
                payload["pct"] = pct
            publish(**payload)
        except Exception:
            pass

    async def _log(step: str, detail: Any = None) -> None:
        trace.append({"step": step, "detail": detail})

    deadline = asyncio.get_running_loop().time() + max(60.0, timeout_sec)

    await _log("accessUrl", target_url)
    await _emit("zap_access")
    await client.access_url(target_url)

    spider_id = await client.spider_scan(target_url)
    await _log("spider.start", spider_id)
    await _emit("zap_spider", pct=0)
    while asyncio.get_running_loop().time() < deadline:
        pct = await client.spider_status(spider_id)
        await _emit("zap_spider", pct=int(pct) if pct is not None else None)
        if pct >= 100:
            break
        await asyncio.sleep(1.5)
    await _log("spider.done", await client.spider_status(spider_id))
    await _emit("zap_passive", pct=0)

    while asyncio.get_running_loop().time() < deadline:
        left = await client.pscan_records_to_scan()
        await _log("pscan.records", left)
        if left <= 0:
            break
        await asyncio.sleep(2.0)

    if run_active and asyncio.get_running_loop().time() < deadline:
        ascan_id = await client.ascan_scan(target_url)
        await _log("ascan.start", ascan_id)
        await _emit("zap_ascan", pct=0)
        while asyncio.get_running_loop().time() < deadline:
            pct = await client.ascan_status(ascan_id)
            await _emit("zap_ascan", pct=int(pct) if pct is not None else None)
            if pct >= 100:
                break
            await asyncio.sleep(2.0)
        await _log("ascan.done", await client.ascan_status(ascan_id))
        while asyncio.get_running_loop().time() < deadline:
            left = await client.pscan_records_to_scan()
            if left <= 0:
                break
            await asyncio.sleep(2.0)

    alerts = await client.fetch_alerts(target_url)
    await _log("alerts.count", len(alerts))

    report = api_alerts_to_report_json(target_url, alerts)
    api_dump = {
        "target": target_url,
        "profile": prof,
        "zap_api_base": base_url,
        "spider_scan_id": spider_id,
        "active_scan": run_active,
        "alerts": alerts,
        "trace": trace,
    }
    (evidence_dir / "zap_api_trace.json").write_text(json.dumps(api_dump, indent=2), encoding="utf-8")
    # Write ZAP-only report beside builtin evidence — ZapScanner.execute merges
    # into zap.json. Do not wipe SecuraIQ Web Scanner findings here.
    (evidence_dir / "zap_api_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (evidence_dir / "zap_api.json").write_text(json.dumps({"alerts": alerts}, indent=2), encoding="utf-8")
    return {
        "ok": True,
        "mode": "zap_api",
        "alerts": len(alerts),
        "artifacts": [
            str(evidence_dir / "zap_api_report.json"),
            str(evidence_dir / "zap_api.json"),
            str(evidence_dir / "zap_api_trace.json"),
        ],
    }


def resolve_zap_api_settings() -> tuple[str, str]:
    from app.config import settings

    base = (getattr(settings, "zap_api_url", None) or "").strip()
    if not base:
        base = "http://127.0.0.1:8090"
    key = (getattr(settings, "zap_api_key", None) or "").strip()
    return base.rstrip("/") + "/", key


async def probe_zap_api() -> tuple[bool, str]:
    base, key = resolve_zap_api_settings()
    client = ZapApiClient(base, api_key=key, timeout=5.0)
    ok, detail = await client.probe()
    if ok:
        return True, f"ZAP API {base} (v{detail})"
    return False, detail
