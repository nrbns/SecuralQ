"""SecuraIQ native agent — packages from last check-in telemetry."""

from __future__ import annotations

import json
from typing import Any

from app.db import now
from app.software.models import InstallationRecord, PATCH_UNKNOWN
from app.software.sources.base import InventorySource, register_source


def packages_from_agent_row(row: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse package list from an agent row's last_payload_json."""
    try:
        payload = json.loads(row.get("last_payload_json") or "{}")
    except Exception:
        return []
    if not isinstance(payload, dict) or payload.get("truncated"):
        return []
    pkgs = payload.get("packages") or []
    return [p for p in pkgs if isinstance(p, dict)][:500]


def records_from_agent(
    *,
    user_id: str,
    agent: dict[str, Any],
    packages: list[dict[str, Any]] | None = None,
) -> list[InstallationRecord]:
    """Build InstallationRecord rows for one agent's package telemetry."""
    aid = str(agent.get("id") or "")
    asset_id = str(agent.get("asset_id") or "")
    hostname = str(agent.get("hostname") or agent.get("name") or aid[:8] or "agent")
    ts = float(agent.get("last_checkin") or 0) or now()
    pkgs = packages if packages is not None else packages_from_agent_row(agent)
    out: list[InstallationRecord] = []
    os_name = str(agent.get("os") or "").strip()
    os_ver = str(agent.get("os_version") or "").strip()
    if os_name:
        out.append(
            InstallationRecord(
                asset_id=asset_id,
                asset_name=hostname,
                product=os_name[:200],
                version=os_ver[:80],
                vendor="securaiq-agent",
                source="securaiq_agent",
                source_id=f"agent-os:{aid}",
                last_seen=ts,
                raw_status="installed",
                detail=f"SecuraIQ agent OS · {aid[:8]}",
                patch_status=PATCH_UNKNOWN,
            )
        )
    for pkg in pkgs:
        product = str(pkg.get("name") or pkg.get("package") or "").strip()
        if not product:
            continue
        out.append(
            InstallationRecord(
                asset_id=asset_id,
                asset_name=hostname,
                product=product[:200],
                version=str(pkg.get("version") or "")[:80],
                vendor=str(pkg.get("vendor") or pkg.get("publisher") or "")[:120],
                publisher=str(pkg.get("publisher") or pkg.get("vendor") or "")[:120],
                architecture=str(pkg.get("architecture") or pkg.get("arch") or "")[:32],
                source="securaiq_agent",
                source_id=f"agent-pkg:{aid}:{product.lower()[:60]}",
                last_seen=ts,
                raw_status="installed",
                detail=f"SecuraIQ agent check-in · {aid[:8]}",
                patch_status=PATCH_UNKNOWN,
            )
        )
    return out


@register_source
class SecuraIQAgentSource(InventorySource):
    key = "securaiq_agent"
    label = "SecuraIQ Agent"

    def health(self, user_id: str) -> dict[str, Any]:
        try:
            from app.agents import ensure_schema, list_agents

            ensure_schema()
            agents = list_agents(user_id, limit=500)
            online = sum(1 for a in agents if (a.get("status") or "") == "online")
            with_pkgs = 0
            for a in agents:
                if packages_from_agent_row(a):
                    with_pkgs += 1
            return {
                "key": self.key,
                "label": self.label,
                "configured": bool(agents),
                "healthy": online > 0 or with_pkgs > 0,
                "agents": len(agents),
                "online": online,
                "with_packages": with_pkgs,
            }
        except Exception as exc:
            return {
                "key": self.key,
                "label": self.label,
                "configured": False,
                "healthy": False,
                "error": str(exc)[:200],
            }

    def collect(self, user_id: str) -> list[InstallationRecord]:
        from app.agents import ensure_schema, list_agents

        ensure_schema()
        rows: list[InstallationRecord] = []
        for agent in list_agents(user_id, limit=500):
            rows.extend(records_from_agent(user_id=user_id, agent=agent))
        return rows


def _pkg_key(pkg: dict[str, Any]) -> str:
    return str(pkg.get("name") or pkg.get("package") or "").strip().lower()


def _pkg_version(pkg: dict[str, Any]) -> str:
    return str(pkg.get("version") or "").strip()


def diff_package_sets(
    previous: list[dict[str, Any]] | None,
    current: list[dict[str, Any]] | None,
) -> dict[str, list[dict[str, Any]]]:
    """Compare previous vs current package lists → installed/removed/updated."""
    prev_map: dict[str, dict[str, Any]] = {}
    for p in previous or []:
        if not isinstance(p, dict):
            continue
        k = _pkg_key(p)
        if k:
            prev_map[k] = p
    cur_map: dict[str, dict[str, Any]] = {}
    for p in current or []:
        if not isinstance(p, dict):
            continue
        k = _pkg_key(p)
        if k:
            cur_map[k] = p
    installed = [cur_map[k] for k in cur_map.keys() - prev_map.keys()]
    removed = [prev_map[k] for k in prev_map.keys() - cur_map.keys()]
    updated: list[dict[str, Any]] = []
    for k in cur_map.keys() & prev_map.keys():
        if _pkg_version(cur_map[k]) != _pkg_version(prev_map[k]):
            updated.append({**cur_map[k], "previous_version": _pkg_version(prev_map[k])})
    return {"installed": installed, "removed": removed, "updated": updated}


def publish_package_change_events(
    user_id: str,
    agent: dict[str, Any],
    diffs: dict[str, list[dict[str, Any]]],
) -> dict[str, int]:
    """Publish software.* events + observed evidence for package diffs."""
    counts = {"installed": 0, "removed": 0, "updated": 0, "evidence": 0}
    aid = str(agent.get("id") or "")
    asset_id = str(agent.get("asset_id") or "")
    hostname = str(agent.get("hostname") or agent.get("name") or aid[:8] or "agent")
    org_id = agent.get("org_id")
    try:
        from app.realtime_bus import publish
        from app.services.evidence import record_evidence
    except Exception:
        return counts

    def _emit(kind: str, pkg: dict[str, Any]) -> None:
        name = str(pkg.get("name") or pkg.get("package") or "").strip()
        if not name:
            return
        ver = _pkg_version(pkg)
        event_type = f"software.{kind}"
        try:
            publish(
                type=event_type,
                event_type=event_type,
                user_id=user_id,
                org_id=org_id,
                agent_id=aid,
                asset_id=asset_id,
                product=name,
                version=ver,
                previous_version=pkg.get("previous_version") or "",
                hostname=hostname,
                source="securaiq_agent",
            )
            counts[kind] = counts.get(kind, 0) + 1
        except Exception:
            pass
        try:
            summary = f"{kind}: {name}" + (f"@{ver}" if ver else "")
            if kind == "updated" and pkg.get("previous_version"):
                summary = f"updated: {name} {pkg.get('previous_version')}→{ver}"
            ev = record_evidence(
                user_id,
                entity_type="software_package",
                entity_id=f"{aid}:{name.lower()[:80]}",
                source="observed",
                summary=summary[:500],
                confidence=0.9,
                detail={
                    "change": kind,
                    "product": name,
                    "version": ver,
                    "previous_version": pkg.get("previous_version") or "",
                    "agent_id": aid,
                    "asset_id": asset_id,
                    "hostname": hostname,
                },
                created_by="securaiq_agent",
                org_id=str(org_id) if org_id else None,
            )
            if ev:
                counts["evidence"] += 1
        except Exception:
            pass

    for pkg in (diffs.get("installed") or [])[:100]:
        _emit("installed", pkg)
    for pkg in (diffs.get("removed") or [])[:100]:
        _emit("removed", pkg)
    for pkg in (diffs.get("updated") or [])[:100]:
        _emit("updated", pkg)
    return counts


def ingest_agent_packages(
    user_id: str,
    agent: dict[str, Any],
    packages: list[dict[str, Any]] | None = None,
    *,
    sync: bool = True,
    previous_packages: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Write agent packages into legacy asset_software + optionally sync engine.

    Called from check-in so inventory is current before the next patch-verify
    job runs — without waiting for a full rebuild.

    When ``previous_packages`` is provided, publish software.installed|removed|updated
    and record observed Evidence Store rows (TTL via EVIDENCE_OBSERVED_TTL_SEC).
    """
    from app.software_inventory import upsert_software_row

    aid = str(agent.get("id") or "")
    asset_id = str(agent.get("asset_id") or "")
    hostname = str(agent.get("hostname") or agent.get("name") or aid[:8] or "agent")
    pkgs = packages if packages is not None else packages_from_agent_row(agent)
    n = 0
    for pkg in pkgs:
        product = str(pkg.get("name") or pkg.get("package") or "").strip()
        if not product:
            continue
        upsert_software_row(
            user_id,
            asset_id=asset_id,
            asset_name=hostname,
            product=product,
            version=str(pkg.get("version") or ""),
            vendor=str(pkg.get("vendor") or pkg.get("publisher") or ""),
            source="securaiq_agent",
            status="installed",
            detail=f"SecuraIQ agent check-in · {aid[:8]}",
        )
        n += 1
    changes: dict[str, Any] = {}
    if previous_packages is not None:
        try:
            diffs = diff_package_sets(previous_packages, pkgs)
            changes = publish_package_change_events(user_id, agent, diffs)
            changes["diff"] = {
                "installed": len(diffs.get("installed") or []),
                "removed": len(diffs.get("removed") or []),
                "updated": len(diffs.get("updated") or []),
            }
        except Exception as exc:
            changes = {"error": str(exc)[:200]}
    engine: dict[str, Any] = {}
    advisory: dict[str, Any] = {}
    if sync and (n or asset_id):
        try:
            from app.software.service import upsert_records

            recs = records_from_agent(user_id=user_id, agent=agent, packages=pkgs)
            engine = upsert_records(user_id, recs, publish=True)
        except Exception as exc:
            engine = {"error": str(exc)[:200]}
        # Phase 4: package → CVE match → enterprise vuln (debounced per asset).
        if asset_id:
            try:
                from app.software.advisories import (
                    mark_asset_refreshed,
                    refresh_advisories_for_asset,
                    should_refresh_asset,
                )

                if should_refresh_asset(asset_id):
                    payload = {}
                    try:
                        payload = json.loads(agent.get("last_payload_json") or "{}")
                    except Exception:
                        payload = {}
                    if not isinstance(payload, dict):
                        payload = {}
                    ports_raw = payload.get("listening_ports") or []
                    ports: list[int] = []
                    for p in ports_raw:
                        try:
                            ports.append(int(p))
                        except (TypeError, ValueError):
                            continue
                    os_hint = f"{agent.get('os') or ''} {agent.get('os_version') or ''}".strip()
                    advisory = refresh_advisories_for_asset(
                        user_id,
                        asset_id,
                        limit=min(40, max(n, 8)),
                        os_hint=os_hint,
                        asset_name=hostname,
                        listening_ports=ports[:40],
                        agent_ip=str(agent.get("ip") or payload.get("ip") or ""),
                        bridge_vulns=True,
                    )
                    mark_asset_refreshed(asset_id)
                else:
                    advisory = {"skipped": "debounced"}
            except Exception as exc:
                advisory = {"error": str(exc)[:200]}
    return {
        "ingested": n,
        "asset_id": asset_id,
        "engine": engine,
        "advisory": advisory,
        "changes": changes,
    }


def apply_patch_version_to_inventory(
    user_id: str,
    *,
    asset_id: str,
    package: str,
    version: str,
    agent_id: str = "",
    hostname: str = "",
) -> bool:
    """Immediately stamp the post-patch version so verification sees it."""
    pkg = (package or "").strip()
    ver = (version or "").strip()
    if not pkg or not asset_id:
        return False
    from app.software_inventory import upsert_software_row

    upsert_software_row(
        user_id,
        asset_id=asset_id,
        asset_name=hostname or asset_id[:8],
        product=pkg,
        version=ver,
        source="securaiq_agent",
        status="installed",
        detail=f"Post-patch version from agent command · {(agent_id or '')[:8]}",
    )
    try:
        from app.software.service import upsert_records
        from app.software.models import InstallationRecord, PATCH_UNKNOWN

        rec = InstallationRecord(
            asset_id=asset_id,
            asset_name=hostname or asset_id[:8],
            product=pkg[:200],
            version=ver[:80],
            source="securaiq_agent",
            source_id=f"agent-pkg:{(agent_id or 'patch')}:{pkg.lower()[:60]}",
            last_seen=None,
            raw_status="installed",
            detail=f"Post-patch version from agent command · {(agent_id or '')[:8]}",
            patch_status=PATCH_UNKNOWN,
        )
        upsert_records(user_id, [rec], publish=True)
    except Exception:
        pass
    return True
