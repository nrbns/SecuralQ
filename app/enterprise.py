"""Structured enterprise workflows: risks, assets, vulnerabilities, remediations."""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from app.db import audit, get_conn, new_id, now, row_to_dict

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Canonical finding lifecycle. Dashboard also treats aliases as closed/open buckets.
VULN_STATUSES = frozenset(
    {
        "open",
        "triaged",
        "in_progress",
        "accepted",
        "false_positive",
        "remediated",
        "verified",
        "resolved",
        "closed",
        "fixed",
    }
)


def _score(impact: int, likelihood: int) -> int:
    return max(1, min(25, int(impact) * int(likelihood)))


# --- Assets -----------------------------------------------------------------


def create_asset(
    user_id: str,
    name: str,
    *,
    asset_type: str = "server",
    criticality: str = "medium",
    owner: str = "",
    notes: str = "",
    engagement_id: str | None = None,
    org_id: str | None = None,
    business_criticality: str = "",
    service_accounts: str = "",
) -> dict[str, Any]:
    from app.tenancy import ensure_tenant_schema, primary_org_id

    ensure_tenant_schema()
    oid = org_id or primary_org_id(user_id)
    aid = new_id()
    ts = now()
    c = get_conn()
    c.execute(
        """
        INSERT INTO assets
        (id, user_id, engagement_id, org_id, name, asset_type, criticality, owner, notes, business_criticality, service_accounts, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (aid, user_id, engagement_id, oid, name.strip(), asset_type, criticality, owner, notes, business_criticality, service_accounts, ts, ts),
    )
    c.commit()
    audit("asset_create", user_id, {"id": aid, "name": name, "org_id": oid})
    try:
        from app.realtime_bus import publish

        publish(type="asset", id=aid, user_id=user_id, org_id=oid)
    except Exception:
        pass
    return get_asset(user_id, aid)  # type: ignore[return-value]


def ensure_asset_for_target(
    user_id: str,
    name: str,
    *,
    notes: str = "",
    asset_type: str = "server",
    criticality: str = "medium",
    engagement_id: str | None = None,
    org_id: str | None = None,
    resolve_ptr: bool = False,
) -> dict[str, Any] | None:
    """Upsert an inventory asset from a live scan target (IP/hostname/path).

    Correlates by exact name, then by IP/hostname stored in notes JSON so
    hostname-first and IP-first scans merge onto one asset.
    """
    from app.asset_names import (
        canonical_asset_name,
        is_better_asset_name,
        is_ipv4,
        parse_notes_meta,
        resolve_ptr_if_ip,
    )
    from app.asset_categories import infer_asset_category, is_better_category, ports_from_meta

    name = (name or "").strip()[:200]
    if not name or name.lower() in {"unknown", "none", "null", "device"}:
        return None

    def _notes_dict(raw: str) -> dict[str, Any]:
        return parse_notes_meta(raw)

    def _merge_notes(existing: str, incoming: str) -> str:
        if not incoming:
            return (existing or "")[:2000]
        old = _notes_dict(existing)
        new = _notes_dict(incoming)
        if old or new:
            return json.dumps({**old, **new})[:2000]
        return (incoming or existing or "")[:2000]

    incoming = _notes_dict(notes)
    incoming_ip = str(incoming.get("ip") or "").strip().lower()
    incoming_host = str(incoming.get("host") or incoming.get("hostname") or "").strip().lower()
    if resolve_ptr and not incoming_host:
        probe_ip = incoming_ip or (name if is_ipv4(name) else "")
        if probe_ip:
            ptr = resolve_ptr_if_ip(probe_ip)
            if ptr:
                incoming["hostname"] = ptr
                incoming["host"] = ptr
                incoming_host = ptr.lower()
                notes = json.dumps(incoming)[:2000]
    name = canonical_asset_name(
        name=name,
        ip=str(incoming.get("ip") or ""),
        hostname=str(incoming.get("hostname") or incoming.get("host") or ""),
    )
    name_l = name.lower()
    if not incoming_ip and is_ipv4(name.split("(")[-1].rstrip(")") if "(" in name else name):
        ip_guess = name.split("(")[-1].rstrip(")") if "(" in name else name
        incoming_ip = ip_guess.strip().lower()

    def _asset_keys(a: dict[str, Any]) -> set[str]:
        keys: set[str] = set()
        an = (a.get("name") or "").strip().lower()
        if an:
            keys.add(an)
        nd = _notes_dict(a.get("notes") or "")
        for k in ("ip", "host", "hostname"):
            v = str(nd.get(k) or "").strip().lower()
            if v:
                keys.add(v)
        return keys

    for a in list_assets(user_id, engagement_id, org_id=org_id):
        keys = _asset_keys(a)
        matched = name_l in keys
        if not matched and incoming_ip and incoming_ip in keys:
            matched = True
        if not matched and incoming_host and incoming_host in keys:
            matched = True
        if not matched:
            continue
        aid = a.get("id")
        merged_meta = _notes_dict(_merge_notes(a.get("notes") or "", notes) if notes else (a.get("notes") or ""))
        inferred = infer_asset_category(
            asset_type=asset_type,
            os=str(merged_meta.get("os") or ""),
            hostname=str(merged_meta.get("hostname") or merged_meta.get("host") or ""),
            oa_type=str(merged_meta.get("oa_type") or ""),
            ports=ports_from_meta(merged_meta),
            name=name,
        )
        if aid and notes:
            merged = _merge_notes(a.get("notes") or "", notes)
            patch: dict[str, Any] = {}
            if merged != (a.get("notes") or ""):
                patch["notes"] = merged
            merged_meta = _notes_dict(merged)
            new_name = canonical_asset_name(
                name=name,
                ip=str(merged_meta.get("ip") or ""),
                hostname=str(merged_meta.get("hostname") or merged_meta.get("host") or ""),
            )
            cur_name = (a.get("name") or "").strip()
            if new_name and is_better_asset_name(new_name, cur_name):
                patch["name"] = new_name[:200]
            cur_type = str(a.get("asset_type") or "")
            if is_better_category(inferred, cur_type):
                patch["asset_type"] = inferred
            if patch:
                return update_asset(user_id, str(aid), patch) or a
        elif aid and is_better_category(inferred, str(a.get("asset_type") or "")):
            updated = update_asset(user_id, str(aid), {"asset_type": inferred})
            if updated:
                return updated
        try:
            from app.realtime_bus import publish

            if aid:
                publish(type="asset", id=aid, user_id=user_id, org_id=org_id, action="scan_seen")
        except Exception:
            pass
        return a
    # Heuristic type from target shape + scan metadata
    merged_meta = _notes_dict(notes)
    at = infer_asset_category(
        asset_type=asset_type,
        os=str(merged_meta.get("os") or ""),
        hostname=str(merged_meta.get("hostname") or merged_meta.get("host") or ""),
        oa_type=str(merged_meta.get("oa_type") or ""),
        ports=ports_from_meta(merged_meta),
        name=name,
    )
    return create_asset(
        user_id,
        name,
        asset_type=at,
        criticality=criticality,
        owner="SecOps",
        notes=(notes or "Discovered via live SecuraIQ scan")[:2000],
        engagement_id=engagement_id,
        org_id=org_id,
    )


def get_asset(user_id: str, asset_id: str) -> dict[str, Any] | None:
    from app.tenancy import row_visible_to_user, tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id)
    row = get_conn().execute(
        f"SELECT * FROM assets WHERE id = ? AND {where}",
        (asset_id, *args),
    ).fetchone()
    data = row_to_dict(row)
    return data if row_visible_to_user(user_id, data) else None


def list_assets(
    user_id: str,
    engagement_id: str | None = None,
    *,
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    from app.tenancy import ensure_tenant_schema, tenant_visibility_sql

    ensure_tenant_schema()
    c = get_conn()
    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM assets WHERE {where}"
    if engagement_id:
        q += " AND engagement_id = ?"
        args.append(engagement_id)
    q += " ORDER BY updated_at DESC LIMIT 500"
    return [row_to_dict(r) for r in c.execute(q, args).fetchall()]  # type: ignore[misc]


_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def enrich_assets_with_scans(
    user_id: str, assets: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Attach live scan facts (IP, ports, last scan) so inventory is not a name-only list."""
    from app.scan_engine.models import list_scans

    try:
        scans = list_scans(user_id, limit=80)
    except Exception:
        scans = []
    by_target: dict[str, dict[str, Any]] = {}
    live: list[dict[str, Any]] = []
    for s in scans:
        tgt = (s.get("target") or "").strip()
        st = (s.get("status") or "").lower()
        if tgt and tgt not in by_target:
            by_target[tgt] = s
        if st in {"queued", "scope_check", "running", "collecting", "parsing", "normalizing"}:
            live.append(
                {
                    "id": s.get("id"),
                    "target": tgt,
                    "status": st,
                    "scanner": s.get("scanner"),
                    "created_at": s.get("created_at"),
                }
            )
    out: list[dict[str, Any]] = []
    for a in assets:
        from app.asset_names import display_asset_label, enrich_asset_row, parse_notes_meta
        from app.asset_categories import enrich_asset_category

        row = enrich_asset_category(enrich_asset_row(a))
        meta = parse_notes_meta((a.get("notes") or ""))
        name = (a.get("name") or "").strip()
        ip = str(row.get("ip") or meta.get("ip") or meta.get("host") or "")
        hostname = str(row.get("hostname") or meta.get("hostname") or meta.get("host") or "")
        if not ip and _IPV4.match(name):
            ip = name
        services = meta.get("services") if isinstance(meta.get("services"), list) else []
        ports: list[str] = []
        for svc in services:
            if not isinstance(svc, dict):
                continue
            port = svc.get("port")
            if port is None:
                continue
            proto = svc.get("protocol") or "tcp"
            sname = (svc.get("service") or "").strip()
            ports.append(f"{port}/{proto}" + (f" {sname}" if sname else ""))
        scan = by_target.get(name) or by_target.get(ip) or (
            by_target.get(hostname) if hostname else None
        )
        row["ip"] = ip
        row["hostname"] = hostname
        row["display_name"] = display_asset_label(
            name=name,
            ip=ip,
            hostname=hostname,
            os=str(meta.get("os") or ""),
        )
        row["mac"] = str(meta.get("mac") or "")
        row["open_ports"] = ports
        row["source"] = str(meta.get("source") or meta.get("scanner") or "")
        if scan:
            summary = scan.get("summary") if isinstance(scan.get("summary"), dict) else {}
            row["last_scan_id"] = scan.get("id")
            row["last_scan_status"] = scan.get("status")
            row["last_scan_at"] = scan.get("completed_at") or scan.get("created_at")
            row["findings"] = summary.get("findings_created")
        out.append(row)
    return out, live


def enrich_vulnerabilities_display(
    user_id: str, vulns: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Attach display_asset_name for UI tables."""
    from app.asset_names import canonical_vuln_asset_name, display_name_for_asset

    assets = {str(a.get("id")): a for a in list_assets(user_id) if a.get("id")}
    out: list[dict[str, Any]] = []
    for v in vulns:
        row = dict(v)
        aid = str(v.get("asset_id") or "")
        asset = assets.get(aid) if aid else None
        if asset:
            row["display_asset_name"] = display_name_for_asset(asset).split(" · ")[0]
        else:
            row["display_asset_name"] = canonical_vuln_asset_name(str(v.get("asset_name") or ""))
        out.append(row)
    return out


def update_asset(user_id: str, asset_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
    row = get_asset(user_id, asset_id)
    if not row:
        return None
    allowed = {"name", "asset_type", "criticality", "owner", "notes", "engagement_id", "business_criticality", "service_accounts"}
    data = {k: v for k, v in patch.items() if k in allowed and v is not None}
    if not data:
        return row
    data["updated_at"] = now()
    sets = ", ".join(f"{k} = ?" for k in data)
    get_conn().execute(
        f"UPDATE assets SET {sets} WHERE id = ?",
        (*data.values(), asset_id),
    )
    get_conn().commit()
    audit("asset_update", user_id, {"id": asset_id, **data})
    try:
        from app.realtime_bus import publish

        publish(type="asset", id=asset_id, user_id=user_id, action="update")
    except Exception:
        pass
    return get_asset(user_id, asset_id)


def delete_asset(user_id: str, asset_id: str) -> bool:
    if not get_asset(user_id, asset_id):
        return False
    cur = get_conn().execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    get_conn().commit()
    if cur.rowcount:
        audit("asset_delete", user_id, {"id": asset_id})
        return True
    return False


# --- Asset dependencies (attack-path connects_to edges) ---------------------
#
# There is no automatic source of truth for "this asset talks to that
# asset" anywhere in this product (no network flow capture, no app
# architecture input) — every row here is either a user's own declaration
# (source='declared', confidence=1.0) or a same-tenant heuristic guess
# (source='inferred', confidence<1.0, see app.services.attack_graph). Never
# silently upgrade an inferred edge's confidence — that would misrepresent
# a guess as a fact.


def create_asset_dependency(
    user_id: str,
    source_asset_id: str,
    target_asset_id: str,
    *,
    relationship: str = "connects_to",
    notes: str = "",
    engagement_id: str | None = None,
    org_id: str | None = None,
    source: str = "declared",
    confidence: float = 1.0,
) -> dict[str, Any]:
    did = new_id()
    ts = now()
    c = get_conn()
    c.execute(
        """
        INSERT INTO asset_dependencies
        (id, user_id, engagement_id, org_id, source_asset_id, target_asset_id, relationship, source, confidence, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (did, user_id, engagement_id, org_id, source_asset_id, target_asset_id, relationship, source, confidence, notes, ts, ts),
    )
    c.commit()
    audit(
        "asset_dependency_create",
        user_id,
        {"id": did, "source_asset_id": source_asset_id, "target_asset_id": target_asset_id, "relationship": relationship, "source": source},
    )
    try:
        from app.services.evidence import record_evidence

        record_evidence(
            user_id,
            entity_type="asset_dependency",
            entity_id=did,
            source=source if source in ("declared", "inferred") else "derived",
            summary=f"{relationship} declared from {source_asset_id} to {target_asset_id}"
            if source == "declared"
            else f"{relationship} suggested from {source_asset_id} to {target_asset_id}",
            confidence=confidence,
            detail={"source_asset_id": source_asset_id, "target_asset_id": target_asset_id, "relationship": relationship, "notes": notes},
            created_by=user_id if source == "declared" else "system",
            org_id=org_id,
        )
    except Exception:
        pass  # evidence recording is best-effort — never block the real write
    return {
        "id": did,
        "user_id": user_id,
        "engagement_id": engagement_id,
        "org_id": org_id,
        "source_asset_id": source_asset_id,
        "target_asset_id": target_asset_id,
        "relationship": relationship,
        "source": source,
        "confidence": confidence,
        "notes": notes,
        "created_at": ts,
        "updated_at": ts,
    }


def list_asset_dependencies(
    user_id: str,
    *,
    asset_id: str | None = None,
    engagement_id: str | None = None,
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    from app.tenancy import ensure_tenant_schema, tenant_visibility_sql

    ensure_tenant_schema()
    c = get_conn()
    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM asset_dependencies WHERE {where}"
    if asset_id:
        q += " AND (source_asset_id = ? OR target_asset_id = ?)"
        args.extend([asset_id, asset_id])
    if engagement_id:
        q += " AND engagement_id = ?"
        args.append(engagement_id)
    q += " ORDER BY created_at DESC LIMIT 2000"
    return [row_to_dict(r) for r in c.execute(q, args).fetchall()]  # type: ignore[misc]


def delete_asset_dependency(user_id: str, dependency_id: str) -> bool:
    c = get_conn()
    row = c.execute(
        "SELECT id FROM asset_dependencies WHERE id = ? AND user_id = ?", (dependency_id, user_id)
    ).fetchone()
    if not row:
        return False
    cur = c.execute("DELETE FROM asset_dependencies WHERE id = ?", (dependency_id,))
    c.commit()
    if cur.rowcount:
        audit("asset_dependency_delete", user_id, {"id": dependency_id})
        return True
    return False


# --- Risks ------------------------------------------------------------------


def create_risk(
    user_id: str,
    *,
    threat: str,
    vulnerability: str = "",
    asset_name: str = "",
    asset_id: str | None = None,
    impact: int = 3,
    likelihood: int = 3,
    owner: str = "",
    mitigation: str = "",
    status: str = "open",
    engagement_id: str | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    from app.tenancy import ensure_tenant_schema, primary_org_id

    ensure_tenant_schema()
    oid = org_id or primary_org_id(user_id)
    rid = new_id()
    ts = now()
    score = _score(impact, likelihood)
    c = get_conn()
    c.execute(
        """
        INSERT INTO risks
        (id, user_id, engagement_id, asset_id, asset_name, threat, vulnerability,
         impact, likelihood, risk_score, owner, mitigation, status, created_at, updated_at, org_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rid, user_id, engagement_id, asset_id, asset_name, threat.strip(), vulnerability,
            impact, likelihood, score, owner, mitigation, status, ts, ts, oid,
        ),
    )
    c.commit()
    audit("risk_create", user_id, {"id": rid, "score": score, "org_id": oid})
    try:
        from app.realtime_bus import publish

        publish(type="risk", id=rid, user_id=user_id, score=score)
    except Exception:
        pass
    return get_risk(user_id, rid)  # type: ignore[return-value]


def get_risk(user_id: str, risk_id: str) -> dict[str, Any] | None:
    row = get_conn().execute(
        "SELECT * FROM risks WHERE id = ? AND user_id = ?", (risk_id, user_id)
    ).fetchone()
    return row_to_dict(row)


def list_risks(
    user_id: str,
    *,
    engagement_id: str | None = None,
    status: str | None = None,
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    from app.tenancy import ensure_tenant_schema, tenant_visibility_sql

    ensure_tenant_schema()
    c = get_conn()
    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM risks WHERE {where}"
    if engagement_id:
        q += " AND engagement_id = ?"
        args.append(engagement_id)
    if status:
        q += " AND status = ?"
        args.append(status)
    q += " ORDER BY risk_score DESC, updated_at DESC LIMIT 500"
    return [row_to_dict(r) for r in c.execute(q, args).fetchall()]  # type: ignore[misc]


def update_risk(user_id: str, risk_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
    cur = get_risk(user_id, risk_id)
    if not cur:
        return None
    fields = {
        "threat", "vulnerability", "asset_name", "asset_id", "impact", "likelihood",
        "owner", "mitigation", "status", "engagement_id",
    }
    data = {k: patch[k] for k in fields if k in patch}
    if "impact" in data or "likelihood" in data:
        impact = int(data.get("impact", cur["impact"]))
        likelihood = int(data.get("likelihood", cur["likelihood"]))
        data["impact"] = impact
        data["likelihood"] = likelihood
        data["risk_score"] = _score(impact, likelihood)
    if not data:
        return cur
    data["updated_at"] = now()
    sets = ", ".join(f"{k} = ?" for k in data)
    get_conn().execute(
        f"UPDATE risks SET {sets} WHERE id = ? AND user_id = ?",
        (*data.values(), risk_id, user_id),
    )
    get_conn().commit()
    audit("risk_update", user_id, {"id": risk_id, **{k: data[k] for k in data if k != "updated_at"}})
    updated = get_risk(user_id, risk_id)
    try:
        from app.realtime_bus import publish

        publish(type="risk", id=risk_id, score=(updated or {}).get("risk_score"), user_id=user_id)
    except Exception:
        pass
    return updated


def delete_risk(user_id: str, risk_id: str) -> bool:
    c = get_conn()
    cur = c.execute("DELETE FROM risks WHERE id = ? AND user_id = ?", (risk_id, user_id))
    c.commit()
    return cur.rowcount > 0


# --- Vulnerabilities --------------------------------------------------------


def create_vulnerability(
    user_id: str,
    item: dict[str, Any],
    *,
    emit_realtime: bool = True,
) -> dict[str, Any]:
    from app.tenancy import ensure_tenant_schema, primary_org_id

    ensure_tenant_schema()
    vid = new_id()
    ts = now()
    oid = item.get("org_id") or primary_org_id(user_id)
    c = get_conn()
    c.execute(
        """
        INSERT INTO vulnerabilities
        (id, user_id, engagement_id, org_id, asset_id, asset_name, cve, title, severity, cvss,
         status, owner, sla_due, source, raw_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            vid,
            user_id,
            item.get("engagement_id"),
            oid,
            item.get("asset_id"),
            item.get("asset_name") or item.get("asset") or "",
            (item.get("cve") or "").upper(),
            item.get("title") or "Untitled finding",
            (item.get("severity") or "medium").lower(),
            item.get("cvss"),
            item.get("status") or "open",
            item.get("owner") or "",
            item.get("sla_due") or "",
            item.get("source") or "import",
            json.dumps(item.get("raw") or item),
            ts,
            ts,
        ),
    )
    c.commit()
    result = get_vulnerability(user_id, vid)

    if emit_realtime:
        try:
            from app.realtime_bus import publish

            publish(
                type="vuln",
                id=vid,
                severity=(item.get("severity") or "medium").lower(),
                user_id=user_id,
                org_id=oid,
            )
        except Exception:
            pass

    severity = (item.get("severity") or "medium").lower()
    if severity in ("critical", "high"):
        from app.notifications import notify

        title = item.get("title") or "Untitled finding"
        asset = item.get("asset_name") or item.get("asset") or "unknown"
        cve = (item.get("cve") or "n/a").upper()

        notify(
            user_id,
            "critical_vuln",
            f"New {severity} vulnerability: {title}",
            f"Asset: {asset} · CVE: {cve} · Source: {item.get('source') or 'import'}",
            link=f"/api/vulnerabilities/{vid}",
            email=(severity == "critical"),
        )

        if severity == "critical":
            import asyncio

            from app.connectors import slack, teams

            alert_text = f"🔴 *Critical vulnerability*: {title}\nAsset: {asset} · CVE: {cve}"
            if slack.is_configured():
                asyncio.create_task(slack.send_message(alert_text))
            if teams.is_configured():
                asyncio.create_task(teams.send_message("Critical vulnerability", alert_text))

    return result  # type: ignore[return-value]


def get_vulnerability(user_id: str, vuln_id: str) -> dict[str, Any] | None:
    from app.tenancy import row_visible_to_user, tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id)
    row = get_conn().execute(
        f"SELECT * FROM vulnerabilities WHERE id = ? AND {where}",
        (vuln_id, *args),
    ).fetchone()
    data = row_to_dict(row)
    if not data or not row_visible_to_user(user_id, data):
        return None
    raw_s = data.get("raw_json")
    if isinstance(raw_s, str) and raw_s.strip().startswith("{"):
        try:
            data["raw"] = json.loads(raw_s)
        except Exception:
            data["raw"] = {}
    elif isinstance(raw_s, dict):
        data["raw"] = raw_s
    return data


def delete_vulnerability(user_id: str, vuln_id: str) -> bool:
    """Delete a single finding. Tenant-scoped via get_vulnerability's
    visibility check so a user can't delete another org's finding by id."""
    if not get_vulnerability(user_id, vuln_id):
        return False
    cur = get_conn().execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
    get_conn().commit()
    if cur.rowcount:
        audit("vuln_delete", user_id, {"id": vuln_id})
        try:
            from app.realtime_bus import publish

            publish(type="vuln", id=vuln_id, user_id=user_id, action="delete")
        except Exception:
            pass
        return True
    return False


def list_vulnerabilities(
    user_id: str,
    *,
    engagement_id: str | None = None,
    status: str | None = None,
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    from app.tenancy import ensure_tenant_schema, tenant_visibility_sql

    ensure_tenant_schema()
    c = get_conn()
    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM vulnerabilities WHERE {where}"
    if engagement_id:
        q += " AND engagement_id = ?"
        args.append(engagement_id)
    if status:
        q += " AND status = ?"
        args.append(status)
    q += " ORDER BY created_at DESC LIMIT 1000"
    rows = [row_to_dict(r) for r in c.execute(q, args).fetchall()]
    rows.sort(key=lambda r: SEVERITY_RANK.get((r or {}).get("severity", "medium"), 2), reverse=True)
    for r in rows:
        if not r:
            continue
        raw_s = r.get("raw_json")
        if isinstance(r.get("raw"), dict):
            continue
        if isinstance(raw_s, str) and raw_s.strip().startswith("{"):
            try:
                r["raw"] = json.loads(raw_s)
            except Exception:
                r["raw"] = {}
        elif isinstance(raw_s, dict):
            r["raw"] = raw_s
        else:
            r["raw"] = r.get("raw") if isinstance(r.get("raw"), dict) else {}
    return rows  # type: ignore[return-value]


def _vuln_raw(row: dict[str, Any] | None) -> dict[str, Any]:
    if not row:
        return {}
    raw = row.get("raw")
    if isinstance(raw, dict):
        return raw
    raw_s = row.get("raw_json")
    if isinstance(raw_s, dict):
        return raw_s
    if isinstance(raw_s, str) and raw_s.strip().startswith("{"):
        try:
            parsed = json.loads(raw_s)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def finding_identity(item: dict[str, Any]) -> tuple[Any, ...]:
    """Stable key so live rescans update one row instead of stacking demo copies."""
    from app.asset_names import host_correlation_key
    from app.exposure import extract_port

    raw = item.get("raw") if isinstance(item.get("raw"), dict) else _vuln_raw(item)
    asset = host_correlation_key(
        str(item.get("asset_name") or raw.get("ip") or raw.get("host") or raw.get("hostname") or "")
    )
    port = raw.get("port")
    if port is None:
        port = extract_port(item.get("title") or "")
    try:
        if port is not None:
            return ("port", asset, int(port))
    except (TypeError, ValueError):
        pass
    src = (item.get("source") or "").strip().lower()
    title = (item.get("title") or "").strip().lower()
    cve = (item.get("cve") or "").strip().upper()
    if cve.startswith("CVE-"):
        return ("cve", asset, cve)
    return ("src", asset, src, title)


def upsert_vulnerability(user_id: str, item: dict[str, Any], *, emit_realtime: bool = True) -> dict[str, Any]:
    """Create or refresh a live finding. Same host+port/title is one row."""
    key = finding_identity(item)
    for existing in list_vulnerabilities(user_id):
        if finding_identity(existing) != key:
            continue
        vid = str(existing.get("id") or "")
        if not vid:
            continue
        raw = {**_vuln_raw(existing), **(item.get("raw") or {})}
        asset_row = None
        aid = item.get("asset_id") or existing.get("asset_id")
        if aid:
            asset_row = get_asset(user_id, str(aid))
        from app.asset_names import canonical_vuln_asset_name, is_better_asset_name

        new_asset_name = canonical_vuln_asset_name(
            str(item.get("asset_name") or existing.get("asset_name") or ""),
            asset=asset_row,
        )
        old_asset_name = str(existing.get("asset_name") or "")
        if not is_better_asset_name(new_asset_name, old_asset_name):
            new_asset_name = old_asset_name or new_asset_name
        patch = {
            "title": item.get("title") or existing.get("title"),
            "severity": (item.get("severity") or existing.get("severity") or "medium").lower(),
            "asset_name": new_asset_name,
            "cve": (item.get("cve") or existing.get("cve") or "").upper(),
            "raw_json": json.dumps(raw)[:8000],
        }
        if item.get("asset_id"):
            patch["asset_id"] = item.get("asset_id")
        updated = update_vulnerability(user_id, vid, patch) or existing
        updated["_upsert"] = "updated"
        return updated
    created = create_vulnerability(user_id, item, emit_realtime=emit_realtime)
    if created:
        created["_upsert"] = "created"
    return created


def collapse_duplicate_findings(user_id: str) -> dict[str, int]:
    """Keep the newest live scan finding per host+port; drop stacked copies."""
    rows = list_vulnerabilities(user_id)
    rows_by_time = sorted(rows, key=lambda r: float(r.get("updated_at") or r.get("created_at") or 0), reverse=True)
    keep: set[tuple[Any, ...]] = set()
    to_delete: list[str] = []
    for v in rows_by_time:
        src = (v.get("source") or "").lower()
        title = (v.get("title") or "").lower()
        is_scan = src.startswith(("securaiq", "nmap", "nuclei", "zap", "scan:")) or "open ports discovered" in title
        if not is_scan and not _vuln_raw(v).get("dedupe") == "risky_port":
            continue
        key = finding_identity(v)
        if key in keep:
            vid = str(v.get("id") or "")
            if vid:
                to_delete.append(vid)
        else:
            keep.add(key)
    if not to_delete:
        return {"removed": 0}
    c = get_conn()
    placeholders = ",".join("?" * len(to_delete))
    c.execute(
        f"DELETE FROM vulnerabilities WHERE user_id = ? AND id IN ({placeholders})",
        (user_id, *to_delete),
    )
    c.commit()
    return {"removed": len(to_delete)}


def update_vulnerability(user_id: str, vuln_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
    cur = get_vulnerability(user_id, vuln_id)
    if not cur:
        return None
    fields = {"status", "owner", "sla_due", "severity", "title", "asset_name", "cve", "raw_json", "asset_id"}
    data = {k: patch[k] for k in fields if k in patch}
    if not data:
        return cur
    if "status" in data:
        st = str(data["status"] or "").strip().lower()
        if st not in VULN_STATUSES:
            raise ValueError(
                f"Invalid vulnerability status '{data['status']}'. "
                f"Allowed: {', '.join(sorted(VULN_STATUSES))}"
            )
        data["status"] = st
    data["updated_at"] = now()
    sets = ", ".join(f"{k} = ?" for k in data)
    get_conn().execute(
        f"UPDATE vulnerabilities SET {sets} WHERE id = ?",
        (*data.values(), vuln_id),
    )
    get_conn().commit()
    audit("vuln_update", user_id, {"id": vuln_id, "status": data.get("status")})
    updated = get_vulnerability(user_id, vuln_id)
    try:
        from app.realtime_bus import publish

        publish(
            type="vuln",
            id=vuln_id,
            severity=(updated or {}).get("severity") or "medium",
            status=(updated or {}).get("status") or "",
            user_id=user_id,
        )
    except Exception:
        pass
    return updated


def triage_vulnerability(
    user_id: str,
    vuln_id: str,
    *,
    owner: str = "SecOps",
    create_ticket_hint: bool = False,
) -> dict[str, Any]:
    """Golden-path writeback: finding → risk + remediation + triaged status."""
    v = get_vulnerability(user_id, vuln_id)
    if not v:
        raise ValueError("Vulnerability not found")

    sev = (v.get("severity") or "medium").lower()
    impact = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(sev, 3)
    likelihood = 4 if sev in {"critical", "high"} else 3
    sla = {"critical": "24h", "high": "72h", "medium": "14d", "low": "30d"}.get(sev, "14d")
    cve = (v.get("cve") or "").strip()
    title = (v.get("title") or "Finding").strip()
    threat = f"{cve + ' — ' if cve else ''}{title}"[:500]
    asset = (v.get("asset_name") or "").strip()
    own = (owner or v.get("owner") or "SecOps").strip() or "SecOps"

    risk = create_risk(
        user_id,
        threat=threat,
        vulnerability=cve or title[:200],
        asset_name=asset,
        asset_id=v.get("asset_id"),
        impact=impact,
        likelihood=likelihood,
        owner=own,
        mitigation=f"Triage from vulnerability {vuln_id}. Verify fix and re-scan.",
        status="open",
        engagement_id=v.get("engagement_id"),
    )
    rem = create_remediation(
        user_id,
        control_id="VM",
        title=f"Remediate: {threat}"[:300],
        owner=own,
        due_date=sla,
        recommendation=(
            f"Prioritize {sev} finding on {asset or 'unknown asset'}. "
            f"Validate patch/config, then close finding after verification scan."
        ),
        engagement_id=v.get("engagement_id"),
    )
    updated = update_vulnerability(
        user_id,
        vuln_id,
        {"status": "triaged", "owner": own, "sla_due": sla},
    )
    audit(
        "vuln_triage",
        user_id,
        {"vuln_id": vuln_id, "risk_id": risk.get("id"), "remediation_id": rem.get("id")},
    )
    return {
        "ok": True,
        "vulnerability": updated,
        "risk": risk,
        "remediation": rem,
        "lifecycle": "open→triaged→in_progress→remediated→verified→resolved",
        "create_ticket_hint": create_ticket_hint,
        "workflow_step": "triaged",
    }


def import_vulnerabilities(
    user_id: str,
    *,
    content: str | bytes,
    filename: str,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    from app.scanner_adapters import try_parse_scanner_json

    name = (filename or "import").lower()
    text = content.decode("utf-8", errors="replace") if isinstance(content, (bytes, bytearray)) else content
    items: list[dict[str, Any]] = []
    adapter = None

    if name.endswith(".json") or text.strip().startswith(("[", "{")):
        adapter, scanned = try_parse_scanner_json(text, filename=filename, engagement_id=engagement_id)
        if adapter and scanned:
            items.extend(scanned)
        else:
            data = json.loads(text)
            if isinstance(data, dict):
                data = data.get("vulnerabilities") or data.get("findings") or data.get("issues") or [data]
            for row in data:
                if not isinstance(row, dict):
                    continue
                items.append(_normalize_vuln_row(row, engagement_id, source=f"json:{filename}"))
    elif name.endswith(".csv") or "," in text.split("\n", 1)[0]:
        from app.hardeningkitty import is_hardeningkitty_report, parse_report_csv

        if is_hardeningkitty_report(text, filename):
            adapter = "hardeningkitty"
            items.extend(parse_report_csv(text, engagement_id=engagement_id, filename=filename))
        else:
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                items.append(_normalize_vuln_row(dict(row), engagement_id, source=f"csv:{filename}"))
    elif name.endswith(".xml") or text.strip().startswith("<"):
        from app.scanner_adapters import (
            is_burp_xml,
            is_greenbone_xml,
            parse_burp_xml,
            parse_greenbone_xml,
        )

        if is_burp_xml(text):
            adapter = "burp"
            items.extend(parse_burp_xml(text, engagement_id=engagement_id, filename=filename))
        elif is_greenbone_xml(text):
            adapter = "greenbone"
            items.extend(parse_greenbone_xml(text, engagement_id=engagement_id, filename=filename))
        else:
            items.extend(_parse_xml_vulns(text, engagement_id, filename))
    else:
        raise ValueError(
            "Unsupported format — use CSV, JSON, XML, HardeningKitty report CSV, or scanner JSON "
            "(Trivy/Semgrep/Gitleaks/Grype/Checkov/Bandit/SonarQube/ZAP) / Burp / Greenbone XML"
        )

    created = []
    for it in items[:500]:
        # Suppress per-row bus spam on bulk import — one vuln_batch below
        created.append(create_vulnerability(user_id, it, emit_realtime=False))
    if created:
        try:
            from app.realtime_bus import publish

            publish(
                type="vuln_batch",
                source=adapter or "import",
                count=len(created),
                file=filename,
                user_id=user_id,
            )
        except Exception:
            pass
    audit(
        "vuln_import",
        user_id,
        {"file": filename, "count": len(created), "adapter": adapter or "generic"},
    )
    return {"imported": len(created), "adapter": adapter or "generic", "vulnerabilities": created[:50]}


def _normalize_vuln_row(row: dict[str, Any], engagement_id: str | None, source: str) -> dict[str, Any]:
    from app.scanner_adapters import _sev_norm

    lower = {str(k).lower().strip(): v for k, v in row.items()}
    title = (
        lower.get("title")
        or lower.get("name")
        or lower.get("plugin name")
        or lower.get("vulnerability")
        or lower.get("finding")
        or "Imported finding"
    )
    cve = lower.get("cve") or lower.get("cve_id") or lower.get("cve-id") or ""
    severity = str(lower.get("severity") or lower.get("risk") or lower.get("severity_label") or "medium")
    asset = lower.get("asset") or lower.get("host") or lower.get("ip") or lower.get("asset_name") or ""
    cvss_raw = lower.get("cvss") or lower.get("cvss_score") or lower.get("cvssv3") or None
    try:
        cvss = float(cvss_raw) if cvss_raw not in (None, "") else None
    except (TypeError, ValueError):
        cvss = None
    return {
        "title": str(title)[:300],
        "cve": str(cve)[:40],
        # Route every generic/CSV/XML import (Nessus, Qualys exports, etc.) through
        # the same critical/high/medium/low/info normalization the dedicated scanner
        # adapters use — a naive lowercase-first-word split silently produced values
        # like "information" or "blocker" that never matched any severity filter/badge.
        "severity": _sev_norm(severity, "medium"),
        "asset_name": str(asset)[:200],
        "cvss": cvss,
        "engagement_id": engagement_id,
        "source": source,
        "raw": row,
    }


def _parse_xml_vulns(text: str, engagement_id: str | None, filename: str) -> list[dict[str, Any]]:
    root = ET.fromstring(text)
    items: list[dict[str, Any]] = []
    # Generic: look for ReportItem / issue / vulnerability nodes
    candidates = (
        root.findall(".//ReportItem")
        + root.findall(".//vulnerability")
        + root.findall(".//issue")
        + root.findall(".//finding")
    )
    if not candidates:
        candidates = list(root)
    for node in candidates[:500]:
        def _t(*keys: str) -> str:
            for k in keys:
                v = node.findtext(k) or node.get(k)
                if v:
                    return v.strip()
            return ""

        title = _t("plugin_name", "name", "title", "PluginName") or node.tag
        items.append(
            _normalize_vuln_row(
                {
                    "title": title,
                    "cve": _t("cve", "CVE"),
                    "severity": _t("severity", "risk", "Risk", "severity"),
                    "asset": _t("host", "ip", "target", "Host"),
                    "cvss": _t("cvss", "cvss_base_score"),
                },
                engagement_id,
                source=f"xml:{filename}",
            )
        )
    return items


# --- Gap remediations -------------------------------------------------------


def _ensure_assessment_id(
    c: Any,
    user_id: str,
    assessment_id: str | None,
    engagement_id: str | None = None,
) -> str:
    """Resolve a real gap_assessments.id (FK required by gap_remediations)."""
    if assessment_id:
        row = c.execute("SELECT id FROM gap_assessments WHERE id = ?", (assessment_id,)).fetchone()
        if row:
            return str(row[0])
    row = c.execute(
        "SELECT id FROM gap_assessments WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
        (user_id,),
    ).fetchone()
    if row:
        return str(row[0])
    # Per-user Mission Control bucket for one-click tasks without a prior gap run
    aid = f"mission-control:{user_id}"
    ts = now()
    c.execute(
        """
        INSERT OR IGNORE INTO gap_assessments
        (id, user_id, engagement_id, framework_id, title, evidence, result_json,
         compliance_percent, created_at)
        VALUES (?, ?, ?, 'iso27001', 'Mission Control work queue', '', '{}', 0, ?)
        """,
        (aid, user_id, engagement_id, ts),
    )
    return aid


def create_remediation(
    user_id: str,
    *,
    control_id: str = "MC",
    title: str,
    owner: str = "",
    due_date: str = "",
    recommendation: str = "",
    engagement_id: str | None = None,
    assessment_id: str | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    from app.tenancy import ensure_tenant_schema, primary_org_id

    ensure_tenant_schema()
    oid = org_id or primary_org_id(user_id)
    rid = new_id()
    ts = now()
    c = get_conn()
    aid = _ensure_assessment_id(c, user_id, assessment_id, engagement_id)
    c.execute(
        """
        INSERT INTO gap_remediations
        (id, assessment_id, user_id, engagement_id, control_id, title, status,
         owner, due_date, notes, recommendation, created_at, updated_at, org_id)
        VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, '', ?, ?, ?, ?)
        """,
        (
            rid,
            aid,
            user_id,
            engagement_id,
            (control_id or "MC")[:40],
            (title or "Task")[:300],
            (owner or "")[:120],
            (due_date or "")[:40],
            (recommendation or title or "")[:2000],
            ts,
            ts,
            oid,
        ),
    )
    c.commit()
    audit("remediation_create", user_id, {"id": rid, "title": title, "org_id": oid})
    try:
        from app.realtime_bus import publish

        publish(type="remediation", id=rid, user_id=user_id, org_id=oid)
    except Exception:
        pass
    rows = list_remediations(user_id, org_id=oid)
    return next((r for r in rows if r.get("id") == rid), {"id": rid, "title": title, "status": "open", "org_id": oid})


def get_remediation(user_id: str, rem_id: str) -> dict[str, Any] | None:
    from app.tenancy import ensure_tenant_schema, row_visible_to_user

    ensure_tenant_schema()
    row = get_conn().execute("SELECT * FROM gap_remediations WHERE id = ?", (rem_id,)).fetchone()
    d = row_to_dict(row)
    if d and not row_visible_to_user(user_id, d):
        return None
    return d


def update_remediation(user_id: str, rem_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
    row = get_remediation(user_id, rem_id)
    if not row:
        return None
    fields = {"status", "owner", "due_date", "notes"}
    data = {k: patch[k] for k in fields if k in patch}
    if not data:
        return row
    data["updated_at"] = now()
    sets = ", ".join(f"{k} = ?" for k in data)
    get_conn().execute(
        f"UPDATE gap_remediations SET {sets} WHERE id = ?",
        (*data.values(), rem_id),
    )
    get_conn().commit()
    audit("gap_remediation_update", user_id, {"id": rem_id, **data})
    result = get_remediation(user_id, rem_id)
    try:
        from app.realtime_bus import publish

        publish(
            type="remediation",
            id=rem_id,
            status=(result or {}).get("status") or "",
            user_id=user_id,
        )
    except Exception:
        pass
    return result


def delete_remediation(user_id: str, rem_id: str) -> bool:
    if not get_remediation(user_id, rem_id):
        return False
    cur = get_conn().execute("DELETE FROM gap_remediations WHERE id = ?", (rem_id,))
    get_conn().commit()
    if cur.rowcount:
        audit("gap_remediation_delete", user_id, {"id": rem_id})
        try:
            from app.realtime_bus import publish

            publish(type="remediation", id=rem_id, user_id=user_id, action="delete")
        except Exception:
            pass
        return True
    return False


def create_remediations_from_live_failures(
    user_id: str,
    failures: list[dict[str, Any]] | None = None,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
) -> list[dict[str, Any]]:
    """Create owned remediation tasks from risk-ranked live control failures.

    Uses the latest gap assessment for each framework when available so tasks
    stay linked to an assessment; otherwise uses assessment_id `live:{framework_id}`.
    Dedupes against existing open remediations for the same control_id.
    """
    from app.services.control_testing import list_live_control_failures
    from app.tenancy import ensure_tenant_schema, primary_org_id

    ensure_tenant_schema()
    oid = org_id or primary_org_id(user_id)
    if failures is None:
        failures = list_live_control_failures(user_id, record_evidence=True).get("failures") or []

    latest_aid: dict[str, str] = {}
    try:
        from app.gap_analysis import list_assessments

        for row in list_assessments(user_id):
            fid = row.get("framework_id")
            if fid and fid not in latest_aid:
                latest_aid[fid] = row["id"]
    except Exception:
        latest_aid = {}

    open_controls = {
        (r.get("control_id") or "").strip().upper()
        for r in list_remediations(user_id, status="open")
        if (r.get("control_id") or "").strip()
    }

    c = get_conn()
    out: list[dict[str, Any]] = []
    ts = now()
    for g in failures:
        st = (g.get("status") or "").lower()
        if st not in {"missing", "partial", "fail"}:
            continue
        cid = (g.get("control_id") or "").strip()
        if not cid:
            continue
        if cid.upper() in open_controls:
            continue
        fid = g.get("framework_id") or "unknown"
        aid = _ensure_assessment_id(c, user_id, latest_aid.get(fid), engagement_id)
        title = g.get("title") or cid
        recommendation = (g.get("summary") or g.get("fix_hint") or "").strip()
        if g.get("risk_score") is not None:
            recommendation = f"[Live risk {g['risk_score']}] {recommendation}"
        rid = new_id()
        c.execute(
            """
            INSERT INTO gap_remediations
            (id, assessment_id, user_id, engagement_id, control_id, title, status,
             owner, due_date, notes, recommendation, created_at, updated_at, org_id)
            VALUES (?, ?, ?, ?, ?, ?, 'open', '', '', ?, ?, ?, ?, ?)
            """,
            (
                rid,
                aid,
                user_id,
                engagement_id,
                cid,
                title,
                f"source=live_test;test={g.get('test') or ''};framework={fid}",
                recommendation,
                ts,
                ts,
                oid,
            ),
        )
        open_controls.add(cid.upper())
        out.append(
            {
                "id": rid,
                "assessment_id": aid,
                "control_id": cid,
                "title": title,
                "status": "open",
                "recommendation": recommendation,
                "framework_id": fid,
                "test": g.get("test"),
                "risk_score": g.get("risk_score"),
                "workspace": g.get("workspace") or "remediations",
            }
        )
    c.commit()
    audit("live_failure_remediations", user_id, {"count": len(out)})
    if out:
        try:
            from app.realtime_bus import publish

            publish(type="remediation", id="live_failures", count=len(out), user_id=user_id)
        except Exception:
            pass
    return out


def create_remediations_from_assessment(
    user_id: str,
    assessment_id: str,
    gaps: list[dict[str, Any]],
    engagement_id: str | None = None,
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    """Persist trackable remediation tasks for missing/partial controls."""
    from app.tenancy import ensure_tenant_schema, primary_org_id

    ensure_tenant_schema()
    oid = org_id or primary_org_id(user_id)
    c = get_conn()
    # clear prior open tasks for this assessment (re-run)
    c.execute("DELETE FROM gap_remediations WHERE assessment_id = ?", (assessment_id,))
    out = []
    ts = now()
    for g in gaps:
        if g.get("status") not in {"missing", "partial"}:
            continue
        rid = new_id()
        c.execute(
            """
            INSERT INTO gap_remediations
            (id, assessment_id, user_id, engagement_id, control_id, title, status,
             owner, due_date, notes, recommendation, created_at, updated_at, org_id)
            VALUES (?, ?, ?, ?, ?, ?, 'open', '', '', '', ?, ?, ?, ?)
            """,
            (
                rid,
                assessment_id,
                user_id,
                engagement_id,
                g.get("control_id") or "",
                g.get("title") or "",
                g.get("recommendation") or "",
                ts,
                ts,
                oid,
            ),
        )
        out.append(
            {
                "id": rid,
                "assessment_id": assessment_id,
                "control_id": g.get("control_id"),
                "title": g.get("title"),
                "status": "open",
                "recommendation": g.get("recommendation"),
            }
        )
    c.commit()
    audit("gap_remediations_seed", user_id, {"assessment_id": assessment_id, "count": len(out)})
    if out:
        try:
            from app.realtime_bus import publish

            publish(type="remediation", id=assessment_id, count=len(out), user_id=user_id)
        except Exception:
            pass
    return out


def list_remediations(
    user_id: str,
    *,
    assessment_id: str | None = None,
    engagement_id: str | None = None,
    status: str | None = None,
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    from app.tenancy import ensure_tenant_schema, tenant_visibility_sql

    ensure_tenant_schema()
    c = get_conn()
    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM gap_remediations WHERE {where}"
    if assessment_id:
        q += " AND assessment_id = ?"
        args.append(assessment_id)
    if engagement_id:
        q += " AND engagement_id = ?"
        args.append(engagement_id)
    if status:
        q += " AND status = ?"
        args.append(status)
    q += " ORDER BY updated_at DESC LIMIT 500"
    return [row_to_dict(r) for r in c.execute(q, args).fetchall()]  # type: ignore[misc]


def evidence_from_files(user_id: str, file_ids: list[str]) -> str:
    """Load uploaded file text for gap analysis evidence."""
    chunks: list[str] = []
    c = get_conn()
    for fid in file_ids[:20]:
        row = c.execute(
            "SELECT * FROM files WHERE id = ? AND user_id = ?", (fid, user_id)
        ).fetchone()
        if not row:
            continue
        path = Path(row["stored_path"])
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        chunks.append(f"--- FILE: {row['filename']} ---\n{text[:40_000]}")
    return "\n\n".join(chunks)


def enterprise_dashboard(user_id: str) -> dict[str, Any]:
    from app.gap_analysis import dashboard_scores, get_assessment
    from app.ops import list_incidents, list_intel_watch, purge_demo_seed
    from app.workspace import list_audit

    purge_demo_seed(user_id)
    gap = dashboard_scores(user_id)
    risks = list_risks(user_id)
    vulns = list_vulnerabilities(user_id)
    remediations = list_remediations(user_id)
    assets = list_assets(user_id)
    playbooks = list_playbooks(user_id)
    campaigns = list_campaigns(user_id)
    incidents = list_incidents(user_id)
    intel_watch = list_intel_watch(user_id)

    open_risks = [r for r in risks if (r.get("status") or "") == "open"]
    open_vulns = [v for v in vulns if (v.get("status") or "") == "open"]
    open_rems = [r for r in remediations if (r.get("status") or "open") != "done"]
    crit_vulns = [v for v in open_vulns if (v.get("severity") or "") in {"critical", "high"}]
    active_campaigns = [c for c in campaigns if (c.get("status") or "") in {"planned", "running"}]
    open_incidents = [i for i in incidents if (i.get("status") or "") == "open"]
    pending_approvals: list[dict[str, Any]] = [
        {
            "id": r.get("id"),
            "title": r.get("title") or r.get("control_id") or "Remediation",
            "owner": r.get("owner") or "Unassigned",
            "status": r.get("status") or "open",
            "control_id": r.get("control_id") or "",
            "kind": "remediation",
        }
        for r in open_rems[:8]
    ]
    for i in open_incidents[:4]:
        pending_approvals.append(
            {
                "id": i.get("id"),
                "title": i.get("title") or "Incident",
                "owner": i.get("owner") or "Unassigned",
                "status": i.get("status") or "open",
                "control_id": "",
                "kind": "incident",
            }
        )

    avg_risk = round(sum(r.get("risk_score") or 0 for r in open_risks) / max(len(open_risks), 1), 1)

    frameworks = gap.get("frameworks") or []
    is_empty = not any(
        [
            assets,
            vulns,
            risks,
            remediations,
            incidents,
            campaigns,
            playbooks,
            intel_watch,
            frameworks,
            gap.get("assessment_count"),
        ]
    )

    # Security index — empty workspaces stay at 0 (not a fake mid-score from “no findings”).
    # When no gap assessments exist, do not treat compliance_score=0 as "0% compliant"
    # (that would falsely drag the index down); score from open risk/vuln/rem posture only.
    assessment_count = int(gap.get("assessment_count") or 0)
    compliance = float(gap.get("compliance_score") or 0)
    if is_empty:
        security_index = 0
    elif assessment_count <= 0:
        security_index = max(
            0,
            min(
                100,
                round(
                    max(0, 100 - len(open_risks) * 4) * 0.4
                    + max(0, 100 - len(crit_vulns) * 8) * 0.35
                    + max(0, 100 - len(open_rems) * 2) * 0.25
                ),
            ),
        )
    else:
        security_index = max(
            0,
            min(
                100,
                round(
                    compliance * 0.55
                    + max(0, 100 - len(open_risks) * 4) * 0.2
                    + max(0, 100 - len(crit_vulns) * 8) * 0.15
                    + max(0, 100 - len(open_rems) * 2) * 0.1
                ),
            ),
        )

    kpi_now = {
        "index": security_index,
        "comp": compliance,
        "crit": len(crit_vulns),
        "risks": len(open_risks),
        "rems": len(open_rems),
        "assets": len(assets),
        "incidents": len(open_incidents),
    }
    kpi_trends = (
        {"has_baseline": False, "security_index_delta": 0, "compliance_delta": 0, "vulns_delta": 0, "risks_delta": 0, "rems_delta": 0, "assets_delta": 0, "incidents_delta": 0}
        if is_empty
        else _compute_kpi_trends(user_id, kpi_now)
    )
    if is_empty:
        try:
            from app.config import settings as _settings

            snap = Path(_settings.data_dir) / "kpi_snaps" / f"{user_id}.json"
            if snap.exists():
                snap.unlink(missing_ok=True)
        except Exception:
            pass

    primary_fw = frameworks[0] if frameworks else None
    org_name = "Local workspace"
    try:
        from app.commercial_ext import list_orgs

        orgs = list_orgs(user_id)
        if orgs:
            org_name = orgs[0].get("name") or org_name
    except Exception:
        pass

    last_scan = None
    for v in vulns:
        ts = v.get("updated_at") or v.get("created_at")
        if ts and (last_scan is None or float(ts or 0) > float(last_scan or 0)):
            last_scan = ts
    for a in assets:
        ts = a.get("updated_at") or a.get("created_at")
        if ts and (last_scan is None or float(ts or 0) > float(last_scan or 0)):
            last_scan = ts
    if not last_scan and frameworks:
        last_scan = primary_fw.get("created_at") if primary_fw else None

    # Environment: live when inventory/findings exist — never invent "Production"
    if is_empty:
        environment = "Empty"
    elif org_name and org_name != "Local workspace":
        environment = f"Live · {org_name}"
    else:
        environment = "Live workspace"

    work_queue = _work_queue(gap, open_risks, crit_vulns or open_vulns, open_rems, assets, playbooks)
    timeline = _organization_timeline(user_id, list_audit, open_vulns, open_risks, remediations)
    asset_breakdown = _asset_breakdown(assets)
    mitre = _mitre_coverage(open_vulns, playbooks, open_risks)
    control_stats = _framework_control_stats(user_id, get_assessment, frameworks)

    correlation: dict[str, Any] = {"hotspots": [], "counts": {}}
    try:
        from app.knowledge_graph import build_knowledge_graph

        g = build_knowledge_graph(user_id)
        correlation = {
            "hotspots": g.get("hotspots") or [],
            "counts": g.get("counts") or {},
            "doctrine": g.get("doctrine") or "",
        }
    except Exception:
        pass

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        if (v.get("status") or "") in {"closed", "resolved", "fixed"}:
            continue
        s = (v.get("severity") or "medium").lower()
        if s in severity_counts:
            severity_counts[s] += 1

    recent_assets = [
        {
            "id": a.get("id"),
            "name": a.get("name") or "",
            "asset_type": a.get("asset_type") or "other",
            "criticality": a.get("criticality") or "medium",
            "owner": a.get("owner") or "",
        }
        for a in assets[:20]
    ]
    hardening = _hardening_dashboard()
    software_posture: dict[str, Any] = {}
    try:
        from app.software_inventory import posture_summary

        software_posture = posture_summary(user_id, rebuild_if_empty=False)
    except Exception:
        pass

    siem_summary: dict[str, Any] = {
        "configured": False,
        "agents_total": 0,
        "active": 0,
        "disconnected": 0,
        "pending": 0,
        "agents": [],
    }
    try:
        from app.connectors import wazuh as wz_conn
        from app.wazuh import list_agents

        siem_summary["configured"] = bool(wz_conn.is_configured())
        agents = list_agents(limit=100)
        siem_summary["agents"] = [
            {
                "id": a.get("agent_id") or a.get("id"),
                "name": a.get("name") or "",
                "ip": a.get("ip") or "",
                "status": a.get("status") or "unknown",
                "os": a.get("os") or "",
                "version": a.get("version") or "",
            }
            for a in agents[:25]
        ]
        for a in agents:
            siem_summary["agents_total"] += 1
            st = (a.get("status") or "").lower()
            if st in {"active", "connected", "online", "enabled"}:
                siem_summary["active"] += 1
            elif st in {"disconnected", "never_connected", "inactive", "disabled"}:
                siem_summary["disconnected"] += 1
            else:
                siem_summary["pending"] += 1
    except Exception:
        pass

    # Honest assessed compliance posture (never-assessed frameworks excluded).
    compliance_posture: dict[str, Any] = {
        "overall_percent": None,
        "frameworks_assessed": 0,
        "frameworks_total": 0,
        "top_gaps": [],
        "counts": {"implemented": 0, "partial": 0, "missing": 0},
        "disclaimer": (
            "Scores help assess control requirements — not a claim that you are certified compliant."
        ),
    }
    try:
        from app.services.compliance_center import compliance_overview

        co = compliance_overview(user_id)
        compliance_posture = {
            "overall_percent": co.get("overall_compliance_percent"),
            "frameworks_assessed": int(co.get("frameworks_assessed") or 0),
            "frameworks_total": int(co.get("frameworks_total") or 0),
            "top_gaps": (co.get("top_gaps") or [])[:3],
            "counts": co.get("counts") or compliance_posture["counts"],
            "disclaimer": co.get("disclaimer") or compliance_posture["disclaimer"],
            "evidence_queue_count": int(co.get("evidence_queue_count") or 0),
            "evidence_queue_preview": (co.get("evidence_queue_preview") or [])[:5],
        }
    except Exception:
        if assessment_count > 0:
            compliance_posture["overall_percent"] = compliance
            compliance_posture["frameworks_assessed"] = len(frameworks)

    # SecuraIQ Sentinel fleet (distinct from optional Wazuh SIEM agents).
    agents_fleet: dict[str, Any] = {"total": 0, "online": 0, "offline": 0, "pending": 0, "error": 0}
    try:
        from app.agents import list_agents as list_securaiq_agents

        fleet = list_securaiq_agents(user_id, limit=200)
        agents_fleet["total"] = len(fleet)
        for a in fleet:
            st = (a.get("status") or "").lower()
            if st in {"online", "upgrading"}:
                agents_fleet["online"] += 1
            elif st in {"pending"}:
                agents_fleet["pending"] += 1
            elif st in {"error"}:
                agents_fleet["error"] += 1
            else:
                agents_fleet["offline"] += 1
    except Exception:
        pass

    # "What should I fix first?" — same ranking as Executive Dashboard / Risk Simulator.
    fix_first: list[dict[str, Any]] = []
    org_risk: dict[str, Any] = {"score": 0.0, "band": "low", "total_open": 0}
    try:
        from app.services.executive_dashboard import _ai_priority_queue
        from app.services.risk_priority import compute_org_risk_score

        org_risk = compute_org_risk_score(user_id)
        fix_first = _ai_priority_queue(user_id, org_id=None, engagement_id=None, limit=5)
    except Exception:
        try:
            from app.services.risk_priority import compute_org_risk_score, compute_priority_list

            org_risk = compute_org_risk_score(user_id)
            pri = compute_priority_list(user_id, limit=5)
            fix_first = [
                {
                    "group_key": f"cve:{it.get('cve')}" if it.get("cve") else f"vuln:{it.get('vuln_id')}",
                    "title": it.get("title") or it.get("cve") or "Finding",
                    "cve": it.get("cve"),
                    "kev": it.get("kev"),
                    "quick_win": it.get("quick_win"),
                    "assets_affected": 1,
                    "asset_names": [it.get("asset_name")] if it.get("asset_name") else [],
                    "estimated_risk_reduction_pct": None,
                    "reasons": it.get("reasons") or [],
                }
                for it in (pri.get("items") or [])
            ]
        except Exception:
            fix_first = []

    return {
        **gap,
        "is_empty": is_empty,
        "security_index": security_index,
        "compliance_posture": compliance_posture,
        "agents_fleet": agents_fleet,
        "org_risk": org_risk,
        "fix_first": fix_first,
        "correlation": correlation,
        "severity_counts": severity_counts,
        "risks_open": len(open_risks),
        "risks_total": len(risks),
        "avg_open_risk_score": avg_risk,
        "vulnerabilities_open": len(open_vulns),
        "vulnerabilities_critical_high": len(crit_vulns),
        "vulnerabilities_total": len(vulns),
        "remediations_open": len(open_rems),
        "remediations_total": len(remediations),
        "assets_total": len(assets),
        "playbooks_total": len(playbooks),
        "campaigns_active": len(active_campaigns),
        "campaigns_total": len(campaigns),
        "findings": {
            "top_risks": open_risks[:5],
            "top_vulns": crit_vulns[:5] or open_vulns[:5],
            "top_remediations": open_rems[:5],
            "top_playbooks": playbooks[:5],
            "top_campaigns": active_campaigns[:5] or campaigns[:5],
        },
        "recommendations": [w["title"] for w in work_queue],
        "work_queue": work_queue,
        "needs_attention": pending_approvals,
        "mission_control": {
            "organization": org_name,
            "environment": environment,
            "framework": (primary_fw or {}).get("framework_id") or "—",
            "framework_score": (primary_fw or {}).get("compliance_percent"),
            "security_score": security_index,
            "security_score_source": "live_registers",
            "security_score_note": (
                "Computed from gap compliance + open risks/vulns/remediations in your workspace"
                if not is_empty
                else "Run Live scan or gap analysis to populate"
            ),
            "last_scan": last_scan,
            "today": {
                "critical_findings": len(crit_vulns),
                "open_risks": len(open_risks),
                "open_actions": len(open_rems),
                "open_incidents": len(open_incidents),
                "controls_failed": sum(
                    1 for f in frameworks if float(f.get("compliance_percent") or 0) < 50
                ),
            },
        },
        "pending_approvals": pending_approvals,
        "intel": {
            "watch_count": len(intel_watch),
            "watch": [
                {
                    "id": w.get("id"),
                    "kind": w.get("kind"),
                    "value": w.get("value"),
                    "notes": w.get("notes") or "",
                }
                for w in intel_watch[:6]
            ],
        },
        "incidents_open": len(open_incidents),
        "incidents_total": len(incidents),
        "workflow": {
            "imported": len(vulns),  # live findings count (scans + imports)
            "findings": len(vulns),
            "open": len(open_vulns),
            "triaged": len(
                [v for v in vulns if (v.get("status") or "") in {"in_progress", "triaged", "accepted"}]
            ),
            "actions": len(open_rems),
            "closed": len([v for v in vulns if (v.get("status") or "") in {"closed", "resolved", "fixed"}]),
            "risks": len(open_risks),
        },
        "data_source": "live_db",
        "security_index_note": (
            "Live composite of gap compliance and open risk/vuln/rem counts"
            if not is_empty
            else "Empty workspace"
        ),
        "asset_breakdown": asset_breakdown,
        "recent_assets": recent_assets,
        "hardening": hardening,
        "software_posture": software_posture,
        "siem_summary": siem_summary,
        "timeline": timeline,
        "mitre_coverage": mitre,
        "framework_control_stats": control_stats,
        "kpi_trends": kpi_trends,
        "morning_brief": _morning_brief(
            org_name=org_name,
            security_index=security_index,
            compliance=compliance,
            crit=len(crit_vulns),
            risks=len(open_risks),
            rems=len(open_rems),
            incidents=len(open_incidents),
            work_queue=work_queue,
            framework=(primary_fw or {}).get("framework_id") or "",
            is_empty=is_empty,
        ),
    }


def _morning_brief(
    *,
    org_name: str,
    security_index: int | float,
    compliance: float,
    crit: int,
    risks: int,
    rems: int,
    incidents: int,
    work_queue: list[dict[str, Any]],
    framework: str,
    is_empty: bool = False,
) -> dict[str, Any]:
    """Deterministic morning AI summary (no model call) for Mission Control home."""
    hour = __import__("datetime").datetime.now().hour
    hello = "Good morning" if hour < 12 else "Good afternoon" if hour < 17 else "Good evening"
    if is_empty:
        summary = (
            f"{hello}. {org_name} starts at zero — no assets, findings, or assessments yet. "
            "Import a scanner export or run gap analysis when you are ready."
        )
        attention = "Your workspace is empty by design."
        next_step = "Import a scanner export, add assets, or run a gap analysis with your evidence."
    elif crit == 0 and risks == 0 and incidents == 0 and not work_queue:
        summary = (
            f"{hello}. {org_name} is quiet — no critical findings or open incidents. "
            "Import a scanner export or run gap analysis when you are ready."
        )
        attention = "Maintain baseline monitoring and keep evidence current."
        next_step = "Connect integrations or import an authorized scanner export."
    else:
        top = (work_queue[0]["title"] if work_queue else "Triage critical findings")
        summary = (
            f"{hello}. Security score is {int(security_index)} with {compliance:.0f}% "
            f"{(framework or 'compliance')}. "
            f"Attention: {crit} critical/high, {risks} open risks, {incidents} incidents, "
            f"{rems} open remediations."
        )
        attention = top
        next_step = (
            work_queue[0].get("ai")
            if work_queue
            else "Triage top vulnerabilities, assign owners, and link evidence."
        )
    return {
        "greeting": hello,
        "summary": summary,
        "attention": attention,
        "next_step": next_step,
        "generated": "rules",  # model optional later
    }


def _compute_kpi_trends(user_id: str, current: dict[str, Any]) -> dict[str, Any]:
    """Persist last KPI snapshot and return deltas for Mission Control trends."""
    from app.config import settings

    snap_dir = Path(settings.data_dir) / "kpi_snaps"
    path = snap_dir / f"{user_id}.json"
    prev: dict[str, Any] = {}
    has_baseline = path.exists()
    if has_baseline:
        try:
            prev = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            prev = {}
            has_baseline = False
    try:
        snap_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({**current, "at": now()}, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

    def delta(key: str) -> int:
        if not has_baseline:
            return 0
        return int(round(float(current.get(key) or 0) - float(prev.get(key) or 0)))

    return {
        "has_baseline": has_baseline,
        "security_index_delta": delta("index"),
        "compliance_delta": delta("comp"),
        "vulns_delta": delta("crit"),
        "risks_delta": delta("risks"),
        "rems_delta": delta("rems"),
        "assets_delta": delta("assets"),
        "incidents_delta": delta("incidents"),
    }


def _work_queue(
    gap: dict[str, Any],
    risks: list[dict[str, Any]],
    vulns: list[dict[str, Any]],
    rems: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    playbooks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def add(
        *,
        priority: str,
        title: str,
        owner: str = "Unassigned",
        due: str = "This week",
        status: str = "open",
        action: str = "task",
        mode: str = "ciso",
        prompt: str = "",
        workspace: str | None = None,
        framework: str = "",
        risk: str | int | float = "",
        ai: str = "",
        entity_id: str = "",
    ) -> None:
        items.append(
            {
                "id": f"wq-{len(items)+1}",
                "priority": priority,
                "title": title,
                "owner": owner,
                "due": due,
                "status": status,
                "action": action,
                "mode": mode,
                "prompt": prompt or title,
                "workspace": workspace,
                "framework": framework,
                "risk": risk,
                "ai": ai or "Ask AI for root cause, impact, and remediation steps.",
                "entity_id": entity_id or "",
            }
        )

    # Empty workspace: no synthetic tasks — only queue real register items
    if not gap.get("assessment_count") and not vulns and not risks and not rems and not assets:
        return []

    if not gap.get("assessment_count") and (vulns or risks or rems):
        add(
            priority="high",
            title="Run gap analysis and attach evidence",
            owner="Compliance",
            due="Today",
            action="gap",
            mode="ciso",
            prompt="Guide me through an ISO 27001 gap analysis with evidence mapping",
            workspace="frameworks",
            framework="ISO 27001",
            risk="Compliance drift",
            ai="Map evidence to controls; run Gap analysis next.",
        )
    for v in vulns[:2]:
        add(
            priority="high" if (v.get("severity") or "") == "critical" else "medium",
            title=f"Patch / triage {v.get('cve') or v.get('title')}",
            owner=v.get("owner") or "SecOps",
            due=v.get("sla_due") or "72h",
            action="open",
            mode="blueteam",
            prompt=f"Draft remediation and verification for {v.get('cve') or ''} {v.get('title')}",
            workspace="vulns",
            risk=v.get("severity") or "",
            ai=f"Triage {v.get('cve') or 'finding'} → remediate → verify.",
            entity_id=str(v.get("id") or ""),
        )
    if risks:
        top = risks[0]
        add(
            priority="high" if (top.get("risk_score") or 0) >= 15 else "medium",
            title=f"Mitigate risk: {top.get('threat')}",
            owner=top.get("owner") or "Risk owner",
            due="This week",
            action="open",
            mode="ciso",
            prompt=f"Draft mitigation plan for risk: {top.get('threat')}",
            workspace="risks",
            risk=top.get("risk_score") or "",
            ai="Reduce likelihood/impact; set residual score.",
            entity_id=str(top.get("id") or ""),
        )
    for r in rems[:2]:
        add(
            priority="medium",
            title=f"Close control {r.get('control_id')}: {r.get('title')}",
            owner=r.get("owner") or "Control owner",
            due=r.get("due_date") or "30 days",
            action="open",
            mode="ciso",
            prompt=f"Implementation checklist for {r.get('control_id')} — {r.get('title')}",
            workspace="remediations",
            framework=str(r.get("framework_id") or r.get("control_id") or ""),
            ai="Attach evidence and close when verified.",
            entity_id=str(r.get("id") or ""),
        )
    # de-dupe by title, keep priority order high>medium>low
    order = {"high": 0, "medium": 1, "low": 2}
    seen: set[str] = set()
    uniq: list[dict[str, Any]] = []
    for it in sorted(items, key=lambda x: order.get(x["priority"], 9)):
        if it["title"] in seen:
            continue
        seen.add(it["title"])
        uniq.append(it)
    return uniq[:8]


def _hardening_dashboard() -> dict[str, Any]:
    """Windows HardeningKitty posture for Mission Control (no secrets)."""
    out: dict[str, Any] = {
        "installed": False,
        "powershell": False,
        "audit_done": False,
        "last_score": None,
        "last_failed": 0,
        "last_imported": 0,
        "last_run_at": None,
        "last_mode": "",
        "setup_script": ".\\scripts\\use_hardeningkitty.cmd",
        "setup_script_download": ".\\scripts\\use_hardeningkitty.cmd -Download",
        "platform_ok": __import__("platform").system().lower() == "windows",
    }
    try:
        from app import hardeningkitty as hk

        st = hk.status()
        runs = hk.recent_runs(8)
        audit_runs = [
            r
            for r in runs
            if (r.get("mode") or "").strip() in {"Audit", "Import", "Config"}
            and (r.get("status") or "done") == "done"
        ]
        last = audit_runs[0] if audit_runs else (runs[0] if runs else None)
        out.update(
            {
                "installed": bool(st.get("installed")),
                "powershell": bool(st.get("powershell")),
                "finding_lists": int(st.get("finding_lists") or 0),
                "cis_lists": int(st.get("cis_lists") or 0),
                "audit_done": bool(audit_runs),
                "last_score": last.get("score") if last else None,
                "last_failed": int(last.get("failed") or 0) if last else 0,
                "last_imported": int(last.get("imported") or 0) if last else 0,
                "last_run_at": last.get("created_at") if last else None,
                "last_mode": (last.get("mode") or "") if last else "",
            }
        )
    except Exception:
        pass
    return out


def _asset_breakdown(assets: list[dict[str, Any]]) -> dict[str, int]:
    from app.asset_categories import inventory_breakdown

    return inventory_breakdown(assets)


def _organization_timeline(
    user_id: str,
    list_audit_fn,
    vulns: list[dict[str, Any]],
    risks: list[dict[str, Any]],
    rems: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        for ev in list_audit_fn(40):
            if ev.get("user_id") not in (None, user_id, "local"):
                # include local + this user
                if user_id == "local":
                    pass
                elif ev.get("user_id") != user_id:
                    continue
            action = ev.get("action") or "event"
            events.append(
                {
                    "ts": ev.get("created_at"),
                    "label": action.replace("_", " "),
                    "detail": (
                        json.dumps(ev.get("detail"))[:120]
                        if isinstance(ev.get("detail"), (dict, list))
                        else str(ev.get("detail") or "")[:120]
                    ),
                    "kind": "audit",
                }
            )
    except Exception:
        pass
    for v in vulns[:3]:
        events.append(
            {
                "ts": v.get("updated_at") or v.get("created_at"),
                "label": f"Vuln {v.get('severity')}",
                "detail": f"{v.get('cve') or ''} {v.get('title')}".strip(),
                "kind": "vuln",
            }
        )
    for r in risks[:2]:
        events.append(
            {
                "ts": r.get("updated_at") or r.get("created_at"),
                "label": "Risk open",
                "detail": r.get("threat") or "",
                "kind": "risk",
            }
        )
    for rem in rems[:2]:
        if (rem.get("status") or "") == "done":
            events.append(
                {
                    "ts": rem.get("updated_at") or rem.get("created_at"),
                    "label": "Control closed",
                    "detail": f"{rem.get('control_id')} {rem.get('title')}",
                    "kind": "remediation",
                }
            )
    events.sort(key=lambda e: float(e.get("ts") or 0), reverse=True)
    return events[:12]


def _mitre_coverage(
    vulns: list[dict[str, Any]],
    playbooks: list[dict[str, Any]],
    risks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keyword signals from live findings — not a certified ATT&CK coverage score."""
    text = " ".join(
        f"{v.get('title','')} {v.get('cve','')} {v.get('description','')}" for v in vulns
    ).lower() + " " + " ".join(p.get("title", "") for p in playbooks).lower()
    text += " " + " ".join(r.get("threat", "") for r in risks).lower()

    tactics = [
        ("Discovery", ["scan", "recon", "enum", "discover", "port"]),
        ("Execution", ["rce", "remote code", "script", "execute", "eval"]),
        ("Persistence", ["persist", "backdoor", "startup", "cron"]),
        ("Privilege Escalation", ["privesc", "privilege", "sudo", "admin"]),
        ("Defense Evasion", ["evasion", "bypass", "disable"]),
        ("Credential Access", ["password", "credential", "mfa", "token", "secret"]),
        ("Lateral Movement", ["lateral", "rdp", "smb", "pivot"]),
        ("Exfiltration", ["exfil", "leak", "upload", "data loss"]),
    ]
    out = []
    for name, kws in tactics:
        hits = sum(1 for k in kws if k in text)
        if playbooks and name.lower() in " ".join(
            (p.get("category") or "") + " " + (p.get("title") or "") for p in playbooks
        ).lower():
            hits += 1
        out.append(
            {
                "tactic": name,
                "hits": hits,
                # Relative bar for UI only — label as signal, not certified coverage
                "coverage": min(100, hits * 20) if hits else 0,
                "mode": "keyword_signal",
            }
        )
    return out


def _framework_control_stats(user_id: str, get_assessment, frameworks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-assessment control counts for Mission Control + Frameworks UI."""
    stats: list[dict[str, Any]] = []
    for f in frameworks:
        aid = f.get("id")
        counts = {"implemented": 0, "partial": 0, "missing": 0, "not_applicable": 0}
        total = 0
        if aid:
            try:
                detail = get_assessment(user_id, aid)
                if detail and detail.get("counts"):
                    counts.update({k: int(detail["counts"].get(k) or 0) for k in counts})
                    total = int(detail.get("control_count") or 0) or sum(counts.values())
            except Exception:
                pass
        stats.append(
            {
                "framework_id": f.get("framework_id"),
                "title": f.get("title"),
                "compliance_percent": f.get("compliance_percent"),
                "controls_total": total,
                "counts": counts,
                "assessment_id": aid,
            }
        )
    return stats


def _live_recommendations(
    gap: dict[str, Any],
    risks: list[dict[str, Any]],
    vulns: list[dict[str, Any]],
    rems: list[dict[str, Any]],
    assets: list[dict[str, Any]] | None = None,
    playbooks: list[dict[str, Any]] | None = None,
    campaigns: list[dict[str, Any]] | None = None,
) -> list[str]:
    # Kept for backward compatibility — prefer work_queue
    return [
        w["title"]
        for w in _work_queue(gap, risks, vulns, rems, assets or [], playbooks or [])
    ][:6]


def export_risk_markdown(user_id: str, engagement_id: str | None = None) -> str:
    risks = list_risks(user_id, engagement_id=engagement_id)
    lines = ["# Risk Assessment Report", "", f"Open/tracked risks: **{len(risks)}**", ""]
    lines += [
        "| Asset | Threat | Vuln | I | L | Score | Owner | Status |",
        "|---|---|---|---:|---:|---:|---|---|",
    ]
    for r in risks:
        lines.append(
            f"| {r.get('asset_name') or '-'} | {r.get('threat')} | {r.get('vulnerability') or '-'} | "
            f"{r.get('impact')} | {r.get('likelihood')} | {r.get('risk_score')} | "
            f"{r.get('owner') or '-'} | {r.get('status')} |"
        )
    lines += ["", "---", "_SecuraIQ structured risk register export._"]
    return "\n".join(lines)


def export_vuln_markdown(user_id: str, engagement_id: str | None = None) -> str:
    vulns = list_vulnerabilities(user_id, engagement_id=engagement_id)
    lines = ["# Vulnerability Summary", "", f"Findings: **{len(vulns)}**", ""]
    lines += [
        "| Severity | CVE | Title | Asset | Status | Owner |",
        "|---|---|---|---|---|---|",
    ]
    for v in vulns:
        lines.append(
            f"| {v.get('severity')} | {v.get('cve') or '-'} | {v.get('title')} | "
            f"{v.get('asset_name') or '-'} | {v.get('status')} | {v.get('owner') or '-'} |"
        )
    lines += ["", "---", "_SecuraIQ vulnerability register export._"]
    return "\n".join(lines)


# --- Playbooks --------------------------------------------------------------

_DEFAULT_PLAYBOOKS = [
    {
        "title": "Ransomware — workstation containment",
        "category": "ir",
        "severity": "critical",
        "steps": (
            "1. Isolate host from network\n"
            "2. Preserve volatile evidence / EDR timeline\n"
            "3. Reset credentials for interactive users\n"
            "4. Check backup integrity before restore\n"
            "5. Exec + legal notification checklist"
        ),
    },
    {
        "title": "Business email compromise (BEC)",
        "category": "ir",
        "severity": "high",
        "steps": (
            "1. Disable suspect mailbox rules / forwarding\n"
            "2. Force sign-out + MFA reset\n"
            "3. Trace recent mail flow and finance wires\n"
            "4. Notify partners if invoices were altered\n"
            "5. Awareness follow-up within 7 days"
        ),
    },
    {
        "title": "Suspected insider data staging",
        "category": "ir",
        "severity": "high",
        "steps": (
            "1. Preserve logs without tipping off subject\n"
            "2. Legal / HR coordination\n"
            "3. Restrict access to sensitive shares\n"
            "4. Collect DLP / USB / cloud sync evidence\n"
            "5. Post-incident access review"
        ),
    },
]



def reset_workspace(user_id: str, *, clear_rag: bool = False) -> dict[str, Any]:
    """Wipe operational data for a user so Mission Control starts at zero. Keeps auth accounts.

    Scan evidence is archived under data/archive/ first (no-loss).
    """
    archived: dict[str, Any] = {}
    try:
        from app.archive import archive_user_scans

        archived = archive_user_scans(user_id)
    except Exception as exc:
        archived = {"ok": False, "error": str(exc)}

    c = get_conn()
    counts: dict[str, int] = {}

    # Child rows first where needed
    chat_ids = [
        r["id"]
        for r in c.execute("SELECT id FROM chats WHERE user_id = ?", (user_id,)).fetchall()
    ]
    if chat_ids:
        placeholders = ",".join("?" * len(chat_ids))
        cur = c.execute(f"DELETE FROM messages WHERE chat_id IN ({placeholders})", chat_ids)
        counts["messages"] = int(cur.rowcount or 0)

    tables = [
        "chats",
        "memories",
        "files",
        "gap_remediations",
        "gap_assessments",
        "assets",
        "risks",
        "vulnerabilities",
        "scans",
        "playbooks",
        "campaigns",
        "incidents",
        "intel_watch",
        "entity_links",
        "webhooks",
        "evidence_links",
        "engagements",
        "notifications",
        "action_approvals",
        "usage_events",
    ]
    for table in tables:
        try:
            cur = c.execute(f"DELETE FROM {table} WHERE user_id = ?", (user_id,))
            counts[table] = int(cur.rowcount or 0)
        except Exception:
            counts[table] = counts.get(table, 0)

    # Global operational queues (no user_id) — always clear so Automation starts empty
    for table in ("xdr_events", "jobs", "wazuh_agents", "openaudit_devices", "hardeningkitty_runs"):
        try:
            cur = c.execute(f"DELETE FROM {table}")
            counts[table] = int(cur.rowcount or 0)
        except Exception:
            counts[table] = counts.get(table, 0)

    # Organizations owned / joined by this user
    try:
        from app.commercial_ext import ensure_org_schema

        ensure_org_schema()
        org_ids = [
            r["org_id"]
            for r in c.execute("SELECT org_id FROM org_members WHERE user_id = ?", (user_id,)).fetchall()
        ]
        cur = c.execute("DELETE FROM org_members WHERE user_id = ?", (user_id,))
        counts["org_members"] = int(cur.rowcount or 0)
        orgs_deleted = 0
        for oid in org_ids:
            left = c.execute("SELECT 1 FROM org_members WHERE org_id = ? LIMIT 1", (oid,)).fetchone()
            if left:
                continue
            c.execute("DELETE FROM organizations WHERE id = ?", (oid,))
            orgs_deleted += 1
        counts["organizations"] = orgs_deleted
    except Exception:
        counts["organizations"] = counts.get("organizations", 0)

    c.commit()
    audit("workspace_reset", user_id, {"counts": counts, "clear_rag": clear_rag})

    # Clear KPI trend baseline so empty UI does not show stale deltas
    try:
        from app.config import settings as _settings

        snap = Path(_settings.data_dir) / "kpi_snaps" / f"{user_id}.json"
        if snap.exists():
            snap.unlink(missing_ok=True)
            counts["kpi_snap"] = 1
    except Exception:
        pass

    rag_cleared = False
    if clear_rag:
        try:
            from app.config import settings as _settings
            from app.rag import rag_engine

            if hasattr(rag_engine, "reset"):
                rag_engine.reset()
                rag_cleared = True
            else:
                persist = Path(_settings.chroma_persist_dir)
                if persist.exists():
                    import shutil

                    shutil.rmtree(persist, ignore_errors=True)
                    rag_cleared = True
        except Exception:
            rag_cleared = False

    return {
        "ok": True,
        "deleted": counts,
        "rag_cleared": rag_cleared,
        "archived": archived,
        "archived_count": archived.get("archived_count") or 0,
        "archive_batch": archived.get("batch_dir"),
    }


def apply_workspace_zero_start() -> dict[str, Any] | None:
    """Nil / zero boot for open local mode — Mission Control starts empty."""
    from app.config import settings as _settings

    if _settings.auth_enabled or not getattr(_settings, "workspace_zero_start", False):
        return None

    user_ids: set[str] = {"local"}
    c = get_conn()
    for table in (
        "assets",
        "risks",
        "vulnerabilities",
        "scans",
        "engagements",
        "gap_assessments",
        "incidents",
        "playbooks",
        "campaigns",
        "notifications",
        "chats",
    ):
        try:
            for row in c.execute(f"SELECT DISTINCT user_id FROM {table}"):
                uid = row[0] if not isinstance(row, dict) else row.get("user_id")
                if uid:
                    user_ids.add(str(uid))
        except Exception:
            continue

    result: dict[str, Any] = {"users": [], "deleted": {}, "archived_count": 0}
    for uid in sorted(user_ids):
        wiped = reset_workspace(uid, clear_rag=False)
        result["users"].append(uid)
        result["deleted"][uid] = wiped.get("deleted") or {}
        result["archived_count"] += int(wiped.get("archived_count") or 0)

    # Clear KPI snap files
    try:
        snap_dir = Path(_settings.data_dir) / "kpi_snaps"
        if snap_dir.is_dir():
            for snap in snap_dir.glob("*.json"):
                snap.unlink(missing_ok=True)
    except Exception:
        pass

    print(
        "Workspace: zero-start — Mission Control loads empty. "
        f"Archived {result['archived_count']} scan(s) under data/archive. "
        "Set WORKSPACE_ZERO_START=false to keep live data across restarts."
    )
    return result


def ensure_default_playbooks(user_id: str) -> None:
    """No-op — playbooks start empty; users add their own."""
    return


def create_playbook(
    user_id: str,
    *,
    title: str,
    category: str = "ir",
    severity: str = "high",
    steps: str = "",
    status: str = "ready",
    owner: str = "",
    engagement_id: str | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    from app.tenancy import ensure_tenant_schema, primary_org_id

    ensure_tenant_schema()
    oid = org_id or primary_org_id(user_id)
    pid = new_id()
    ts = now()
    c = get_conn()
    c.execute(
        """
        INSERT INTO playbooks
        (id, user_id, engagement_id, title, category, severity, steps, status, owner, created_at, updated_at, org_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (pid, user_id, engagement_id, title.strip(), category, severity, steps, status, owner, ts, ts, oid),
    )
    c.commit()
    audit("playbook_create", user_id, {"id": pid, "title": title, "org_id": oid})
    try:
        from app.realtime_bus import publish

        publish(type="playbook", id=pid, user_id=user_id)
    except Exception:
        pass
    return get_playbook(user_id, pid)  # type: ignore[return-value]


def get_playbook(user_id: str, playbook_id: str) -> dict[str, Any] | None:
    row = get_conn().execute(
        "SELECT * FROM playbooks WHERE id = ? AND user_id = ?", (playbook_id, user_id)
    ).fetchone()
    return row_to_dict(row)


def list_playbooks(
    user_id: str, engagement_id: str | None = None, *, org_id: str | None = None
) -> list[dict[str, Any]]:
    from app.tenancy import ensure_tenant_schema, tenant_visibility_sql

    ensure_tenant_schema()
    c = get_conn()
    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM playbooks WHERE {where}"
    if engagement_id:
        q += " AND engagement_id = ?"
        args.append(engagement_id)
        q += " ORDER BY updated_at DESC"
    else:
        q += " ORDER BY updated_at DESC LIMIT 200"
    rows = c.execute(q, args).fetchall()
    return [row_to_dict(r) for r in rows]  # type: ignore[misc]


def update_playbook(user_id: str, playbook_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
    row = get_playbook(user_id, playbook_id)
    if not row:
        return None
    allowed = {"title", "category", "severity", "steps", "status", "owner", "engagement_id"}
    data = {k: v for k, v in patch.items() if k in allowed and v is not None}
    if not data:
        return row
    data["updated_at"] = now()
    sets = ", ".join(f"{k} = ?" for k in data)
    get_conn().execute(
        f"UPDATE playbooks SET {sets} WHERE id = ? AND user_id = ?",
        (*data.values(), playbook_id, user_id),
    )
    get_conn().commit()
    audit("playbook_update", user_id, {"id": playbook_id, **data})
    return get_playbook(user_id, playbook_id)


def delete_playbook(user_id: str, playbook_id: str) -> bool:
    cur = get_conn().execute(
        "DELETE FROM playbooks WHERE id = ? AND user_id = ?", (playbook_id, user_id)
    )
    get_conn().commit()
    if cur.rowcount:
        audit("playbook_delete", user_id, {"id": playbook_id})
        return True
    return False


# --- Awareness campaigns ----------------------------------------------------


def create_campaign(
    user_id: str,
    *,
    name: str,
    campaign_type: str = "phishing_sim",
    audience: str = "",
    status: str = "planned",
    sent_count: int = 0,
    click_count: int = 0,
    report_count: int = 0,
    notes: str = "",
    engagement_id: str | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    from app.tenancy import ensure_tenant_schema, primary_org_id

    ensure_tenant_schema()
    oid = org_id or primary_org_id(user_id)
    cid = new_id()
    ts = now()
    c = get_conn()
    c.execute(
        """
        INSERT INTO campaigns
        (id, user_id, engagement_id, name, campaign_type, audience, status,
         sent_count, click_count, report_count, notes, created_at, updated_at, org_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cid,
            user_id,
            engagement_id,
            name.strip(),
            campaign_type,
            audience,
            status,
            int(sent_count),
            int(click_count),
            int(report_count),
            notes,
            ts,
            ts,
            oid,
        ),
    )
    c.commit()
    audit("campaign_create", user_id, {"id": cid, "name": name, "org_id": oid})
    try:
        from app.realtime_bus import publish

        publish(type="campaign", id=cid, user_id=user_id)
    except Exception:
        pass
    return get_campaign(user_id, cid)  # type: ignore[return-value]


def get_campaign(user_id: str, campaign_id: str) -> dict[str, Any] | None:
    row = get_conn().execute(
        "SELECT * FROM campaigns WHERE id = ? AND user_id = ?", (campaign_id, user_id)
    ).fetchone()
    return row_to_dict(row)


def list_campaigns(
    user_id: str, engagement_id: str | None = None, *, org_id: str | None = None
) -> list[dict[str, Any]]:
    from app.tenancy import ensure_tenant_schema, tenant_visibility_sql

    ensure_tenant_schema()
    c = get_conn()
    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM campaigns WHERE {where}"
    if engagement_id:
        q += " AND engagement_id = ?"
        args.append(engagement_id)
        q += " ORDER BY updated_at DESC"
    else:
        q += " ORDER BY updated_at DESC LIMIT 200"
    rows = c.execute(q, args).fetchall()
    return [row_to_dict(r) for r in rows]  # type: ignore[misc]


def update_campaign(user_id: str, campaign_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
    row = get_campaign(user_id, campaign_id)
    if not row:
        return None
    allowed = {
        "name",
        "campaign_type",
        "audience",
        "status",
        "sent_count",
        "click_count",
        "report_count",
        "notes",
        "engagement_id",
    }
    data = {k: v for k, v in patch.items() if k in allowed and v is not None}
    if not data:
        return row
    data["updated_at"] = now()
    sets = ", ".join(f"{k} = ?" for k in data)
    get_conn().execute(
        f"UPDATE campaigns SET {sets} WHERE id = ? AND user_id = ?",
        (*data.values(), campaign_id, user_id),
    )
    get_conn().commit()
    audit("campaign_update", user_id, {"id": campaign_id, **data})
    return get_campaign(user_id, campaign_id)


def delete_campaign(user_id: str, campaign_id: str) -> bool:
    cur = get_conn().execute(
        "DELETE FROM campaigns WHERE id = ? AND user_id = ?", (campaign_id, user_id)
    )
    get_conn().commit()
    if cur.rowcount:
        audit("campaign_delete", user_id, {"id": campaign_id})
        return True
    return False
