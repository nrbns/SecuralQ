"""Security knowledge graph: assets ↔ vulns ↔ risks ↔ controls ↔ evidence ↔ incidents ↔ XDR.

This is SecuraIQ's correlation centerpiece — not a decorative side page. Derived
edges are rebuilt on each graph read; optional ``rebuild_auto_links`` persists
high-confidence links into ``entity_links`` for explicit analyst review.
"""

from __future__ import annotations

import re
from typing import Any

from app.commercial_ext import list_evidence_links
from app.db import get_conn, new_id, now, row_to_dict
from app.enterprise import list_assets, list_remediations, list_risks, list_vulnerabilities
from app.ops import list_incidents


def ensure_graph_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS entity_links (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            src_type TEXT NOT NULL,
            src_id TEXT NOT NULL,
            dst_type TEXT NOT NULL,
            dst_id TEXT NOT NULL,
            relation TEXT NOT NULL DEFAULT 'related',
            notes TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            UNIQUE(user_id, src_type, src_id, dst_type, dst_id, relation)
        );
        """
    )
    c.commit()


def add_entity_link(
    user_id: str,
    *,
    src_type: str,
    src_id: str,
    dst_type: str,
    dst_id: str,
    relation: str = "related",
    notes: str = "",
) -> dict[str, Any]:
    ensure_graph_schema()
    lid = new_id()
    try:
        get_conn().execute(
            """
            INSERT INTO entity_links
            (id, user_id, src_type, src_id, dst_type, dst_id, relation, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                lid,
                user_id,
                src_type[:40],
                src_id[:80],
                dst_type[:40],
                dst_id[:80],
                (relation or "related")[:60],
                (notes or "")[:500],
                now(),
            ),
        )
        get_conn().commit()
    except Exception:
        row = get_conn().execute(
            """
            SELECT * FROM entity_links
            WHERE user_id = ? AND src_type = ? AND src_id = ? AND dst_type = ? AND dst_id = ? AND relation = ?
            """,
            (user_id, src_type[:40], src_id[:80], dst_type[:40], dst_id[:80], (relation or "related")[:60]),
        ).fetchone()
        return row_to_dict(row) or {"id": lid}
    row = get_conn().execute("SELECT * FROM entity_links WHERE id = ?", (lid,)).fetchone()
    return row_to_dict(row)  # type: ignore[return-value]


def list_entity_links(user_id: str) -> list[dict[str, Any]]:
    ensure_graph_schema()
    rows = get_conn().execute(
        "SELECT * FROM entity_links WHERE user_id = ? ORDER BY created_at DESC LIMIT 500",
        (user_id,),
    ).fetchall()
    return [row_to_dict(r) for r in rows]  # type: ignore[misc]


def _list_xdr_events(limit: int = 200) -> list[dict[str, Any]]:
    try:
        rows = get_conn().execute(
            "SELECT * FROM xdr_events ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def _list_agent_threats(user_id: str, limit: int = 200) -> list[dict[str, Any]]:
    """Active native SecuraIQ agent threats (Sentinel + check-in FIM)."""
    try:
        from app.agents import list_threats

        return [
            t
            for t in list_threats(user_id, limit=limit)
            if str(t.get("status") or "active").lower() == "active"
        ]
    except Exception:
        return []


def _norm_host(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def build_knowledge_graph(user_id: str) -> dict[str, Any]:
    """Derive a correlated graph from registers + XDR + explicit links."""
    ensure_graph_schema()
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str, str]] = set()

    def node(kind: str, nid: str, label: str, meta: dict[str, Any] | None = None) -> str:
        key = f"{kind}:{nid}"
        if key not in nodes:
            nodes[key] = {"id": key, "type": kind, "ref": nid, "label": label, "meta": meta or {}}
        elif meta:
            nodes[key]["meta"].update({k: v for k, v in meta.items() if v is not None})
        return key

    def edge(src: str, dst: str, relation: str) -> None:
        key = (src, dst, relation)
        if key in seen_edges or src == dst:
            return
        seen_edges.add(key)
        edges.append({"from": src, "to": dst, "relation": relation})

    assets = list_assets(user_id)
    asset_by_name = {_norm_host(a.get("name") or ""): a for a in assets if a.get("name")}
    asset_by_id = {a["id"]: a for a in assets}
    for a in assets:
        node(
            "asset",
            a["id"],
            a.get("name") or "asset",
            {"type": a.get("asset_type"), "criticality": a.get("criticality")},
        )

    def resolve_asset_key(name: str) -> str | None:
        aname = _norm_host(name)
        if not aname:
            return None
        if aname in asset_by_name:
            a = asset_by_name[aname]
            return node("asset", a["id"], a.get("name") or aname)
        # fuzzy: hostname substring match
        for n, a in asset_by_name.items():
            if aname in n or n in aname:
                return node("asset", a["id"], a.get("name") or n)
        return node("asset", f"name:{aname}", name, {"synthetic": True})

    vulns = list_vulnerabilities(user_id)
    vuln_by_asset: dict[str, list[dict[str, Any]]] = {}
    for v in vulns:
        vk = node(
            "vuln",
            v["id"],
            f"{v.get('cve') or ''} {v.get('title') or ''}".strip()[:80],
            {"severity": v.get("severity"), "status": v.get("status")},
        )
        aname = v.get("asset_name") or ""
        ak = resolve_asset_key(aname) if aname else None
        if ak:
            edge(vk, ak, "affects")
            vuln_by_asset.setdefault(ak, []).append(v)
        cve = (v.get("cve") or "").upper()
        if cve.startswith("CVE-"):
            ck = node("cve", cve, cve)
            edge(vk, ck, "maps_to")

    risks = list_risks(user_id)
    for r in risks:
        rk = node(
            "risk",
            r["id"],
            (r.get("threat") or "risk")[:80],
            {"score": r.get("risk_score"), "status": r.get("status")},
        )
        ak = resolve_asset_key(r.get("asset_name") or "")
        if ak:
            edge(rk, ak, "threatens")
            # Same asset as open vulns → correlate risk↔vuln
            for v in vuln_by_asset.get(ak, [])[:5]:
                if (v.get("status") or "") == "open":
                    edge(rk, node("vuln", v["id"], v.get("title") or "vuln"), "informed_by")

    rems = list_remediations(user_id)
    for rem in rems:
        control_id = rem.get("control_id") or rem["id"]
        ck = node(
            "control",
            control_id,
            f"{rem.get('control_id') or ''} — {rem.get('title') or ''}".strip(" —")[:80],
            {"status": rem.get("status"), "owner": rem.get("owner")},
        )
        rk = node("remediation", rem["id"], rem.get("title") or "task", {"status": rem.get("status")})
        edge(ck, rk, "tracked_by")

    for ev in list_evidence_links(user_id):
        ek = node(
            "evidence",
            ev["id"],
            ev.get("filename") or ev.get("file_id") or "evidence",
            {"status": ev.get("status"), "control_id": ev.get("control_id")},
        )
        cid = ev.get("control_id")
        if cid:
            edge(ek, node("control", cid, cid), "supports")
        if ev.get("remediation_id"):
            edge(ek, node("remediation", ev["remediation_id"], "remediation"), "attached_to")

    incidents = list_incidents(user_id)
    for inc in incidents:
        ik = node(
            "incident",
            inc["id"],
            inc.get("title") or "incident",
            {"severity": inc.get("severity"), "status": inc.get("status"), "source": inc.get("source")},
        )
        blob = f"{inc.get('title') or ''} {inc.get('summary') or ''}"
        # Link incident → asset when a known asset name appears in the text
        for aname, a in asset_by_name.items():
            if len(aname) >= 3 and aname in blob.lower():
                edge(ik, node("asset", a["id"], a.get("name") or aname), "involves")
                break
        # XDR-sourced incidents: source like xdr:crowdstrike
        src = (inc.get("source") or "").lower()
        if src.startswith("xdr:"):
            vendor = src.split(":", 1)[-1]
            edge(ik, node("vendor", vendor, vendor), "from_vendor")

    for evt in _list_xdr_events():
        ek = node(
            "xdr",
            evt["id"],
            (evt.get("title") or "detection")[:80],
            {
                "vendor": evt.get("vendor"),
                "severity": evt.get("severity"),
                "host": evt.get("host"),
                "kind": evt.get("kind"),
            },
        )
        host = evt.get("host") or ""
        ak = resolve_asset_key(host) if host else None
        if ak:
            edge(ek, ak, "on_host")
        if evt.get("linked_incident_id"):
            edge(ek, node("incident", evt["linked_incident_id"], "incident"), "opened")
        if evt.get("linked_vuln_id"):
            edge(ek, node("vuln", evt["linked_vuln_id"], "vuln"), "maps_to")
        vendor = (evt.get("vendor") or "").strip()
        if vendor:
            edge(ek, node("vendor", vendor, vendor), "detected_by")

    # Native agent threats (check-in FIM / Sentinel) — same "xdr" bucket for
    # correlation_hotspots so Detect is visible without a parallel graph type.
    for thr in _list_agent_threats(user_id):
        tid = str(thr.get("id") or "")
        if not tid:
            continue
        ek = node(
            "xdr",
            f"agent_threat:{tid}",
            (thr.get("title") or "agent detection")[:80],
            {
                "vendor": "securaiq_agent",
                "severity": thr.get("severity"),
                "host": thr.get("asset_id") or "",
                "kind": thr.get("category") or "agent_threat",
                "source": "securaiq_agent_threats",
            },
        )
        asset_id = str(thr.get("asset_id") or "").strip()
        if asset_id and asset_id in asset_by_id:
            edge(ek, node("asset", asset_id, asset_by_id[asset_id].get("name") or asset_id), "on_host")
        if thr.get("incident_id"):
            edge(ek, node("incident", thr["incident_id"], "incident"), "opened")
        if thr.get("vuln_id"):
            edge(ek, node("vuln", thr["vuln_id"], "vuln"), "maps_to")
        edge(ek, node("vendor", "securaiq_agent", "securaiq_agent"), "detected_by")

    for link in list_entity_links(user_id):
        sk = node(link["src_type"], link["src_id"], f"{link['src_type']}:{link['src_id']}")
        dk = node(link["dst_type"], link["dst_id"], f"{link['dst_type']}:{link['dst_id']}")
        edge(sk, dk, link.get("relation") or "related")

    by_type: dict[str, int] = {}
    for n in nodes.values():
        by_type[n["type"]] = by_type.get(n["type"], 0) + 1

    hotspots = correlation_hotspots(user_id, graph={"nodes": list(nodes.values()), "edges": edges})

    return {
        "nodes": list(nodes.values()),
        "edges": edges[:2000],
        "counts": {"nodes": len(nodes), "edges": len(edges), "by_type": by_type},
        "hotspots": hotspots[:12],
        "doctrine": (
            "Correlation joins VAPT findings, XDR detections, incidents, and GRC controls "
            "on shared assets — the differentiator is one picture, not five tabs."
        ),
    }


def correlation_hotspots(
    user_id: str,
    *,
    graph: dict[str, Any] | None = None,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Assets (or synthetic hosts) that sit at the intersection of disciplines."""
    g = graph or build_knowledge_graph(user_id)
    nodes = {n["id"]: n for n in g.get("nodes") or []}
    edges = g.get("edges") or []

    # adjacency: asset_key -> related typed neighbors
    asset_hits: dict[str, dict[str, set[str]]] = {}
    for e in edges:
        for end, other in ((e["from"], e["to"]), (e["to"], e["from"])):
            n = nodes.get(end)
            o = nodes.get(other)
            if not n or not o:
                continue
            if n.get("type") != "asset":
                continue
            bucket = asset_hits.setdefault(end, {"vuln": set(), "incident": set(), "xdr": set(), "risk": set(), "control": set()})
            t = o.get("type")
            if t in bucket:
                bucket[t].add(other)
            if t == "remediation":
                bucket["control"].add(other)

    scored: list[dict[str, Any]] = []
    for aid, buckets in asset_hits.items():
        n = nodes.get(aid) or {}
        v, i, x, r, c = (
            len(buckets["vuln"]),
            len(buckets["incident"]),
            len(buckets["xdr"]),
            len(buckets["risk"]),
            len(buckets["control"]),
        )
        disciplines = sum(1 for k in (v, i, x, r, c) if k)
        if disciplines < 2 and (v + i + x) < 2:
            continue
        score = v * 3 + i * 4 + x * 3 + r * 2 + c + disciplines * 5
        meta = n.get("meta") or {}
        scored.append(
            {
                "asset_id": n.get("ref") or aid,
                "asset_key": aid,
                "label": n.get("label") or aid,
                "synthetic": bool(meta.get("synthetic")),
                "criticality": meta.get("criticality"),
                "score": score,
                "disciplines": disciplines,
                "counts": {"vuln": v, "incident": i, "xdr": x, "risk": r, "control": c},
                "why": _hotspot_why(v, i, x, r, c),
            }
        )
    scored.sort(key=lambda h: (-h["score"], h["label"]))
    return scored[:limit]


def _hotspot_why(v: int, i: int, x: int, r: int, c: int) -> str:
    parts = []
    if v:
        parts.append(f"{v} vuln(s)")
    if x:
        parts.append(f"{x} detection(s)")
    if i:
        parts.append(f"{i} incident(s)")
    if r:
        parts.append(f"{r} risk(s)")
    if c:
        parts.append(f"{c} control/remediation(s)")
    return " + ".join(parts) if parts else "correlated"


def correlate_focus(user_id: str, query: str) -> dict[str, Any]:
    """Return the subgraph around an asset name/id (or CVE)."""
    g = build_knowledge_graph(user_id)
    q = (query or "").strip().lower()
    if not q:
        return {"query": query, "nodes": [], "edges": [], "hotspots": g.get("hotspots") or []}

    seed = set()
    for n in g.get("nodes") or []:
        label = (n.get("label") or "").lower()
        ref = str(n.get("ref") or "").lower()
        nid = (n.get("id") or "").lower()
        if q in label or q == ref or q in nid or q == nid.split(":", 1)[-1]:
            seed.add(n["id"])

    if not seed:
        return {"query": query, "nodes": [], "edges": [], "match": False, "hotspots": []}

    # 1-hop expansion
    keep = set(seed)
    for e in g.get("edges") or []:
        if e["from"] in seed or e["to"] in seed:
            keep.add(e["from"])
            keep.add(e["to"])
    nodes = [n for n in (g.get("nodes") or []) if n["id"] in keep]
    edges = [e for e in (g.get("edges") or []) if e["from"] in keep and e["to"] in keep]
    return {
        "query": query,
        "match": True,
        "nodes": nodes,
        "edges": edges,
        "counts": {
            "nodes": len(nodes),
            "edges": len(edges),
            "by_type": {
                t: sum(1 for n in nodes if n.get("type") == t)
                for t in {n.get("type") for n in nodes}
            },
        },
        "hotspots": [h for h in (g.get("hotspots") or []) if q in (h.get("label") or "").lower()]
        or (g.get("hotspots") or [])[:6],
        "doctrine": g.get("doctrine"),
    }


def rebuild_auto_links(user_id: str) -> dict[str, Any]:
    """Persist high-confidence derived edges (asset↔vuln, xdr↔incident) as entity_links."""
    g = build_knowledge_graph(user_id)
    created = 0
    for e in g.get("edges") or []:
        rel = e.get("relation") or "related"
        if rel not in {"affects", "on_host", "opened", "involves", "threatens", "maps_to"}:
            continue
        frm, to = e["from"], e["to"]
        if ":" not in frm or ":" not in to:
            continue
        src_type, src_id = frm.split(":", 1)
        dst_type, dst_id = to.split(":", 1)
        if src_id.startswith("name:") or dst_id.startswith("name:"):
            continue  # skip synthetic hosts for persisted links
        t0 = now()
        row = add_entity_link(
            user_id,
            src_type=src_type,
            src_id=src_id,
            dst_type=dst_type,
            dst_id=dst_id,
            relation=rel,
            notes="auto:correlation",
        )
        if row and abs(float(row.get("created_at") or 0) - t0) < 2.5:
            created += 1
    return {"ok": True, "links_created": created, "hotspots": correlation_hotspots(user_id)[:8]}
