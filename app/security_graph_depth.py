"""Security graph identity depth — users, permissions, containers, cloud, data.

Honesty: derived from existing registers (org members, RBAC roles, asset
categories, cloud connector findings, database-typed assets). Not a full
IAM/K8s/cloud twin. Lab-production depth over the attack/knowledge graphs.
"""

from __future__ import annotations

from typing import Any, Callable


def enrich_graph_identity_depth(
    user_id: str,
    *,
    node: Callable[..., str],
    edge: Callable[[str, str, str], None],
    assets: list[dict[str, Any]],
) -> dict[str, Any]:
    """Mutate graph via node/edge callbacks; return depth counts."""
    counts = {
        "user": 0,
        "permission": 0,
        "container": 0,
        "cloud_resource": 0,
        "data_store": 0,
    }

    # --- Users + permissions (org membership / RBAC) ---
    try:
        from app.commercial_ext import list_orgs, list_org_members
        from app.rbac import ORG_ROLE_RANK, PERMISSIONS

        role_actions: dict[str, list[str]] = {}
        for action, spec in PERMISSIONS.items():
            org_min = spec.get("org_min")
            if not org_min:
                continue
            for role, rank in ORG_ROLE_RANK.items():
                if rank >= ORG_ROLE_RANK.get(str(org_min), 99):
                    role_actions.setdefault(role, []).append(action)

        orgs = list_orgs(user_id) or []
        for org in orgs[:20]:
            oid = str(org.get("id") or "")
            if not oid:
                continue
            try:
                members = list_org_members(user_id, oid) or []
            except Exception:
                members = []
            for m in members[:200]:
                uid = str(m.get("user_id") or "")
                if not uid:
                    continue
                uname = str(m.get("username") or uid)[:80]
                uk = node("user", uid, uname, {"org_id": oid, "role": m.get("role")})
                counts["user"] += 1
                role = str(m.get("role") or "viewer").lower()
                pk = node(
                    "permission",
                    f"{oid}:{role}",
                    f"role:{role}",
                    {"org_id": oid, "perms": (role_actions.get(role) or [])[:20]},
                )
                counts["permission"] += 1
                edge(uk, pk, "has_role")
    except Exception:
        pass

    # --- Containers / data stores from asset types ---
    from app.asset_categories import normalize_asset_category

    for a in assets:
        aid = str(a.get("id") or "")
        if not aid:
            continue
        cat = normalize_asset_category(a.get("asset_type") or a.get("category") or "")
        label = str(a.get("name") or aid)[:80]
        ak = node("asset", aid, label, {"type": a.get("asset_type")})
        if cat in {"container", "kubernetes", "k8s"} or "container" in str(a.get("asset_type") or "").lower():
            ck = node("container", aid, f"container:{label}", {"asset_id": aid})
            counts["container"] += 1
            edge(ck, ak, "runs_on")
        if cat in {"database", "data", "storage"} or "db" in str(a.get("asset_type") or "").lower():
            dk = node("data_store", aid, f"data:{label}", {"asset_id": aid})
            counts["data_store"] += 1
            edge(ak, dk, "stores")
        # Cloud-tagged assets (notes meta or type)
        cloud = str(a.get("cloud_provider") or a.get("provider") or "").lower()
        if not cloud:
            try:
                from app.asset_names import parse_notes_meta

                meta = parse_notes_meta(str(a.get("notes") or ""))
                cloud = str(meta.get("cloud_provider") or meta.get("provider") or "").lower()
            except Exception:
                cloud = ""
        if cloud in {"aws", "azure", "gcp"} or cat in {"cloud", "saas"}:
            cr = node(
                "cloud_resource",
                aid,
                f"{cloud or 'cloud'}:{label}",
                {"provider": cloud or "cloud", "asset_id": aid},
            )
            counts["cloud_resource"] += 1
            edge(cr, ak, "hosts")

    # --- Cloud posture findings (when connectors have synced) ---
    try:
        from app.db import get_conn

        rows = get_conn().execute(
            """
            SELECT id, title, provider, resource_id, severity
            FROM cloud_posture_findings
            WHERE user_id = ?
            ORDER BY created_at DESC LIMIT 100
            """,
            (user_id,),
        ).fetchall()
        for r in rows:
            rid = str(r["id"] or r["resource_id"] or "")
            if not rid:
                continue
            label = str(r["title"] or r["resource_id"] or rid)[:80]
            ck = node(
                "cloud_resource",
                rid,
                label,
                {
                    "provider": r["provider"],
                    "severity": r["severity"],
                    "source": "cloud_posture",
                },
            )
            counts["cloud_resource"] += 1
            _ = ck
    except Exception:
        pass

    return {
        "ok": True,
        "depth_counts": counts,
        "lab_production": True,
        "full_twin": False,
        "note": (
            "Identity depth from org members/RBAC, asset categories, and cloud posture rows. "
            "Not a full IAM/K8s/cloud twin — confirm edges before high-confidence decisions."
        ),
    }


def graph_depth_status(user_id: str) -> dict[str, Any]:
    """Readiness snapshot for USP #6."""
    from app.knowledge_graph import build_knowledge_graph

    g = build_knowledge_graph(user_id)
    by = (g.get("counts") or {}).get("by_type") or {}
    depth_types = ("user", "permission", "container", "cloud_resource", "data_store")
    present = {t: int(by.get(t) or 0) for t in depth_types}
    return {
        "ok": True,
        "lab_production": True,
        "full_twin": False,
        "depth_types": present,
        "depth_nodes": sum(present.values()),
        "total_nodes": (g.get("counts") or {}).get("nodes"),
        "attack_graph": True,
        "knowledge_graph": True,
        "note": (
            "Lab-production security graph: attack paths + knowledge graph with "
            "user/permission/container/cloud/data depth scaffolds. Full twin still open."
        ),
    }
