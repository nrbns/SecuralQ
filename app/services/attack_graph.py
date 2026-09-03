"""Attack-path graph — the "why is this asset actually dangerous" layer on
top of the risk engine.

This is deliberately a narrow, computed-on-demand graph over data that
already exists in the product, not a persisted graph database and not a
fabricated one. Every node and edge below traces back to a real row:

    Asset            <- assets
    Software         <- software_installations / software_products
    Vulnerability     <- the same scored open findings risk_priority.py uses
                          (_scored_open_items), so a vuln's score here is
                          always identical to its score everywhere else
    Internet exposure <- app.asset_categories.is_internet_exposed_category
    Application       <- NOT a separate row. An asset whose category
                          normalizes to "web" is tagged node_type="application"
                          instead of getting a fabricated satellite node —
                          there is no distinct Application entity in this
                          product's data model, so pretending one exists
                          would be inventing a node, not deriving one.
    Business Criticality <- a node ATTRIBUTE (asset.business_criticality or
                          .criticality), not a satellite node — same reasoning.
    Identity          <- ONLY emitted when a user has filled in
                          asset.service_accounts. There is no IAM/AD/Entra/
                          LDAP/Okta/IAM data source anywhere in this product
                          yet. Every Identity node/edge is source="declared",
                          confidence=0.0, verified=False — never presented
                          as fact. Adding a real IAM connector later would
                          let this move declared -> observed -> verified.
    connects_to edges <- from asset_dependencies: a user's own declaration
                          or confirmation of a suggestion (source="declared"
                          or "confirmed", confidence=1.0, verified=True), or
                          a same-tenant heuristic guess (source="inferred",
                          confidence 0.3, verified=False — an internet-
                          exposed asset paired with a database-categorized
                          asset, see _infer_dependencies). No network flow
                          capture or app-architecture input exists yet, so
                          inferred edges are guesses and are always labeled
                          as such — never asserted as fact.

Every edge carries a permanent evidence contract (see _edge_meta): source,
confidence, verified, first_seen, last_seen, evidence. `verified` is always
derived from `source` (declared/confirmed = a human vouched for it,
inferred = a guess, however confident) rather than stored separately, so
it can never drift out of sync with what actually backs the edge. Any AI
narration built on this graph should read `verified` before asserting a
relationship as fact — e.g. "SecuraIQ inferred a likely connection... with
30% confidence... confirm it to use it for high-confidence decisions",
never "X definitely connects to Y" for an unverified edge.

Attack path risk = vuln_risk x exposure_confidence x business_impact x
path_length_factor. See _compute_path_risk for the exact formula.
"""

from __future__ import annotations

from typing import Any

from app.asset_categories import is_internet_exposed_category, normalize_asset_category
from app.db import get_conn, now
from app.enterprise import list_asset_dependencies, list_assets

_DB_CATEGORY = "database"
_WEB_CATEGORY = "web"
_INFERRED_CONFIDENCE = 0.3
_MAX_ASSETS_FOR_INFERENCE = 300  # guardrail against O(n^2) inference on huge inventories
_MAX_RAW_PATHS = 3000  # guardrail against runaway recursion in dense declared-dependency graphs


def _is_database_asset(asset: dict[str, Any]) -> bool:
    return normalize_asset_category(asset.get("asset_type")) == _DB_CATEGORY


def _edge_meta(*, source: str, confidence: float, evidence: str, first_seen: float, last_seen: float) -> dict[str, Any]:
    """The evidence contract every edge in this graph carries, permanently:
    source, confidence, verified, first_seen, last_seen, evidence. `verified`
    is derived from `source` rather than stored separately — "declared" and
    "confirmed" are both a human vouching for the relationship (verified),
    "inferred" never is, no matter how high its confidence gets. This is
    what lets the UI (and any future AI narration) say "SecuraIQ inferred a
    likely connection... confirm to use it for high-confidence decisions"
    instead of quietly asserting a guess as fact."""
    return {
        "source": source,
        "confidence": confidence,
        "verified": source in ("declared", "confirmed"),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "evidence": evidence,
    }


def _split_accounts(raw: str) -> list[str]:
    parts = [p.strip() for chunk in raw.split("\n") for p in chunk.split(",")]
    return [p for p in parts if p]


def _installed_products_for_asset(user_id: str, asset_id: str) -> list[dict[str, Any]]:
    c = get_conn()
    rows = c.execute(
        """
        SELECT i.software_product_id AS product_id, p.name AS product_name, i.version AS version
        FROM software_installations i
        JOIN software_products p ON p.id = i.software_product_id
        WHERE i.user_id = ? AND i.asset_id = ?
        """,
        (user_id, asset_id),
    ).fetchall()
    return [dict(r) for r in rows]


def _advisory_cves_for_products(user_id: str, product_ids: list[str]) -> dict[str, set[str]]:
    """product_id -> set of upper-cased CVE ids with a known advisory."""
    if not product_ids:
        return {}
    c = get_conn()
    placeholders = ",".join("?" for _ in product_ids)
    rows = c.execute(
        f"SELECT software_product_id, cve_id FROM software_advisories "
        f"WHERE user_id = ? AND software_product_id IN ({placeholders}) AND cve_id != ''",
        (user_id, *product_ids),
    ).fetchall()
    out: dict[str, set[str]] = {}
    for r in rows:
        d = dict(r)
        out.setdefault(d["software_product_id"], set()).add((d["cve_id"] or "").strip().upper())
    return out


def _infer_dependencies(assets: list[dict[str, Any]], declared_pairs: set[tuple[str, str]], *, computed_at: float) -> list[dict[str, Any]]:
    """A low-confidence guess, never a fact: pair every internet-exposed
    asset with every database-categorized asset in the same tenant that
    doesn't already have a declared (or confirmed) edge between them.
    Capped to avoid O(n^2) blowup on large inventories — beyond that size,
    declared edges (or a smaller engagement scope) are required.

    Not persisted — recomputed fresh on every graph build, so its
    first_seen/last_seen are both "now": an inference has no history, only
    a moment it was last suggested."""
    if len(assets) > _MAX_ASSETS_FOR_INFERENCE:
        return []
    exposed = [a for a in assets if is_internet_exposed_category(a.get("asset_type"))]
    databases = [a for a in assets if _is_database_asset(a)]
    out: list[dict[str, Any]] = []
    for e in exposed:
        for d in databases:
            if e["id"] == d["id"] or (e["id"], d["id"]) in declared_pairs:
                continue
            out.append(
                {
                    "from": e["id"],
                    "to": d["id"],
                    "type": "connects_to",
                    **_edge_meta(
                        source="inferred",
                        confidence=_INFERRED_CONFIDENCE,
                        evidence="Internet-exposed asset paired with a database-categorized asset in the same tenant, with no declared or confirmed link — a security-inference heuristic, not an observation.",
                        first_seen=computed_at,
                        last_seen=computed_at,
                    ),
                }
            )
    return out


def build_graph(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    """Build the full node/edge list. Nodes and edges are plain dicts (not a
    graph-library object) — this is a "scoped-down security graph" in the
    same spirit as risk_priority.py's docstring: real joins over existing
    tables, not a new subsystem."""
    try:
        from app.software.models import ensure_schema as ensure_software_schema

        ensure_software_schema()
    except Exception:
        pass

    from app.services.risk_priority import _scored_open_items

    assets = list_assets(user_id, engagement_id, org_id=org_id)
    assets_by_id = {a["id"]: a for a in assets if a.get("id")}
    scored_vulns = _scored_open_items(user_id, org_id=org_id, engagement_id=engagement_id)
    vulns_by_asset: dict[str, list[dict[str, Any]]] = {}
    for v in scored_vulns:
        if v.get("asset_id"):
            vulns_by_asset.setdefault(v["asset_id"], []).append(v)

    declared = list_asset_dependencies(user_id, engagement_id=engagement_id, org_id=org_id)

    computed_at = now()
    nodes: list[dict[str, Any]] = [{"id": "internet", "type": "internet", "label": "Internet"}]
    edges: list[dict[str, Any]] = []

    for asset in assets:
        aid = asset["id"]
        is_web = normalize_asset_category(asset.get("asset_type")) == _WEB_CATEGORY
        exposed = is_internet_exposed_category(asset.get("asset_type"))
        criticality = asset.get("criticality") or "medium"
        business_criticality = (asset.get("business_criticality") or "").strip() or criticality
        nodes.append(
            {
                "id": aid,
                "type": "application" if is_web else "asset",
                "label": asset.get("name") or aid,
                "asset_type": asset.get("asset_type") or "",
                "criticality": criticality,
                "business_criticality": business_criticality,
                "exposed": exposed,
            }
        )
        if exposed:
            edges.append(
                {
                    "from": "internet",
                    "to": aid,
                    "type": "exposed_to",
                    **_edge_meta(
                        source="derived",
                        confidence=1.0,
                        evidence=f"Asset category '{asset.get('asset_type') or 'other'}' is treated as internet-facing.",
                        first_seen=computed_at,
                        last_seen=computed_at,
                    ),
                }
            )

        products = _installed_products_for_asset(user_id, aid)
        product_ids = [p["product_id"] for p in products]
        advisories = _advisory_cves_for_products(user_id, product_ids)
        for p in products:
            sw_node_id = f"sw:{p['product_id']}:{aid}"
            nodes.append(
                {
                    "id": sw_node_id,
                    "type": "software",
                    "label": f"{p['product_name']} {p['version']}".strip(),
                    "asset_id": aid,
                }
            )
            edges.append(
                {
                    "from": aid,
                    "to": sw_node_id,
                    "type": "runs",
                    **_edge_meta(
                        source="derived",
                        confidence=1.0,
                        evidence="Software installation record (agent inventory or scan).",
                        first_seen=computed_at,
                        last_seen=computed_at,
                    ),
                }
            )

        for v in vulns_by_asset.get(aid, []):
            vuln_node_id = f"vuln:{v['vuln_id']}"
            nodes.append(
                {
                    "id": vuln_node_id,
                    "type": "vulnerability",
                    "vuln_id": v["vuln_id"],
                    "label": v.get("cve") or v.get("title") or v["vuln_id"],
                    "cve": v.get("cve") or "",
                    "severity": v["severity"],
                    "score": v["score"],
                    "band": v["band"],
                    "kev": v["kev"],
                }
            )
            attached_to_software = False
            cve_upper = (v.get("cve") or "").upper()
            if cve_upper:
                for p in products:
                    if cve_upper in advisories.get(p["product_id"], set()):
                        sw_node_id = f"sw:{p['product_id']}:{aid}"
                        edges.append(
                            {
                                "from": sw_node_id,
                                "to": vuln_node_id,
                                "type": "affected_by",
                                **_edge_meta(
                                    source="derived",
                                    confidence=1.0,
                                    evidence=f"Advisory match: installed {p['product_name']} {p['version']} against a known {cve_upper} advisory.",
                                    first_seen=computed_at,
                                    last_seen=computed_at,
                                ),
                            }
                        )
                        attached_to_software = True
            if not attached_to_software:
                edges.append(
                    {
                        "from": aid,
                        "to": vuln_node_id,
                        "type": "affected_by",
                        **_edge_meta(
                            source="derived",
                            confidence=1.0,
                            evidence="Open finding recorded directly against this asset (no matching software installation to attach it to).",
                            first_seen=computed_at,
                            last_seen=computed_at,
                        ),
                    }
                )

        service_accounts = (asset.get("service_accounts") or "").strip()
        for idx, account_name in enumerate(_split_accounts(service_accounts)):
            identity_id = f"identity:{aid}:{idx}"
            nodes.append(
                {
                    "id": identity_id,
                    "type": "identity",
                    "label": account_name,
                    "source": "declared",
                    "confidence": 0.0,
                    "verified": False,
                    "verification_status": "unverified",
                }
            )
            edges.append(
                {
                    "from": aid,
                    "to": identity_id,
                    "type": "has_identity",
                    **_edge_meta(
                        source="declared",
                        confidence=0.0,
                        evidence="User-supplied service account name — no AD/Entra/LDAP/Okta/IAM verification performed.",
                        first_seen=computed_at,
                        last_seen=computed_at,
                    ),
                    "verification_status": "unverified",
                }
            )

    declared_pairs: set[tuple[str, str]] = set()
    for d in declared:
        src, tgt = d.get("source_asset_id"), d.get("target_asset_id")
        if src in assets_by_id and tgt in assets_by_id:
            row_source = d.get("source") or "declared"
            evidence = d.get("notes") or (
                "Administrator declaration." if row_source in ("declared", "confirmed") else "Security inference."
            )
            if row_source == "confirmed":
                evidence = f"Confirmed by an administrator (originally an automated suggestion). {evidence}".strip()
            edges.append(
                {
                    "from": src,
                    "to": tgt,
                    "type": d.get("relationship") or "connects_to",
                    **_edge_meta(
                        source=row_source,
                        confidence=float(d.get("confidence", 1.0)),
                        evidence=evidence,
                        first_seen=float(d.get("created_at") or computed_at),
                        last_seen=float(d.get("updated_at") or computed_at),
                    ),
                    "notes": d.get("notes") or "",
                }
            )
            declared_pairs.add((src, tgt))

    edges.extend(_infer_dependencies(assets, declared_pairs, computed_at=computed_at))

    return {"generated_at": computed_at, "nodes": nodes, "edges": edges, "total_assets": len(assets)}


def _compute_path_risk(path_edges: list[dict[str, Any]], target_node: dict[str, Any], target_vulns: list[dict[str, Any]]) -> dict[str, Any]:
    from app.services.risk import _CRITICALITY, _band

    worst = max(target_vulns, key=lambda v: v.get("score", 0)) if target_vulns else None
    vuln_risk_n = (float(worst.get("score", 0)) / 100.0) if worst else 0.0

    path_confidence = 1.0
    for e in path_edges:
        try:
            path_confidence *= float(e.get("confidence", 1.0))
        except (TypeError, ValueError):
            pass

    biz = target_node.get("business_criticality") or target_node.get("criticality") or "medium"
    business_impact_n = _CRITICALITY.get(str(biz).lower(), 0.65)

    hops = max(1, len(path_edges))
    path_length_factor = 1.0 / (1.0 + 0.15 * (hops - 1))

    raw = vuln_risk_n * path_confidence * business_impact_n * path_length_factor
    score = round(raw * 100, 1)
    return {
        "risk_score": score,
        "band": _band(score),
        "worst_vulnerability": worst,
        "hops": hops,
        "path_confidence": round(path_confidence, 3),
    }


def compute_attack_paths(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    max_depth: int = 4,
    limit: int = 25,
) -> dict[str, Any]:
    """Every returned path starts at "Internet" and ends at a reachable
    asset — "why is this asset actually dangerous" made concrete as a
    route, not just a score.

    Vulnerabilities accumulate ALONG the whole route, not just at the
    endpoint: a path Internet -> WEB-01 -> DB-01 where WEB-01 has an Apache
    RCE and DB-01 has no vulnerability of its own is still reported — the
    Apache RCE is what makes reaching DB-01 dangerous in the first place.
    Requiring a vulnerability strictly on the terminal node would miss
    exactly the "this vulnerability creates a path to a business-critical
    database" story this feature exists to tell. worst_vulnerability is the
    highest-scored vulnerability found anywhere along the path; business
    impact is still the TERMINAL asset's criticality — what's actually
    being reached. Sorted by attack_path_risk descending."""
    graph = build_graph(user_id, org_id=org_id, engagement_id=engagement_id)
    nodes_by_id = {n["id"]: n for n in graph["nodes"]}

    adjacency: dict[str, list[dict[str, Any]]] = {}
    for e in graph["edges"]:
        if e["type"] in ("exposed_to", "connects_to"):
            adjacency.setdefault(e["from"], []).append(e)

    vulns_by_asset_node: dict[str, list[dict[str, Any]]] = {}
    for e in graph["edges"]:
        if e["type"] != "affected_by":
            continue
        source_id = e["from"]
        asset_id = source_id.split(":")[-1] if source_id.startswith("sw:") else source_id
        vulns_by_asset_node.setdefault(asset_id, []).append(nodes_by_id[e["to"]])

    paths: list[dict[str, Any]] = []
    raw_path_count = 0

    def _walk(
        current_id: str,
        path_node_ids: list[str],
        path_edges: list[dict[str, Any]],
        visited: set[str],
        cumulative_vulns: dict[str, dict[str, Any]],
    ) -> None:
        nonlocal raw_path_count
        if raw_path_count > _MAX_RAW_PATHS:
            return
        if len(path_node_ids) - 1 > max_depth:
            return

        if current_id != "internet":
            cumulative_vulns = dict(cumulative_vulns)
            for v in vulns_by_asset_node.get(current_id, []):
                cumulative_vulns[v["vuln_id"]] = v
            if cumulative_vulns:
                raw_path_count += 1
                target_node = nodes_by_id[current_id]
                vulns_on_path = list(cumulative_vulns.values())
                risk = _compute_path_risk(path_edges, target_node, vulns_on_path)
                paths.append(
                    {
                        "nodes": [nodes_by_id[n] for n in path_node_ids],
                        "edges": list(path_edges),
                        "target_asset": target_node,
                        "vulnerabilities": vulns_on_path,
                        **risk,
                    }
                )

        for edge in adjacency.get(current_id, []):
            nxt = edge["to"]
            if nxt in visited or raw_path_count > _MAX_RAW_PATHS:
                continue
            _walk(nxt, path_node_ids + [nxt], path_edges + [edge], visited | {nxt}, cumulative_vulns)

    _walk("internet", ["internet"], [], {"internet"}, {})
    paths.sort(key=lambda p: p["risk_score"], reverse=True)

    return {
        "generated_at": graph["generated_at"],
        "total_paths": len(paths),
        "paths": paths[: max(1, min(limit, 200))],
    }


def attack_paths_disrupted_by_group(
    user_id: str,
    vuln_id_groups: dict[str, set[str]],
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
) -> dict[str, dict[str, int]]:
    """For the Risk Reduction Simulator: given the simulator's own grouping
    (group_key -> set of vuln_id), how many currently-computed attack paths
    include a vulnerability from that group, and how many of those reach a
    business-critical target? Computes the attack-path list ONCE, not once
    per group, since it can be the expensive part."""
    result = compute_attack_paths(user_id, org_id=org_id, engagement_id=engagement_id, max_depth=6, limit=1000)
    out = {key: {"attack_paths_disrupted": 0, "business_critical_paths_disrupted": 0} for key in vuln_id_groups}
    for path in result["paths"]:
        path_vuln_ids = {v.get("vuln_id") for v in path.get("vulnerabilities", []) if v.get("vuln_id")}
        if not path_vuln_ids:
            continue
        target = path.get("target_asset") or {}
        biz = str(target.get("business_criticality") or target.get("criticality") or "medium").lower()
        is_business_critical = biz in ("critical", "high")
        for key, ids in vuln_id_groups.items():
            if path_vuln_ids & ids:
                out[key]["attack_paths_disrupted"] += 1
                if is_business_critical:
                    out[key]["business_critical_paths_disrupted"] += 1
    return out
