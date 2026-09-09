"""CMMC / 32 CFR Part 170 asset-scoping categories ("Secure Enclave" model).

This is a different axis from app.asset_categories (which answers "what kind
of thing is this asset" -- server, endpoint, network, etc). This module
answers "where does this asset sit relative to a CMMC Level 2 assessment
boundary" -- a classification that only matters once an org is actually
scoping a CMMC assessment, and which SecuraIQ cannot infer or verify on its
own. It is always a user-entered, self-reported classification, never a
computed fact -- callers must not present it as verified.

Categories (per the official CMMC scoping guidance):
  - cui_asset:    processes, stores, or transmits CUI. Assessed against all
                  110 NIST SP 800-171 practices.
  - spa:          Security Protection Asset -- provides a security function
                  for the CUI boundary (e.g. MFA gateway, firewall, EDR/SIEM
                  console, endpoint management) without itself touching CUI.
                  Still assessed against all 110 practices.
  - crma:         Contractor Risk Managed Asset -- can access CUI but is
                  managed via policy/procedure to reduce risk. Documented
                  and risk-managed rather than fully assessed.
  - specialized:  Specialized Asset -- IoT, OT, GFE, or test equipment that
                  can't run standard security agents. Documented, not fully
                  assessed.
  - out_of_scope: No CUI or security-function contact at all.
  - "" (unset):   Not yet classified -- the default for every asset. Most
                  orgs using SecuraIQ have no CMMC scope at all, so this is
                  blank until a user opts in.
"""

from __future__ import annotations

from typing import Any

CMMC_SCOPE_ORDER = ("cui_asset", "spa", "crma", "specialized", "out_of_scope")

CMMC_SCOPE_LABELS: dict[str, str] = {
    "": "Not classified",
    "cui_asset": "CUI Asset",
    "spa": "Security Protection Asset (SPA)",
    "crma": "Contractor Risk Managed Asset (CRMA)",
    "specialized": "Specialized Asset",
    "out_of_scope": "Out of scope",
}

CMMC_SCOPE_DESCRIPTIONS: dict[str, str] = {
    "cui_asset": "Processes, stores, or transmits CUI. Assessed against all 110 NIST SP 800-171 practices.",
    "spa": "Provides a security function for the CUI boundary (MFA, firewall, EDR/SIEM, endpoint management). Assessed against all 110 practices even though it never touches CUI.",
    "crma": "Can access CUI but is managed by policy to reduce risk. Documented and risk-managed rather than fully assessed against all 110 practices.",
    "specialized": "IoT, OT, GFE, or test equipment that can't run standard security agents. Documented, not fully assessed.",
    "out_of_scope": "No CUI or security-function contact. Outside the CMMC assessment boundary entirely.",
}

# Assets in these categories carry the full 110-practice assessment burden.
FULL_ASSESSMENT_CATEGORIES = frozenset({"cui_asset", "spa"})


def normalize_cmmc_scope(value: str | None) -> str:
    t = (value or "").strip().lower().replace(" ", "_").replace("-", "_")
    if t in CMMC_SCOPE_LABELS:
        return t
    return ""


def cmmc_scope_label(value: str | None) -> str:
    return CMMC_SCOPE_LABELS.get(normalize_cmmc_scope(value), "Not classified")


def list_cmmc_scope_categories() -> list[dict[str, str]]:
    return [
        {"id": c, "label": CMMC_SCOPE_LABELS[c], "description": CMMC_SCOPE_DESCRIPTIONS[c]}
        for c in CMMC_SCOPE_ORDER
    ]


def scope_breakdown(assets: list[dict[str, Any]]) -> dict[str, int]:
    """Real counts from actual stored asset rows -- never invented."""
    counts: dict[str, int] = {"": 0, **{c: 0 for c in CMMC_SCOPE_ORDER}}
    for a in assets:
        cat = normalize_cmmc_scope(a.get("cmmc_asset_category"))
        counts[cat] = counts.get(cat, 0) + 1
    return {k: v for k, v in counts.items() if v > 0}


# "Regular business" here means the CMMC scoping guidance's own out-of-scope
# category, plus unclassified -- the network the Secure Enclave model is
# built to keep separate from the CUI boundary. crma/specialized are
# deliberately excluded: those categories are how CMMC scoping *allows*
# limited, policy-managed contact with the boundary without full assessment,
# so a connection touching one of those is not, by itself, a violation.
_REGULAR_BUSINESS_CATEGORIES = frozenset({"", "out_of_scope"})


def enclave_boundary_report(
    assets: list[dict[str, Any]], dependencies: list[dict[str, Any]]
) -> dict[str, Any]:
    """Cross-references two pieces of data this product already collects --
    cmmc_asset_category (self-reported CMMC scope) and asset_dependencies
    (declared/inferred connects_to edges) -- to check whether the "Secure
    Enclave" boundary the CMMC scoping guidance describes is actually
    architecturally isolated, or whether a declared connection crosses it.

    This is the honest version of a Secure Enclave diagram: rather than
    drawing a static picture of "enclave" vs. "regular business network",
    it recomputes the same boundary from real asset classifications and
    flags any declared/inferred dependency that crosses it -- a real
    finding, not decoration. Silence (no violations) means "no crossing
    dependency is currently declared", never "the boundary is proven
    clean" -- dependency declarations can be incomplete, so this can't
    detect a crossing nobody told SecuraIQ about.
    """
    by_id = {a.get("id"): a for a in assets if a.get("id")}
    enclave_ids: set[str] = set()
    regular_ids: set[str] = set()
    for a in assets:
        aid = a.get("id")
        if not aid:
            continue
        cat = normalize_cmmc_scope(a.get("cmmc_asset_category"))
        if cat in FULL_ASSESSMENT_CATEGORIES:
            enclave_ids.add(aid)
        elif cat in _REGULAR_BUSINESS_CATEGORIES:
            regular_ids.add(aid)

    violations: list[dict[str, Any]] = []
    for dep in dependencies:
        src, tgt = dep.get("source_asset_id"), dep.get("target_asset_id")
        if not src or not tgt:
            continue
        crosses = (src in enclave_ids and tgt in regular_ids) or (
            tgt in enclave_ids and src in regular_ids
        )
        if not crosses:
            continue
        enclave_side, regular_side = (src, tgt) if src in enclave_ids else (tgt, src)
        violations.append(
            {
                "dependency_id": dep.get("id"),
                "enclave_asset_id": enclave_side,
                "enclave_asset_name": (by_id.get(enclave_side) or {}).get("name") or "",
                "regular_asset_id": regular_side,
                "regular_asset_name": (by_id.get(regular_side) or {}).get("name") or "",
                "relationship": dep.get("relationship") or "connects_to",
                "source": dep.get("source") or "declared",
                "reason": (
                    "A CUI Asset / Security Protection Asset has a "
                    f"{dep.get('source') or 'declared'} {dep.get('relationship') or 'connects_to'} "
                    "connection to an out-of-scope/unclassified asset -- the Secure Enclave "
                    "model requires the boundary to be free of unmediated connections like this. "
                    "Either bring the other asset into scope or remove the connection."
                ),
            }
        )

    return {
        "enclave_asset_count": len(enclave_ids),
        "regular_business_asset_count": len(regular_ids),
        "other_scoped_asset_count": len(by_id) - len(enclave_ids) - len(regular_ids),
        "boundary_violations": violations,
        "boundary_intact": not violations,
        "disclaimer": (
            "cmmc_asset_category and asset dependencies are self-reported/declared data. "
            "No violations shown means none is currently declared, not that the boundary has "
            "been independently verified."
        ),
    }
