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
