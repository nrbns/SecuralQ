"""Known non-FIPS-validated remote-access tooling detector.

CMMC Level 2 controls AC.L2-3.1.13 (cryptographic protection of remote
access sessions) and SC.L2-3.13.11 (FIPS-validated cryptography for CUI)
are failed outright by using certain popular remote-access/RMM products
that do not offer FIPS-140-validated cryptographic modules. This module
flags known-risky products BY NAME when they show up in SecuraIQ's real
software inventory (app.software.models software_products /
software_installations) -- it does not (and cannot) verify whether FIPS
mode is actually configured on any product, including ones not on this
list. A "pass" here means "no known-risky product detected by name", not
"FIPS-validated cryptography is confirmed in use".

The risky/safe lists below are deliberately short and sourced from a
specific named set of products called out as non-FIPS vs FIPS-friendly in
CMMC consulting guidance reviewed for this feature. They are illustrative,
not an exhaustive or authoritative list of every FIPS/non-FIPS remote
access tool on the market -- extend them only with products you can
actually confirm, never by guessing.
"""

from __future__ import annotations

from typing import Any

from app.db import get_conn

# Products known NOT to offer FIPS-140-validated cryptography for remote
# access / remote support -- using one of these for CUI remote access fails
# AC.L2-3.1.13 / SC.L2-3.13.11 outright (5-point controls, no POA&M allowed).
NON_FIPS_REMOTE_ACCESS_TOOLS: dict[str, str] = {
    "splashtop": "Splashtop remote access is not FIPS-140-validated.",
    "screenconnect": "ScreenConnect (ConnectWise Control) is not FIPS-140-validated.",
    "connectwise control": "ScreenConnect (ConnectWise Control) is not FIPS-140-validated.",
    "teamviewer": "TeamViewer is not FIPS-140-validated.",
}

# Products called out as FIPS-friendly / FedRAMP-authorized alternatives --
# detecting one of these is a positive signal, not a compliance guarantee
# (FIPS mode still has to actually be enabled/configured).
FIPS_FRIENDLY_REMOTE_ACCESS_TOOLS: dict[str, str] = {
    "preveil": "PreVeil is built around FIPS-validated cryptography.",
    "ninjaone": "NinjaOne offers a FedRAMP-authorized tier.",
    "duo": "Cisco Duo Federal is FedRAMP-authorized.",
    "huntress": "Huntress offers a Sensitive Data Mode for regulated environments.",
}


def _installed_products(user_id: str) -> list[dict[str, Any]]:
    rows = get_conn().execute(
        """
        SELECT p.name AS product_name, p.normalized_name AS normalized_name,
               i.asset_id AS asset_id, i.asset_name AS asset_name
        FROM software_installations i
        JOIN software_products p ON p.id = i.software_product_id
        WHERE i.user_id = ?
        """,
        (user_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def scan_remote_access_tooling(user_id: str) -> dict[str, Any]:
    """Real, computed result -- never fabricated. Empty findings if the org
    has no software inventory at all (status 'unknown', not 'pass')."""
    try:
        installs = _installed_products(user_id)
    except Exception:
        installs = []

    if not installs:
        return {
            "status": "unknown",
            "summary": "No software inventory recorded -- cannot check for known non-FIPS remote-access tools.",
            "risky_findings": [],
            "fips_friendly_findings": [],
            "checked_products": sorted(NON_FIPS_REMOTE_ACCESS_TOOLS),
        }

    risky: list[dict[str, Any]] = []
    friendly: list[dict[str, Any]] = []
    seen_risky_keys: set[tuple[str, str]] = set()
    seen_friendly_keys: set[tuple[str, str]] = set()
    for row in installs:
        blob = f"{row.get('normalized_name') or ''} {row.get('product_name') or ''}".lower()
        for needle, reason in NON_FIPS_REMOTE_ACCESS_TOOLS.items():
            if needle in blob:
                key = (needle, row.get("asset_id") or row.get("asset_name") or "")
                if key in seen_risky_keys:
                    continue
                seen_risky_keys.add(key)
                risky.append({
                    "product": row.get("product_name"),
                    "asset_id": row.get("asset_id"),
                    "asset_name": row.get("asset_name"),
                    "reason": reason,
                })
        for needle, reason in FIPS_FRIENDLY_REMOTE_ACCESS_TOOLS.items():
            if needle in blob:
                key = (needle, row.get("asset_id") or row.get("asset_name") or "")
                if key in seen_friendly_keys:
                    continue
                seen_friendly_keys.add(key)
                friendly.append({
                    "product": row.get("product_name"),
                    "asset_id": row.get("asset_id"),
                    "asset_name": row.get("asset_name"),
                    "reason": reason,
                })

    if risky:
        status = "fail"
        summary = (
            f"{len(risky)} installation(s) of a known non-FIPS-validated remote-access tool found "
            f"({', '.join(sorted({r['product'] for r in risky}))}) -- fails AC.L2-3.1.13 / SC.L2-3.13.11 "
            "if used for CUI remote access."
        )
    else:
        status = "pass"
        summary = (
            f"No known non-FIPS-validated remote-access tool detected across {len(installs)} tracked "
            f"installation(s) (checked for: {', '.join(sorted(NON_FIPS_REMOTE_ACCESS_TOOLS))}). This does not "
            "confirm FIPS-validated cryptography is actually configured on whatever remote-access tool is in "
            "use -- only that no known-risky product was found by name."
        )

    return {
        "status": status,
        "summary": summary,
        "risky_findings": risky,
        "fips_friendly_findings": friendly,
        "checked_products": sorted(NON_FIPS_REMOTE_ACCESS_TOOLS),
    }
