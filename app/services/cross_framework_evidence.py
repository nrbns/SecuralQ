"""Cross-framework evidence write-through via canonical control registry.

When evidence is linked to a control, optionally propagate to sibling controls
mapped under the same canonical control. Explicit and tested — not fuzzy AI.
"""

from __future__ import annotations

from typing import Any


def sibling_controls_via_canonical(
    framework_id: str,
    control_id: str,
) -> list[dict[str, str]]:
    """Return other (framework_id, control_id) pairs sharing a canonical control."""
    from app.services.canonical_controls import canonical_controls_for

    siblings: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    src_fid = (framework_id or "").strip()
    src_cid = (control_id or "").strip().upper()
    for cc in canonical_controls_for(src_fid, src_cid):
        frameworks = cc.get("frameworks") or {}
        for fw, ids in frameworks.items():
            for cid in ids or []:
                key = (str(fw), str(cid).strip().upper())
                if key in seen:
                    continue
                if key == (src_fid, src_cid):
                    continue
                seen.add(key)
                siblings.append(
                    {
                        "framework_id": key[0],
                        "control_id": key[1],
                        "canonical_id": str(cc.get("id") or ""),
                    }
                )
    return siblings


def propagate_evidence_to_canonical_siblings(
    user_id: str,
    evidence_id: str,
    *,
    framework_id: str,
    control_id: str,
    role: str = "supports",
    org_id: str | None = None,
    max_links: int = 40,
) -> dict[str, Any]:
    """Link evidence to sibling controls under the same canonical mapping.

    Role is forced to ``supports`` for siblings (never auto-``satisfies``)
    so a declared doc for one framework cannot alone PASS another.
    """
    from app.evidence_spine.mapping import link_evidence_to_control

    siblings = sibling_controls_via_canonical(framework_id, control_id)[:max_links]
    linked: list[dict[str, Any]] = []
    errors: list[str] = []
    sibling_role = "supports" if role == "satisfies" else (role or "supports")
    for sib in siblings:
        try:
            row = link_evidence_to_control(
                user_id,
                evidence_id,
                control_id=sib["control_id"],
                framework_id=sib["framework_id"],
                role=sibling_role,
                org_id=org_id,
                propagate_canonical=False,  # prevent recursion
            )
            linked.append(
                {
                    "framework_id": sib["framework_id"],
                    "control_id": sib["control_id"],
                    "canonical_id": sib.get("canonical_id"),
                    "map_id": row.get("id"),
                    "role": sibling_role,
                }
            )
        except Exception as exc:
            errors.append(f"{sib['framework_id']}:{sib['control_id']}: {exc}")
    return {
        "ok": True,
        "source": {"framework_id": framework_id, "control_id": control_id},
        "siblings_considered": len(siblings),
        "linked": linked,
        "errors": errors[:20],
        "note": (
            "Sibling links use role=supports (never auto-satisfies). "
            "One implementation can inform multiple frameworks; each still "
            "needs its own assessment determination."
        ),
    }
