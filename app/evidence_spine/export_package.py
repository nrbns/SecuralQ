"""Evidence export package — vault hashes + audit chain tip. Not a court filing."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def build_export_package(user_id: str, *, limit: int = 40) -> dict[str, Any]:
    from app.audit_chain import verify_chain
    from app.evidence_spine.legal_hold import list_legal_holds
    from app.evidence_spine.vault import list_vault

    items = []
    try:
        raw = list_vault(user_id, limit=limit)
        for it in (raw or [])[:limit]:
            if not isinstance(it, dict):
                continue
            items.append(
                {
                    "vault_id": it.get("id") or it.get("vault_id"),
                    "evidence_id": it.get("current_evidence_id") or it.get("evidence_id"),
                    "title": it.get("title"),
                    "content_hash": it.get("content_hash") or it.get("sha256") or "",
                    "review_status": it.get("review_status"),
                }
            )
    except Exception:
        items = []
    chain = verify_chain(limit=2_000)
    holds = list_legal_holds(user_id)
    manifest = {
        "user_id": user_id,
        "items": items,
        "audit": {"ok": bool(chain.get("ok")), "checked": chain.get("checked")},
        "holds": (holds.get("holds") or [])[:20],
    }
    blob = json.dumps(manifest, sort_keys=True, default=str).encode("utf-8")
    return {
        "ok": True,
        "package_hash": hashlib.sha256(blob).hexdigest(),
        "item_count": len(items),
        "audit_chain_ok": bool(chain.get("ok")),
        "legal_holds": len(manifest["holds"]),
        "manifest": manifest,
        "disclaimer": "Lab export of stored hashes + chain tip. Not a legal production.",
    }


def compare_vault_items(user_id: str, left_id: str, right_id: str) -> dict[str, Any]:
    from app.evidence_spine.vault import get_vault_item

    a = get_vault_item(user_id, left_id) or {}
    b = get_vault_item(user_id, right_id) or {}
    ha = str(a.get("content_hash") or a.get("sha256") or "")
    hb = str(b.get("content_hash") or b.get("sha256") or "")
    return {
        "ok": True,
        "left": {"id": left_id, "hash": ha, "title": a.get("title")},
        "right": {"id": right_id, "hash": hb, "title": b.get("title")},
        "same_hash": bool(ha and ha == hb),
        "note": "Hash compare only — not a redline of document text.",
    }
