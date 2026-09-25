"""Branded SecuraIQ product scanners — Secret / API / Config.

Thin product facades over existing adapters (Gitleaks, Web/ZAP/Nuclei, Checkov).
Lab-production named offerings — not separate engines.
"""

from __future__ import annotations

from typing import Any


PRODUCTS: dict[str, dict[str, Any]] = {
    "secret_scanner": {
        "name": "SecuraIQ Secret Scanner",
        "adapters": ["gitleaks", "trufflehog"],
        "primary": "gitleaks",
        "category": "secrets",
        "import_hint": "POST /api/vulnerabilities/import with Gitleaks JSON",
    },
    "api_scanner": {
        "name": "SecuraIQ API Scanner",
        "adapters": ["zap", "nuclei", "securaiq"],
        "primary": "zap",
        "category": "dast",
        "import_hint": "Built-in web/API DAST via scan engine; optional ZAP/Nuclei",
    },
    "config_scanner": {
        "name": "SecuraIQ Config Scanner",
        "adapters": ["checkov", "trivy"],
        "primary": "checkov",
        "category": "iac",
        "import_hint": "POST /api/vulnerabilities/import with Checkov/Trivy JSON",
    },
    "easm_scanner": {
        "name": "SecuraIQ EASM",
        "adapters": ["securaiq"],
        "primary": "securaiq",
        "category": "easm",
        "import_hint": "POST /api/easm/discover — owned-host DNS + TLS SAN",
    },
}


def _adapter_available(adapter_id: str) -> tuple[bool, str]:
    aid = (adapter_id or "").lower()
    if aid in {"gitleaks", "checkov", "trivy", "trufflehog"}:
        return True, "import adapter shipped"
    try:
        from app.scanners.registry import get_scanner

        sc = get_scanner(aid if aid != "securaiq" else "securaiq")
        ok, detail = sc.available()
        return bool(ok), str(detail)
    except Exception as exc:
        return False, str(exc)[:120]


def product_status(product_id: str) -> dict[str, Any]:
    meta = PRODUCTS.get((product_id or "").strip().lower())
    if not meta:
        raise KeyError(product_id)
    adapters = []
    for aid in meta["adapters"]:
        ok, detail = _adapter_available(aid)
        adapters.append({"id": aid, "available": ok, "detail": detail})
    primary_ok = any(a["id"] == meta["primary"] and a["available"] for a in adapters) or any(
        a["available"] for a in adapters
    )
    return {
        "id": product_id,
        "name": meta["name"],
        "category": meta["category"],
        "lab_production": True,
        "standalone_engine": False,
        "primary_adapter": meta["primary"],
        "adapters": adapters,
        "ready": primary_ok,
        "import_hint": meta["import_hint"],
        "note": (
            f"{meta['name']} is a branded facade over shipped adapters "
            f"({', '.join(meta['adapters'])}) — not a separate binary."
        ),
    }


def catalog() -> dict[str, Any]:
    products = []
    for pid in PRODUCTS:
        try:
            products.append(product_status(pid))
        except Exception as exc:
            products.append({"id": pid, "ok": False, "error": str(exc)[:160]})
    return {
        "ok": True,
        "lab_production": True,
        "products": products,
        "note": (
            "SecuraIQ Secret / API / Config / EASM scanners are branded product surfaces "
            "over existing import + scan-engine + owned-host DNS adapters."
        ),
    }
