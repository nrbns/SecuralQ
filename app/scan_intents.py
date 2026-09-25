"""One scan experience — product intents hide engine names."""

from __future__ import annotations

from typing import Any

# Engines stay behind the intent. Nmap/Nuclei/ZAP are adapters, not nav items.
INTENTS: dict[str, dict[str, Any]] = {
    "quick": {
        "label": "Quick Scan",
        "kind": "scan",
        "scanner": "securaiq",
        "profile": "discovery",
    },
    "full": {
        "label": "Full Assessment",
        "kind": "scan",
        "scanner": "securaiq",
        "profile": "full",
    },
    "easm": {
        "label": "External Attack Surface",
        "kind": "discover",
        "scanner": "easm",
        "profile": "discovery",
        "note": "Owned-host EASM discover — not a third-party ASM feed.",
    },
    "internal": {
        "label": "Internal Network",
        "kind": "scan",
        "scanner": "securaiq",
        "profile": "discovery",
    },
    "web": {
        "label": "Web Application",
        "kind": "scan",
        "scanner": "zap",
        "profile": "web",
    },
    "api": {
        "label": "API",
        "kind": "scan",
        "scanner": "zap",
        "profile": "web",
    },
    "cloud": {
        "label": "Cloud",
        "kind": "scan",
        "scanner": "securaiq",
        "profile": "discovery",
        "note": "Uses the built-in engine against owned cloud hostnames — not a CSPM connector.",
    },
    "endpoint": {
        "label": "Endpoint",
        "kind": "agent",
        "scanner": "agent",
        "profile": "discovery",
        "note": "Endpoint posture comes from enrolled agents, not Nmap.",
    },
    "compliance": {
        "label": "Compliance",
        "kind": "controls",
        "scanner": "controls",
        "profile": "discovery",
        "note": "Live control last-results — not a certification scan.",
    },
}


def list_scan_intents() -> dict[str, Any]:
    return {
        "ok": True,
        "intents": [{"id": k, **v} for k, v in INTENTS.items()],
        "note": "Engines stay behind the intent. Nmap/Nuclei/ZAP are adapters, not nav items.",
    }


def resolve_scan_intent(intent_id: str) -> dict[str, Any]:
    key = (intent_id or "").strip().lower()
    meta = INTENTS.get(key)
    if not meta:
        raise KeyError(intent_id)
    return {"ok": True, "id": key, **meta}
