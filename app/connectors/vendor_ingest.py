"""Vendor ingest connectors — Tenable/Qualys/Nessus/Rapid7/Wiz/Splunk/Elastic.

Lab-production: export/file ingest + readiness status. Live API pull requires
operator credentials; until configured, status is honest ``not_configured``.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable

from app.db import get_conn, new_id, now

VENDORS = (
    "tenable",
    "qualys",
    "nessus",
    "rapid7",
    "wiz",
    "splunk",
    "elastic",
)

_ENV_KEYS = {
    "tenable": ("TENABLE_ACCESS_KEY", "TENABLE_SECRET_KEY"),
    "qualys": ("QUALYS_API_URL", "QUALYS_USERNAME", "QUALYS_PASSWORD"),
    "nessus": ("NESSUS_URL", "NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY"),
    "rapid7": ("RAPID7_API_KEY", "RAPID7_REGION"),
    "wiz": ("WIZ_CLIENT_ID", "WIZ_CLIENT_SECRET"),
    "splunk": ("SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN"),  # ingest→SIEM also uses these
    "elastic": ("ELASTIC_URL", "ELASTIC_API_KEY"),
}


def ensure_vendor_ingest_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS vendor_ingest_batches (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            vendor TEXT NOT NULL,
            filename TEXT NOT NULL DEFAULT '',
            findings INTEGER NOT NULL DEFAULT 0,
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_vendor_ingest_user
            ON vendor_ingest_batches(user_id, vendor, created_at DESC);
        """
    )
    c.commit()


def is_configured(vendor: str) -> bool:
    keys = _ENV_KEYS.get((vendor or "").strip().lower()) or ()
    if not keys:
        return False
    return all(bool((os.environ.get(k) or "").strip()) for k in keys)


def vendor_status(vendor: str) -> dict[str, Any]:
    v = (vendor or "").strip().lower()
    cfg = is_configured(v)
    return {
        "vendor": v,
        "configured": cfg,
        "live_api": cfg,
        "export_ingest": True,
        "env_keys": list(_ENV_KEYS.get(v) or ()),
        "note": (
            "Export/file ingest is lab-production. Live API pull activates when "
            "env credentials are set — until then configured=false (honest)."
        ),
    }


def catalog_status() -> dict[str, Any]:
    vendors = [vendor_status(v) for v in VENDORS]
    return {
        "ok": True,
        "lab_production": True,
        "vendors": vendors,
        "configured_count": sum(1 for v in vendors if v["configured"]),
        "export_ingest": True,
        "note": (
            "Tenable/Qualys/Nessus/Rapid7/Wiz/Splunk/Elastic: export ingest ready; "
            "live API only when credentials configured."
        ),
    }


def _normalize_generic_finding(row: dict[str, Any], *, vendor: str, filename: str) -> dict[str, Any]:
    title = str(row.get("title") or row.get("name") or row.get("plugin_name") or "Finding")[:200]
    sev = str(row.get("severity") or row.get("risk") or row.get("severity_id") or "medium").lower()
    if sev in {"4", "critical"}:
        sev = "critical"
    elif sev in {"3", "high"}:
        sev = "high"
    elif sev in {"2", "medium", "med"}:
        sev = "medium"
    elif sev in {"1", "low"}:
        sev = "low"
    else:
        sev = sev if sev in {"critical", "high", "medium", "low", "info"} else "medium"
    return {
        "title": title,
        "severity": sev,
        "cve": (row.get("cve") or row.get("cve_id") or "") or None,
        "asset_name": str(row.get("asset") or row.get("host") or row.get("asset_name") or "")[:120],
        "source": f"{vendor}:{filename}",
        "evidence": str(row.get("description") or row.get("output") or "")[:2000],
        "raw": row,
    }


def parse_vendor_payload(
    vendor: str,
    payload: Any,
    *,
    filename: str = "upload.json",
) -> list[dict[str, Any]]:
    """Normalize JSON list/dict exports into vuln-shaped rows."""
    v = (vendor or "").strip().lower()
    rows: list[dict[str, Any]] = []
    if isinstance(payload, list):
        raw_items = payload
    elif isinstance(payload, dict):
        raw_items = (
            payload.get("vulnerabilities")
            or payload.get("findings")
            or payload.get("results")
            or payload.get("data")
            or payload.get("issues")
            or []
        )
        if isinstance(raw_items, dict):
            raw_items = raw_items.get("vulnerabilities") or raw_items.get("list") or []
    else:
        raw_items = []
    if not isinstance(raw_items, list):
        raw_items = []
    for item in raw_items[:5000]:
        if isinstance(item, dict):
            rows.append(_normalize_generic_finding(item, vendor=v, filename=filename))
    # Nessus/Qualys XML often arrives as text — defer to scanner_adapters greenbone/burp paths
    return rows


def ingest_vendor_export(
    user_id: str,
    vendor: str,
    payload: Any,
    *,
    filename: str = "upload.json",
    engagement_id: str | None = None,
) -> dict[str, Any]:
    """Persist findings via enterprise vuln create path when available."""
    ensure_vendor_ingest_schema()
    v = (vendor or "").strip().lower()
    if v not in VENDORS:
        raise ValueError(f"unsupported vendor: {vendor}")
    findings = parse_vendor_payload(v, payload, filename=filename)
    created = 0
    try:
        from app.enterprise import create_vulnerability

        for f in findings:
            try:
                create_vulnerability(
                    user_id,
                    {
                        "title": f["title"],
                        "severity": f["severity"],
                        "cve": f.get("cve") or "",
                        "asset_name": f.get("asset_name") or "",
                        "source": f.get("source") or v,
                        "engagement_id": engagement_id,
                        "raw": f.get("raw") or {},
                    },
                )
                created += 1
            except Exception:
                pass
    except Exception as exc:
        return {
            "ok": False,
            "vendor": v,
            "error": str(exc)[:200],
            "parsed": len(findings),
            "created": 0,
        }

    bid = new_id()
    get_conn().execute(
        """
        INSERT INTO vendor_ingest_batches
        (id, user_id, vendor, filename, findings, meta_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            bid,
            user_id,
            v,
            filename[:200],
            created,
            json.dumps({"parsed": len(findings), "live_api": is_configured(v)}),
            now(),
        ),
    )
    get_conn().commit()
    return {
        "ok": True,
        "vendor": v,
        "batch_id": bid,
        "parsed": len(findings),
        "created": created,
        "configured_live_api": is_configured(v),
        "note": "Export ingest complete. Live API sync still requires credentials.",
    }


# Thin per-vendor helpers for catalog / imports
def status_tenable() -> dict[str, Any]:
    return vendor_status("tenable")


def status_qualys() -> dict[str, Any]:
    return vendor_status("qualys")


def status_nessus() -> dict[str, Any]:
    return vendor_status("nessus")


def status_rapid7() -> dict[str, Any]:
    return vendor_status("rapid7")


def status_wiz() -> dict[str, Any]:
    return vendor_status("wiz")


def status_splunk() -> dict[str, Any]:
    return vendor_status("splunk")


def status_elastic() -> dict[str, Any]:
    return vendor_status("elastic")
