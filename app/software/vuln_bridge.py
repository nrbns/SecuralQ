"""Bridge software_advisories → enterprise vulnerabilities (Phase 4).

Agent packages land in inventory; after advisory match we upsert open findings
so risk / dashboard / compliance paths see package CVEs — not only the Software page.
"""

from __future__ import annotations

from typing import Any


def _severity_normalize(sev: str, cvss: float | None, kev: bool) -> str:
    if kev:
        return "critical"
    s = (sev or "").strip().upper()
    if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return s.lower()
    if cvss is not None:
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low"
    return "medium"


def bridge_advisories_to_vulnerabilities(
    user_id: str,
    *,
    asset_id: str,
    asset_name: str = "",
    advisories: list[dict[str, Any]],
    product_name: str = "",
    version: str = "",
    listening_ports: list[int] | None = None,
    agent_ip: str = "",
    emit_realtime: bool = True,
) -> dict[str, Any]:
    """Upsert enterprise findings for matched package advisories on one asset."""
    if not advisories or not (asset_id or asset_name):
        return {"created": 0, "updated": 0, "skipped": 0}

    from app.enterprise import upsert_vulnerability

    ports = [int(p) for p in (listening_ports or []) if str(p).isdigit() or isinstance(p, int)]
    exposed = bool(ports)  # coarse exposure: host publishes listening ports
    created = updated = skipped = 0

    for adv in advisories:
        cve = str(adv.get("cve_id") or adv.get("cve") or "").strip().upper()
        if not cve.startswith("CVE-"):
            skipped += 1
            continue
        kev = bool(adv.get("kev"))
        cvss = adv.get("cvss")
        try:
            cvss_f = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            cvss_f = None
        severity = _severity_normalize(str(adv.get("severity") or ""), cvss_f, kev)
        product = (product_name or "software").strip() or "software"
        ver = (version or "").strip()
        title = f"{cve} on {product}" + (f" {ver}" if ver else "")
        fixed = str(adv.get("fixed_version") or "").strip()
        detail = str(adv.get("detail") or "")[:400]
        raw = {
            "source_kind": "software:advisory",
            "product": product,
            "version": ver,
            "fixed_version": fixed,
            "advisory_source": adv.get("source") or "",
            "kev": kev,
            "epss": adv.get("epss"),
            "listening_ports": ports[:40],
            "agent_ip": agent_ip or "",
            "exposure": "listening_ports" if exposed else "host_inventory",
            "detail": detail,
        }
        item = {
            "asset_id": asset_id,
            "asset_name": asset_name or asset_id[:8],
            "cve": cve,
            "title": title[:240],
            "severity": severity,
            "cvss": cvss_f,
            "status": "open",
            "source": "software:advisory",
            "raw": raw,
        }
        try:
            row = upsert_vulnerability(user_id, item, emit_realtime=emit_realtime)
            if (row or {}).get("_upsert") == "created":
                created += 1
            else:
                updated += 1
        except Exception:
            skipped += 1

    return {"created": created, "updated": updated, "skipped": skipped}
