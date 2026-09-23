"""Public Trust Center payload — honest claims only."""

from __future__ import annotations

from typing import Any


def trust_center_payload() -> dict[str, Any]:
    from app.audit_chain import verify_chain
    from app.evidence_spine.worm import worm_backend_status
    from app.phase1_ops_remaining import authenticode_status, capacity_http_status, sentinel_ha_status
    from app.platform_ready import platform_ready

    ready = platform_ready()
    worm = worm_backend_status()
    sign = authenticode_status()
    cap = capacity_http_status()
    ha = sentinel_ha_status()
    chain = verify_chain(limit=2_000)
    return {
        "ok": True,
        "product": "SecuraIQ",
        "status_page": "/status.html",
        "security_txt": "/.well-known/security.txt",
        "ready": bool(ready.get("ready")),
        "deployment_mode": ready.get("deployment_mode") or "lab",
        "claims": {
            "audit_hash_chain": bool(chain.get("ok")),
            "lab_worm_markers": (worm.get("backend") or "") == "local_fs",
            "cloud_object_lock": bool(worm.get("configured") and worm.get("object_lock_enabled")),
            "lab_authenticode": bool(sign.get("lab_artifact_signed")),
            "ev_authenticode": bool(sign.get("ev_commercial")),
            "http_capacity_measured": int(cap.get("http_top_measured") or 0),
            "redis_sentinel_lab": ha.get("status") == "lab",
        },
        "honesty": [
            "Lab self-signed Authenticode is not EV / SmartScreen trust.",
            "Local FS WORM markers are not cloud Object Lock.",
            "Desktop Sentinel inject is not multi-AZ commercial HA.",
            "No third-party pentest or SOC 2 attestation is claimed here.",
        ],
        "reports": {
            "security_txt": "/.well-known/security.txt",
            "public_status": "/api/status/public",
            "sbom": "CI generates CycloneDX when the security workflow runs",
        },
    }
