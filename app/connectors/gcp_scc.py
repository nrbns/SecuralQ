"""Google Security Command Center — optional google-cloud-securitycenter.

Env:
  GCP_PROJECT_ID
  GCP_SERVICE_ACCOUNT_JSON  — path to service account JSON (authorized project)
"""

from __future__ import annotations

from typing import Any

from app.config import settings


def is_configured() -> bool:
    return bool(
        (settings.gcp_project_id or "").strip()
        and (settings.gcp_service_account_json or "").strip()
    )


def _client_available() -> bool:
    try:
        from google.cloud import securitycenter  # noqa: F401

        return True
    except Exception:
        return False


async def ping() -> dict[str, Any]:
    if not is_configured():
        return {"ok": False, "error": "not_configured"}
    if not _client_available():
        return {
            "ok": False,
            "error": "google_cloud_securitycenter_not_installed",
            "hint": "pip install google-cloud-securitycenter — or POST /api/cloud/import",
        }
    try:
        import asyncio
        from google.cloud import securitycenter
        from google.oauth2 import service_account

        def _call():
            creds = service_account.Credentials.from_service_account_file(
                settings.gcp_service_account_json
            )
            client = securitycenter.SecurityCenterClient(credentials=creds)
            parent = f"projects/{settings.gcp_project_id}/sources/-"
            # list one finding
            it = client.list_findings(request={"parent": parent, "page_size": 1})
            next(iter(it), None)
            return True

        await asyncio.to_thread(_call)
        return {"ok": True, "vendor": "gcp_scc"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:300]}


async def fetch_findings(limit: int = 50) -> list[dict[str, Any]]:
    if not is_configured() or not _client_available():
        return []
    import asyncio
    from google.cloud import securitycenter
    from google.oauth2 import service_account

    def _call():
        creds = service_account.Credentials.from_service_account_file(
            settings.gcp_service_account_json
        )
        client = securitycenter.SecurityCenterClient(credentials=creds)
        parent = f"projects/{settings.gcp_project_id}/sources/-"
        out = []
        for fr in client.list_findings(request={"parent": parent, "page_size": max(1, min(limit, 100))}):
            f = fr.finding
            sev = str(f.severity.name if hasattr(f.severity, "name") else f.severity).lower()
            out.append(
                {
                    "id": str(f.name)[:200],
                    "title": str(f.category or f.name)[:240],
                    "severity": sev if "critical" in sev or "high" in sev or "medium" in sev or "low" in sev else "medium",
                    "status": str(f.state.name if hasattr(f.state, "name") else f.state),
                    "source": "gcp_scc",
                    "resource": str(f.resource_name or "")[:300],
                }
            )
            if len(out) >= limit:
                break
        return out

    return await asyncio.to_thread(_call)
