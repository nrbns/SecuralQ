"""AWS Security Hub findings — optional boto3 (authorized accounts only).

Env:
  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_REGION
  Or standard AWS credential chain when boto3 is installed.
"""

from __future__ import annotations

from typing import Any

from app.config import settings


def is_configured() -> bool:
    # Explicit keys or region alone with ambient creds (boto3)
    if (settings.aws_access_key_id or "").strip() and (settings.aws_secret_access_key or "").strip():
        return True
    return bool((settings.aws_region or "").strip()) and _boto3_available()


def _boto3_available() -> bool:
    try:
        import boto3  # noqa: F401

        return True
    except Exception:
        return False


def _client():
    import boto3

    kwargs: dict[str, Any] = {"region_name": (settings.aws_region or "us-east-1").strip()}
    if (settings.aws_access_key_id or "").strip():
        kwargs["aws_access_key_id"] = settings.aws_access_key_id
        kwargs["aws_secret_access_key"] = settings.aws_secret_access_key
    return boto3.client("securityhub", **kwargs)


async def ping() -> dict[str, Any]:
    if not is_configured():
        return {"ok": False, "error": "not_configured"}
    if not _boto3_available():
        return {
            "ok": False,
            "error": "boto3_not_installed",
            "hint": "pip install boto3 — or POST /api/cloud/import with findings JSON",
        }
    try:
        import asyncio

        def _call():
            return _client().get_findings(MaxResults=1)

        await asyncio.to_thread(_call)
        return {"ok": True, "vendor": "aws_security_hub"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:300]}


async def fetch_findings(limit: int = 50) -> list[dict[str, Any]]:
    if not is_configured() or not _boto3_available():
        return []
    import asyncio

    def _call():
        return _client().get_findings(
            Filters={"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]},
            MaxResults=max(1, min(int(limit), 100)),
        )

    data = await asyncio.to_thread(_call)
    out = []
    for f in data.get("Findings") or []:
        sev = str(((f.get("Severity") or {}).get("Label") or "MEDIUM")).lower()
        out.append(
            {
                "id": str(f.get("Id") or f.get("ProductArn") or "")[:200],
                "title": str(f.get("Title") or "Security Hub finding")[:240],
                "severity": sev if sev in {"critical", "high", "medium", "low", "informational"} else "medium",
                "status": str(f.get("WorkflowState") or f.get("RecordState") or "ACTIVE"),
                "source": "aws_security_hub",
                "resource": str(((f.get("Resources") or [{}])[0] or {}).get("Id") or "")[:300],
            }
        )
    return out
