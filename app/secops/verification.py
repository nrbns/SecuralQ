"""Phase 9–10 thin verify — read-only host-control verification after remediations.

Does not auto-execute. Confirms observed PASS/FAIL from agent telemetry /
control test results after an approved enable_firewall / enable_defender.
"""

from __future__ import annotations

from typing import Any


def verify_host_remediation(
    user_id: str,
    *,
    agent_id: str,
    test_name: str = "host_firewall",
    org_id: str | None = None,
) -> dict[str, Any]:
    """Return current live host-control verdict for one agent (observed only)."""
    from app.agents import agent_visible_to_user, get_agent
    from app.controls.test_registry import (
        TEST_HOST_DEFENDER,
        TEST_HOST_DISK_ENCRYPTION,
        TEST_HOST_FIREWALL,
        TEST_HOST_SSH_ROOT,
    )
    from app.services.control_testing import (
        evaluate_host_defender_payload,
        evaluate_host_disk_encryption_payload,
        evaluate_host_firewall_payload,
        evaluate_host_ssh_root_payload,
    )

    agent = get_agent(str(agent_id or "").strip())
    if not agent_visible_to_user(user_id, agent):
        return {"ok": False, "error": "agent_not_found", "verified": False}
    payload = agent.get("last_payload") if isinstance(agent.get("last_payload"), dict) else {}
    aid = str(agent.get("id") or "")
    asset = str(agent.get("asset_id") or "")
    os_name = str(payload.get("os") or "")
    name = str(test_name or TEST_HOST_FIREWALL).strip()
    evaluators = {
        TEST_HOST_FIREWALL: lambda: evaluate_host_firewall_payload(
            payload, agent_id=aid, asset_id=asset
        ),
        TEST_HOST_DEFENDER: lambda: evaluate_host_defender_payload(
            payload, agent_id=aid, asset_id=asset, os_name=os_name
        ),
        TEST_HOST_SSH_ROOT: lambda: evaluate_host_ssh_root_payload(
            payload, agent_id=aid, asset_id=asset
        ),
        TEST_HOST_DISK_ENCRYPTION: lambda: evaluate_host_disk_encryption_payload(
            payload, agent_id=aid, asset_id=asset
        ),
    }
    fn = evaluators.get(name)
    if not fn:
        return {
            "ok": False,
            "error": "unsupported_test",
            "verified": False,
            "allowed": list(evaluators.keys()),
        }
    result = fn()
    status = str(result.get("status") or "unknown").lower()
    return {
        "ok": True,
        "verified": status == "pass",
        "status": status,
        "test": name,
        "agent_id": aid,
        "asset_id": asset,
        "summary": result.get("summary") or "",
        "honesty": (
            "Verification uses observed agent telemetry only — not a canary/rollback engine. "
            "UNKNOWN when not collected; never invents PASS."
        ),
        "detail": result.get("detail") or {},
    }
