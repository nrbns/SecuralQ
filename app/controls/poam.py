"""POA&M-like auto-open/close stubs via gap_remediations.

Honest foundations only: on host-control FAIL, ensure an open remediation
row exists; on PASS after FAIL, mark matching rows done. Reuses enterprise
gap_remediations — not a formal CMMC POA&M package or certification claim.

Never raises to callers (agent check-in must stay up).
No auto-execute of firewall/defender/SSH changes.
"""

from __future__ import annotations

from typing import Any

# Human-readable fix hints (recommend only — never auto-applied).
_FIX_HINTS: dict[str, str] = {
    "host_firewall": (
        "Enable the host firewall (ufw/firewalld/Windows Firewall), then wait "
        "for the next SecuraIQ agent check-in to verify PASS. "
        "Approved agent commands are optional and not auto-executed."
    ),
    "host_defender": (
        "Enable Microsoft Defender (or equivalent AV) on the host, then wait "
        "for the next agent check-in to verify PASS. No auto-remediation."
    ),
    "host_ssh_root": (
        "Set PermitRootLogin no (or prohibit-password) in sshd_config, then "
        "wait for the next agent check-in to verify PASS. No auto-remediation."
    ),
}


def poam_marker(test_name: str, agent_id: str) -> str:
    return f"poam:{test_name}:{agent_id}"


def _primary_control(test_name: str) -> tuple[str, str]:
    try:
        from app.services.control_testing import _HOST_TEST_PRIMARY_CONTROLS

        return _HOST_TEST_PRIMARY_CONTROLS.get(test_name, ("cis_controls", "MC"))
    except Exception:
        return ("cis_controls", "MC")


def _publish_recommended(
    user_id: str,
    *,
    rem: dict[str, Any] | None,
    agent_id: str,
    test_name: str,
    title: str,
    recommendation: str,
) -> None:
    try:
        from app.realtime_bus import publish

        publish(
            event_type="remediation.recommended",
            type="remediation.recommended",
            user_id=user_id,
            agent_id=agent_id,
            test=test_name,
            remediation_id=(rem or {}).get("id"),
            title=title,
            recommendation=recommendation[:500],
            auto_execute=False,
            source="control_engine_poam",
        )
        # Dual-write flat remediation for existing UI filters
        publish(
            type="remediation",
            event_type="remediation.recommended",
            id=(rem or {}).get("id") or f"needed:{poam_marker(test_name, agent_id)}",
            user_id=user_id,
            agent_id=agent_id,
            status="recommended",
            title=title,
            test=test_name,
            auto_execute=False,
            _from_processor=True,
        )
    except Exception:
        pass


def open_poam_for_host_fail(
    user_id: str,
    *,
    agent_id: str,
    hostname: str = "",
    test_name: str,
    result: dict[str, Any] | None = None,
    control_id: str | None = None,
    framework_id: str | None = None,
) -> dict[str, Any] | None:
    """Create or reuse an open gap_remediation for this agent+test FAIL.

    Returns the remediation dict when possible; None on any error.
    """
    if not user_id or not agent_id or not test_name:
        return None
    result = result or {}
    try:
        from app.enterprise import create_remediation, list_remediations, update_remediation
    except Exception:
        return None

    marker = poam_marker(test_name, agent_id)
    # Also recognize RT-11 host_firewall marker for idempotency
    legacy_fw = f"host_firewall:{agent_id}" if test_name == "host_firewall" else ""
    host = hostname or agent_id[:8]
    title = f"POA&M stub: remediate {test_name} on {host}"[:300]

    try:
        open_rems = list_remediations(user_id, status="open")
    except Exception:
        open_rems = []

    for rem in open_rems:
        notes = rem.get("notes") or ""
        rec = rem.get("recommendation") or ""
        if marker in notes or marker in rec:
            return rem
        if legacy_fw and (legacy_fw in notes or legacy_fw in rec):
            return rem

    primary = _primary_control(test_name)
    cid = (control_id or primary[1])[:40]
    hint = _FIX_HINTS.get(test_name, "Remediate the failing host control, then re-check via agent check-in.")
    summary = str(result.get("summary") or f"{test_name} failed.")
    recommendation = (
        f"{summary} [{marker}] {hint}"
    )[:2000]

    rem: dict[str, Any] | None = None
    try:
        rem = create_remediation(
            user_id,
            control_id=cid,
            title=title,
            recommendation=recommendation,
        )
        rid = (rem or {}).get("id")
        if rid:
            try:
                notes = marker if not legacy_fw else f"{marker} {legacy_fw}"
                update_remediation(user_id, rid, {"notes": notes[:500]})
            except Exception:
                pass
    except Exception:
        rem = None

    _publish_recommended(
        user_id,
        rem=rem,
        agent_id=agent_id,
        test_name=test_name,
        title=title,
        recommendation=recommendation,
    )
    return rem


def close_poam_for_host_pass(
    user_id: str,
    *,
    agent_id: str,
    test_name: str,
) -> int:
    """Mark matching open POA&M/remediation rows done. Returns count closed."""
    if not user_id or not agent_id or not test_name:
        return 0
    closed = 0
    try:
        from app.enterprise import list_remediations, update_remediation

        marker = poam_marker(test_name, agent_id)
        legacy_fw = f"host_firewall:{agent_id}" if test_name == "host_firewall" else ""
        for rem in list_remediations(user_id, status="open"):
            notes = rem.get("notes") or ""
            rec = rem.get("recommendation") or ""
            if marker in notes or marker in rec or (
                legacy_fw and (legacy_fw in notes or legacy_fw in rec)
            ):
                try:
                    update_remediation(user_id, rem["id"], {"status": "done"})
                    closed += 1
                except Exception:
                    continue
    except Exception:
        return closed
    return closed


def open_poam_from_control_fail_result(
    user_id: str,
    *,
    framework_id: str,
    control_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    """Best-effort POA&M open from a control.failed live-test result.

    Uses detail.failing_agents when present; otherwise a synthetic agent key.
    Never raises.
    """
    opened: list[dict[str, Any]] = []
    try:
        status = (result.get("status") or "").lower()
        if status != "fail":
            return opened
        test_name = str(result.get("test") or "")
        detail = result.get("detail") if isinstance(result.get("detail"), dict) else {}
        agents = detail.get("failing_agents") or []
        if isinstance(agents, list) and agents:
            for entry in agents:
                if isinstance(entry, dict):
                    aid = str(entry.get("agent_id") or entry.get("id") or "")
                    host = str(entry.get("hostname") or "")
                else:
                    aid = str(entry)
                    host = ""
                if not aid:
                    continue
                rem = open_poam_for_host_fail(
                    user_id,
                    agent_id=aid,
                    hostname=host,
                    test_name=test_name or "control_fail",
                    result=result,
                    control_id=control_id,
                    framework_id=framework_id,
                )
                if rem:
                    opened.append(rem)
        elif test_name.startswith("host_"):
            # Aggregate FAIL without per-agent list — single stub row
            rem = open_poam_for_host_fail(
                user_id,
                agent_id=f"aggregate:{control_id}",
                hostname="",
                test_name=test_name,
                result=result,
                control_id=control_id,
                framework_id=framework_id,
            )
            if rem:
                opened.append(rem)
    except Exception:
        return opened
    return opened
