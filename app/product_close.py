"""Lab-closable leftovers: onboarding, ROI, tamper, evidence lineage helpers."""

from __future__ import annotations

from typing import Any

from app.db import get_conn, table_columns


def tamper_status(user_id: str = "") -> dict[str, Any]:
    from app.audit_chain import verify_chain

    chain = verify_chain(limit=5_000)
    fim_n = 0
    try:
        c = get_conn()
        if "securaiq_agent_threats" in {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}:
            q = "SELECT COUNT(*) AS n FROM securaiq_agent_threats WHERE category = 'file_integrity'"
            args: tuple = ()
            if user_id:
                cols = table_columns(c, "securaiq_agent_threats")
                if "user_id" in cols:
                    q += " AND user_id = ?"
                    args = (user_id,)
            fim_n = int((c.execute(q, args).fetchone() or {}).get("n") or 0)
    except Exception:
        fim_n = 0
    return {
        "ok": bool(chain.get("ok")),
        "audit_chain_ok": bool(chain.get("ok")),
        "fim_events": fim_n,
        "disclaimer": "Hash-chain + FIM signals — not a commercial EDR/tamper certification",
    }


def onboarding_progress(user_id: str) -> dict[str, Any]:
    c = get_conn()
    steps: list[dict[str, Any]] = []

    def _count(sql: str, args: tuple = ()) -> int:
        try:
            row = c.execute(sql, args).fetchone()
            return int((row["n"] if row else 0) or 0)
        except Exception:
            return 0

    tables = {
        r[0]
        for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    org_n = 1
    if "organizations" in tables:
        org_n = _count("SELECT COUNT(*) AS n FROM organizations WHERE user_id = ?", (user_id,))
        if org_n == 0:
            org_n = _count("SELECT COUNT(*) AS n FROM organizations")
    agent_n = 0
    if "securaiq_agents" in tables:
        agent_n = _count("SELECT COUNT(*) AS n FROM securaiq_agents WHERE user_id = ?", (user_id,))
    asset_n = _count("SELECT COUNT(*) AS n FROM assets WHERE user_id = ?", (user_id,))
    risk_ok = False
    try:
        from app.services.risk_priority import compute_org_risk_score

        score = compute_org_risk_score(user_id)
        risk_ok = score is not None
    except Exception:
        risk_ok = False

    steps.append({"id": "org", "ok": org_n > 0, "detail": f"orgs={org_n}"})
    steps.append({"id": "agent", "ok": agent_n > 0, "detail": f"agents={agent_n}"})
    steps.append({"id": "asset", "ok": asset_n > 0, "detail": f"assets={asset_n}"})
    steps.append({"id": "risk", "ok": risk_ok, "detail": "org risk computed" if risk_ok else "no risk yet"})
    steps.append(
        {
            "id": "top5",
            "ok": risk_ok and asset_n > 0,
            "detail": "Command Center / risk why-increased is the next operator view",
        }
    )
    done = sum(1 for s in steps if s["ok"])
    return {
        "ok": done >= 4,
        "complete": done == len(steps),
        "done": done,
        "total": len(steps),
        "steps": steps,
        "next": next((s["id"] for s in steps if not s["ok"]), None),
    }


def roi_metrics(user_id: str) -> dict[str, Any]:
    from app.services.executive_dashboard import (
        _mean_remediation_time_days,
        _security_exposure,
        _verified_remediation,
    )

    exposure = _security_exposure(user_id, org_id=None, engagement_id=None)
    verified = _verified_remediation(user_id)
    mttr = _mean_remediation_time_days(user_id, org_id=None, engagement_id=None)
    change = exposure.get("change_pct")
    return {
        "ok": True,
        "exposure_change_pct": change,
        "exposure_history_points": exposure.get("history_points"),
        "verified_remediation": verified,
        "mttr_days": (mttr or {}).get("mean_days"),
        "mttr_sample": (mttr or {}).get("sample_size"),
        "disclaimer": (
            "ROI uses measured history only. Missing history is null — never invented."
        ),
    }


def list_evidence_lineage(user_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
    from app.evidence_spine.schema import ensure_evidence_spine_schema

    ensure_evidence_spine_schema()
    rows = get_conn().execute(
        """
        SELECT id, evidence_id, vault_id, action, actor_id, detail, created_at
        FROM evidence_access_log
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (user_id, max(1, min(int(limit), 200))),
    ).fetchall()
    return [dict(r) for r in rows]
