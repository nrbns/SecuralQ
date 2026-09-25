"""Total phase board — world-class 1–5 + master-build 1–46.

A phase is lab when its in-repo proof module exists.
Commercial leftovers stay ops and are never claimed done.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]


def _mod(name: str) -> bool:
    try:
        __import__(name)
        return True
    except Exception:
        return False


def _file(*rel: str) -> bool:
    return _ROOT.joinpath(*rel).is_file()


def _row(n: int, name: str, ok: bool, *, ops: list[str] | None = None, note: str = "") -> dict[str, Any]:
    return {
        "id": n,
        "name": name,
        "status": "lab" if ok else "partial",
        "code_unblocked": ok,
        "ops_blocked": ops or [],
        "note": note,
    }


def master_build_phases() -> list[dict[str, Any]]:
    return [
        _row(1, "Realtime foundation", _mod("app.realtime_bus") and _mod("app.event_processor")),
        _row(2, "Real agent platform", _mod("app.agents") and _file("scripts", "securaiq_agent.py")),
        _row(3, "Agent security", _mod("app.agent_certs") and _mod("app.agent_security")),
        _row(4, "Realtime command system", _mod("app.agents")),
        _row(5, "Security event engine", _mod("app.event_processor")),
        _row(6, "EDR depth", _mod("app.agents"), ops=["commercial_edr"], note="FIM + connectors; not full EDR"),
        _row(7, "Vulnerability management", _mod("app.enterprise")),
        _row(8, "Patch management", _mod("app.agents")),
        _row(9, "Risk engine", _mod("app.services.risk_priority")),
        _row(10, "Risk simulator", _mod("app.services.risk_priority"), ops=["digital_twin"]),
        _row(11, "Attack path engine", _mod("app.services.attack_graph")),
        _row(12, "Compliance engine", _mod("app.gap_analysis") or _mod("app.compliance_ops.tasks")),
        _row(13, "Control test engine", _mod("app.services.control_testing")),
        _row(14, "Continuous compliance", _mod("app.compliance_ops.automation")),
        _row(15, "Framework library", _mod("app.integrations_catalog")),
        _row(16, "Cross-framework mapping", _mod("app.evidence_spine.mapping") or _mod("app.gap_analysis")),
        _row(17, "Evidence engine", _mod("app.evidence_spine.vault")),
        _row(18, "Evidence integrity", _mod("app.audit_chain") and _mod("app.evidence_spine.worm")),
        _row(19, "Audit center", _mod("app.audit_chain")),
        _row(20, "Compliance exceptions", _mod("app.services.exceptions")),
        _row(21, "Policy management", _mod("app.gap_analysis") or _mod("app.compliance_ops.tasks")),
        _row(22, "Cloud security / CSPM", _mod("app.cloud_posture") or _file("app", "cloud_posture_api.py"), ops=["live_cloud_tenant"]),
        _row(
            23,
            "Container / Kubernetes",
            _file("scripts", "packaging", "QUICKSTART.md") and _mod("app.integrations_catalog"),
            note="scanner adapters + packaging; not full K8s posture / Helm product",
        ),
        _row(24, "Application security", _mod("app.scan_engine") or _file("app", "sonarqube_api.py")),
        _row(25, "SBOM / supply chain", _file("docs", "openapi.json"), note="CI SBOM + adapters"),
        _row(26, "Identity security", _mod("app.security_graph_depth"), ops=["live_idp"]),
        _row(27, "Data security", _mod("app.data_governance_api") or _file("app", "data_governance_api.py")),
        _row(28, "Third-party risk", _mod("app.enterprise")),
        _row(29, "Malware analysis", _file("data", "knowledge", "wormgpt_threat_intel.md"), note="lab intel only; no malware engine"),
        _row(30, "Incident response", _mod("app.thehive_api") or _file("app", "thehive_api.py")),
        _row(31, "AI Security Operations", _mod("app.secops") or _mod("app.product_close")),
        _row(32, "AI Security (AISPM)", _file("tests", "test_ai_security.py")),
        _row(33, "Security Digital Twin", _mod("app.services.risk_priority"), ops=["digital_twin_depth"], note="risk sim ≠ twin"),
        _row(34, "Business services", _mod("app.service_impact")),
        _row(35, "Realtime UI", _file("static", "app.js")),
        _row(36, "UI/UX pattern", _file("static", "index.html")),
        _row(37, "Executive mode", _mod("app.services.executive_dashboard")),
        _row(38, "SOC mode", _mod("app.agents")),
        _row(39, "Compliance mode", _mod("app.compliance_ops.tasks")),
        _row(40, "Multi-tenancy", _mod("app.tenancy")),
        _row(41, "Enterprise auth", _mod("app.auth") and _mod("app.saml_scaffold")),
        _row(42, "Audit (platform)", _mod("app.audit_chain")),
        _row(
            43,
            "HA / DR",
            _mod("app.phase1_ops_remaining") and _mod("app.measured_ops"),
            ops=["postgres_ha", "multi_az"],
            note="SQLite RTO/RPO published via GET /api/ops/measured; cluster/Postgres remain ops",
        ),
        _row(44, "Security of SecuraIQ", _file("tests", "test_ai_security.py") and _mod("app.trust_center")),
        _row(45, "Realtime load testing", _mod("app.phase1_ops_remaining"), ops=["http_5k_100k_unmeasured"]),
        _row(
            46,
            "Chaos testing",
            _file("scripts", "realtime_chaos_test.py") and _file("tests", "test_realtime_chaos_local.py"),
            ops=["chaos_at_5k"],
            note="soft chaos + reconnect; Redis kill remains manual",
        ),
    ]


def total_phase_board() -> dict[str, Any]:
    from app.phase_board import all_phases_board

    wc = all_phases_board()
    mb = master_build_phases()
    from app.launch_plan import launch_p0_rows

    p0 = launch_p0_rows()
    return {
        "ok": bool(wc.get("ok")) and all(p.get("code_unblocked") for p in mb),
        "all_lab": bool(wc.get("all_lab")) and all(p.get("status") == "lab" for p in mb),
        "world_class": wc,
        "master_build": mb,
        "master_build_count": len(mb),
        "launch_p0_count": len(p0),
        "launch_open": sum(1 for r in p0 if r.get("status") == "open"),
        "disclaimer": (
            "all_lab = in-repo lab-production proofs for every numbered phase. "
            "EV, C3PAO, live IdP/cloud tenants, digital twin, and 5k–100k HTTP remain ops."
        ),
    }
