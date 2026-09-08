"""Cross-tenant isolation: Org A must never see Org B data."""

from __future__ import annotations

import importlib

import pytest


def _reload(monkeypatch, data_dir):
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEPLOYMENT_MODE", "lab")
    monkeypatch.setenv("DATABASE_URL", "")
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)
    return config_mod, db_mod


@pytest.fixture()
def two_orgs(tmp_path, monkeypatch):
    data_dir = tmp_path / "tenant"
    data_dir.mkdir()
    _reload(monkeypatch, data_dir)
    from app.auth import register_user
    from app.commercial_ext import create_org
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    alice = register_user("alice_iso", "password123", role="user")
    bob = register_user("bob_iso", "password123", role="user")
    org_a = create_org(alice.id, "OrgA-Iso")
    org_b = create_org(bob.id, "OrgB-Iso")
    return alice, bob, org_a, org_b


def test_vuln_and_risk_isolation(two_orgs):
    alice, bob, org_a, org_b = two_orgs
    from app.enterprise import create_asset, create_risk, create_vulnerability, list_risks, list_vulnerabilities

    create_asset(alice.id, "host-a", org_id=org_a["id"])
    create_asset(bob.id, "host-b", org_id=org_b["id"])
    create_vulnerability(
        alice.id,
        {"title": "Alice finding", "severity": "high", "asset_name": "host-a", "org_id": org_a["id"]},
    )
    create_vulnerability(
        bob.id,
        {"title": "Bob finding", "severity": "critical", "asset_name": "host-b", "org_id": org_b["id"]},
    )
    create_risk(alice.id, threat="Alice threat", asset_name="host-a", org_id=org_a["id"])
    create_risk(bob.id, threat="Bob threat", asset_name="host-b", org_id=org_b["id"])

    alice_vulns = {v["title"] for v in list_vulnerabilities(alice.id, org_id=org_a["id"])}
    bob_vulns = {v["title"] for v in list_vulnerabilities(bob.id, org_id=org_b["id"])}
    assert "Alice finding" in alice_vulns
    assert "Bob finding" not in alice_vulns
    assert "Bob finding" in bob_vulns
    assert "Alice finding" not in bob_vulns

    alice_risks = {r["threat"] for r in list_risks(alice.id, org_id=org_a["id"])}
    bob_risks = {r["threat"] for r in list_risks(bob.id, org_id=org_b["id"])}
    assert "Alice threat" in alice_risks
    assert "Bob threat" not in alice_risks
    assert "Bob threat" in bob_risks
    assert "Alice threat" not in bob_risks


def test_chat_and_engagement_isolation(two_orgs):
    alice, bob, org_a, org_b = two_orgs
    from app.workspace import create_chat, create_engagement, list_chats, list_engagements

    ea = create_engagement(alice.id, "Eng-A", scope_json=["10.0.0.0/8"])
    eb = create_engagement(bob.id, "Eng-B", scope_json=["192.168.0.0/16"])
    create_chat(alice.id, title="Alice chat", engagement_id=ea["id"])
    create_chat(bob.id, title="Bob chat", engagement_id=eb["id"])

    alice_eng = {e["name"] for e in list_engagements(alice.id)}
    bob_eng = {e["name"] for e in list_engagements(bob.id)}
    assert "Eng-A" in alice_eng and "Eng-B" not in alice_eng
    assert "Eng-B" in bob_eng and "Eng-A" not in bob_eng

    alice_chats = {c["title"] for c in list_chats(alice.id)}
    bob_chats = {c["title"] for c in list_chats(bob.id)}
    assert "Alice chat" in alice_chats
    assert "Bob chat" not in alice_chats
    assert "Bob chat" in bob_chats
    assert "Alice chat" not in bob_chats

    # org ids unused here but prove fixture still yields distinct orgs
    assert org_a["id"] != org_b["id"]


def test_scan_incident_evidence_isolation(two_orgs):
    """P0.1: scans / incidents / evidence fail closed across orgs."""
    alice, bob, org_a, org_b = two_orgs
    from app.ops import create_incident, get_incident, list_incidents
    from app.scan_engine.models import create_scan, get_scan_for_user, list_scans
    from app.services.evidence import get_evidence, list_evidence, record_evidence

    sa = create_scan(user_id=alice.id, target="10.0.0.1", org_id=org_a["id"], authorized=True)
    sb = create_scan(user_id=bob.id, target="10.0.0.2", org_id=org_b["id"], authorized=True)
    assert sa.get("org_id") == org_a["id"]
    assert sb.get("org_id") == org_b["id"]

    alice_scans = {s["id"] for s in list_scans(alice.id, org_id=org_a["id"])}
    bob_scans = {s["id"] for s in list_scans(bob.id, org_id=org_b["id"])}
    assert sa["id"] in alice_scans and sb["id"] not in alice_scans
    assert sb["id"] in bob_scans and sa["id"] not in bob_scans
    assert get_scan_for_user(bob.id, sa["id"]) is None
    assert get_scan_for_user(alice.id, sa["id"]) is not None

    ia = create_incident(alice.id, title="Alice incident", org_id=org_a["id"])
    ib = create_incident(bob.id, title="Bob incident", org_id=org_b["id"])
    assert ia.get("org_id") == org_a["id"]
    alice_inc = {i["title"] for i in list_incidents(alice.id, org_id=org_a["id"])}
    bob_inc = {i["title"] for i in list_incidents(bob.id, org_id=org_b["id"])}
    assert "Alice incident" in alice_inc and "Bob incident" not in alice_inc
    assert "Bob incident" in bob_inc and "Alice incident" not in bob_inc
    assert get_incident(bob.id, ia["id"]) is None
    assert get_incident(alice.id, ia["id"]) is not None

    ea = record_evidence(
        alice.id,
        entity_type="threat",
        entity_id="t-a",
        source="observed",
        summary="alice signal",
        org_id=org_a["id"],
    )
    eb = record_evidence(
        bob.id,
        entity_type="threat",
        entity_id="t-b",
        source="observed",
        summary="bob signal",
        org_id=org_b["id"],
    )
    assert ea.get("org_id") == org_a["id"]
    alice_ev = {e["summary"] for e in list_evidence(alice.id, org_id=org_a["id"])}
    bob_ev = {e["summary"] for e in list_evidence(bob.id, org_id=org_b["id"])}
    assert "alice signal" in alice_ev and "bob signal" not in alice_ev
    assert "bob signal" in bob_ev and "alice signal" not in bob_ev
    assert get_evidence(bob.id, ea["id"]) is None
    assert get_evidence(alice.id, ea["id"]) is not None
    assert get_evidence(alice.id, eb["id"]) is None


def test_archive_meta_org_isolation(two_orgs):
    """Archived scan reports stamped with org_id are not readable cross-tenant."""
    alice, bob, org_a, org_b = two_orgs
    from pathlib import Path

    from app.archive import (
        archive_root,
        archive_user_scans,
        find_archived_scan_for_user,
        list_archives,
    )
    from app.scan_engine.models import create_scan, update_scan

    sa = create_scan(user_id=alice.id, target="10.1.1.1", org_id=org_a["id"], authorized=True)
    update_scan(sa["id"], status="completed", summary_json={"findings_created": 1})
    ev = Path(sa["evidence_dir"])
    ev.mkdir(parents=True, exist_ok=True)
    (ev / "report.md").write_text("# Alice scan\n", encoding="utf-8")

    result = archive_user_scans(alice.id)
    assert result.get("ok")
    assert result.get("archived_count", 0) >= 1

    alice_arch = list_archives(alice.id, org_id=org_a["id"])
    bob_arch = list_archives(bob.id, org_id=org_b["id"])
    alice_ids = {a.get("scan_id") for a in alice_arch}
    bob_ids = {a.get("scan_id") for a in bob_arch}
    assert sa["id"] in alice_ids
    assert sa["id"] not in bob_ids
    assert find_archived_scan_for_user(sa["id"], bob.id) is None
    assert find_archived_scan_for_user(sa["id"], alice.id) is not None
    assert archive_root().is_dir()


def test_intel_watch_gap_remediation_xdr_isolation(two_orgs):
    """Remaining P0.1 surfaces: intel watch, gap remediations, XDR events."""
    alice, bob, org_a, org_b = two_orgs
    from app.enterprise import create_remediation, get_remediation, list_remediations
    from app.ops import add_intel_watch, list_intel_watch
    from app.xdr import ingest_detections, list_events

    add_intel_watch(alice.id, kind="cve", value="CVE-ALICE", org_id=org_a["id"])
    add_intel_watch(bob.id, kind="cve", value="CVE-BOB", org_id=org_b["id"])
    alice_w = {w["value"] for w in list_intel_watch(alice.id, org_id=org_a["id"])}
    bob_w = {w["value"] for w in list_intel_watch(bob.id, org_id=org_b["id"])}
    assert "CVE-ALICE" in alice_w and "CVE-BOB" not in alice_w
    assert "CVE-BOB" in bob_w and "CVE-ALICE" not in bob_w

    ra = create_remediation(alice.id, title="Alice rem", control_id="AC-1", org_id=org_a["id"])
    create_remediation(bob.id, title="Bob rem", control_id="AC-2", org_id=org_b["id"])
    assert ra.get("org_id") == org_a["id"]
    alice_rems = {r["title"] for r in list_remediations(alice.id, org_id=org_a["id"])}
    bob_rems = {r["title"] for r in list_remediations(bob.id, org_id=org_b["id"])}
    assert "Alice rem" in alice_rems and "Bob rem" not in alice_rems
    assert "Bob rem" in bob_rems and "Alice rem" not in bob_rems
    assert get_remediation(bob.id, ra["id"]) is None

    ingest_detections(
        [{"vendor": "generic", "external_id": "evt-a", "title": "Alice XDR", "severity": "low"}],
        user_id=alice.id,
        org_id=org_a["id"],
        auto_incidents=False,
    )
    ingest_detections(
        [{"vendor": "generic", "external_id": "evt-b", "title": "Bob XDR", "severity": "low"}],
        user_id=bob.id,
        org_id=org_b["id"],
        auto_incidents=False,
    )
    alice_xdr = {e["title"] for e in list_events(alice.id, org_id=org_a["id"])}
    bob_xdr = {e["title"] for e in list_events(bob.id, org_id=org_b["id"])}
    assert "Alice XDR" in alice_xdr and "Bob XDR" not in alice_xdr
    assert "Bob XDR" in bob_xdr and "Alice XDR" not in bob_xdr


def test_tool_scope_blocks_cross_engagement_target(two_orgs):
    alice, _bob, _oa, _ob = two_orgs
    from app.services.tool_policy import assert_tool_target_allowed
    from app.workspace import create_engagement

    eng = create_engagement(alice.id, "Scoped", scope_json=["10.0.0.0/8"])
    assert_tool_target_allowed(
        user_id=alice.id,
        engagement_id=eng["id"],
        target="10.1.2.3",
        ip="10.1.2.3",
        authorized=True,
    )
    with pytest.raises(ValueError, match="out of engagement scope"):
        assert_tool_target_allowed(
            user_id=alice.id,
            engagement_id=eng["id"],
            target="8.8.8.8",
            ip="8.8.8.8",
            authorized=True,
        )
