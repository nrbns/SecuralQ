"""Check-in FIM → native threat ingest (Detect wedge after Phase 6 risk).

Only modified/deleted become medium file_integrity threats — never invent from
added, empty, or truncated payloads. Fingerprint dedupe matches Sentinel.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="fim_checkin_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def test_detections_from_checkin_fim_only_modify_delete():
    from app.agents import detections_from_checkin_file_integrity

    dets = detections_from_checkin_file_integrity(
        {
            "file_integrity": [
                {"path": "/etc/passwd", "status": "modified", "hash": "abc"},
                {"path": "/etc/shadow", "status": "deleted"},
                {"path": "/tmp/new", "status": "added", "hash": "def"},
                {"path": "", "status": "modified"},
            ]
        }
    )
    assert len(dets) == 2
    assert all(d["category"] == "file_integrity" and d["severity"] == "medium" for d in dets)
    assert dets[0]["title"].startswith("Monitored file modified:")
    assert dets[1]["title"].startswith("Monitored file deleted:")
    assert dets[0]["target"] == "/etc/passwd"


def test_detections_from_checkin_fim_truncated_empty_no_invent():
    from app.agents import detections_from_checkin_file_integrity

    assert detections_from_checkin_file_integrity({"truncated": True, "file_integrity": []}) == []
    assert detections_from_checkin_file_integrity({"truncated": True}) == []
    assert detections_from_checkin_file_integrity(None) == []


def test_checkin_fim_creates_threat_and_skips_realert(tmp_path, monkeypatch):
    from app.agents import checkin, enroll_agent, list_threats
    from app.enterprise import list_vulnerabilities

    uid = _setup(monkeypatch, tmp_path)
    enrolled = enroll_agent(uid, name="fim-host")
    aid = enrolled["agent_id"]

    payload = {
        "hostname": "fim-host",
        "os": "linux",
        "file_integrity": [
            {"path": "/etc/ssh/sshd_config", "status": "modified", "hash": "deadbeef"},
        ],
    }
    out = checkin(aid, payload)
    assert out.get("ok") is True

    threats = list_threats(uid, agent_id=aid)
    assert len(threats) == 1
    assert threats[0]["category"] == "file_integrity"
    assert threats[0]["severity"] == "medium"
    assert "sshd_config" in (threats[0].get("title") or "")

    findings = [
        v
        for v in list_vulnerabilities(uid, status="open")
        if (v.get("source") or "") == "agent:sentinel" and "sshd_config" in (v.get("title") or "")
    ]
    assert len(findings) == 1

    # Same fingerprint within re-alert window → skip (hit_count bumps, no new finding storm)
    out2 = checkin(aid, payload)
    assert out2.get("ok") is True
    threats2 = list_threats(uid, agent_id=aid)
    assert len(threats2) == 1
    assert int(threats2[0].get("hit_count") or 0) >= 2
    findings2 = [
        v
        for v in list_vulnerabilities(uid, status="open")
        if (v.get("source") or "") == "agent:sentinel" and "sshd_config" in (v.get("title") or "")
    ]
    assert len(findings2) == 1


def test_checkin_added_only_creates_no_threat(tmp_path, monkeypatch):
    from app.agents import checkin, enroll_agent, list_threats

    uid = _setup(monkeypatch, tmp_path, username="fim_added_only")
    enrolled = enroll_agent(uid, name="fim-added")
    checkin(
        enrolled["agent_id"],
        {
            "hostname": "fim-added",
            "os": "linux",
            "file_integrity": [{"path": "/opt/new.conf", "status": "added", "hash": "1"}],
        },
    )
    assert list_threats(uid, agent_id=enrolled["agent_id"]) == []


def test_knowledge_graph_includes_native_agent_threat(tmp_path, monkeypatch):
    from app.agents import checkin, enroll_agent
    from app.enterprise import create_vulnerability
    from app.knowledge_graph import build_knowledge_graph

    uid = _setup(monkeypatch, tmp_path, username="fim_graph")
    enrolled = enroll_agent(uid, name="fim-graph-host")
    ci = checkin(
        enrolled["agent_id"],
        {
            "hostname": "fim-graph-host",
            "os": "linux",
            "file_integrity": [
                {"path": "/etc/hosts", "status": "modified", "hash": "aa"},
            ],
        },
    )
    asset_id = ci["asset_id"]
    # Second discipline so hotspots can fire (≥2 disciplines or ≥2 vuln+xdr)
    create_vulnerability(
        uid,
        {
            "asset_id": asset_id,
            "asset_name": "fim-graph-host",
            "title": "OpenSSH outdated",
            "severity": "high",
            "cvss": 7.5,
            "status": "open",
        },
    )
    g = build_knowledge_graph(uid)
    xdr_nodes = [
        n
        for n in g["nodes"]
        if n.get("type") == "xdr" and (n.get("meta") or {}).get("vendor") == "securaiq_agent"
    ]
    assert xdr_nodes
    assert any("hosts" in (n.get("label") or "") for n in xdr_nodes)
    hotspots = g.get("hotspots") or []
    assert any(h.get("asset_id") == asset_id for h in hotspots)
