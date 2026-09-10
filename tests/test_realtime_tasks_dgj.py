"""REALTIME Task D offline buffer + Task G lifecycle + Task J Ed25519."""

from __future__ import annotations


def test_offline_buffer_enqueue_ack_persist(tmp_path):
    from app.agent_offline_buffer import OfflineTelemetryBuffer

    path = tmp_path / "buf.json"
    buf = OfflineTelemetryBuffer("agent-a", path=path, max_events=100)
    s1 = buf.enqueue("telemetry", {"n": 1})
    s2 = buf.enqueue("telemetry", {"n": 2})
    assert s1 == 1 and s2 == 2
    assert buf.pending_count == 2

    # Reload from disk
    buf2 = OfflineTelemetryBuffer("agent-a", path=path)
    assert buf2.pending_count == 2
    assert buf2.pending_sequences() == [1, 2]

    removed = buf2.ack([1, 2])
    assert removed == 2
    assert buf2.pending_count == 0
    assert buf2.last_acked_seq == 2


def test_offline_buffer_max_events_bound(tmp_path):
    from app.agent_offline_buffer import OfflineTelemetryBuffer

    buf = OfflineTelemetryBuffer("agent-b", path=tmp_path / "b.json", max_events=5)
    for i in range(12):
        buf.enqueue("telemetry", {"i": i})
    assert buf.pending_count == 5
    # Oldest dropped — sequences should be the newest five
    assert buf.pending_sequences() == [8, 9, 10, 11, 12]


def test_server_sequence_recovery_contiguous():
    from app.agent_offline_buffer import process_buffered_events_on_server

    out = process_buffered_events_on_server(
        "a1",
        sequence=3,
        buffered_events=[
            {"sequence": 1, "event_type": "telemetry", "payload": {}},
            {"sequence": 2, "event_type": "telemetry", "payload": {}},
            {"sequence": 3, "event_type": "telemetry", "payload": {}},
        ],
        request_missing_from=1,
        last_acked_seq=0,
    )
    assert out["last_acked_seq"] == 3
    assert out["acked_sequences"] == [1, 2, 3]
    assert out.get("missing_from") is None
    assert not (out.get("gap") or {}).get("detected")


def test_server_sequence_gap_does_not_ack_across_hole():
    """RT-05 — contiguous ACK only; hole at 2 must not ACK 3."""
    from app.agent_offline_buffer import process_buffered_events_on_server

    out = process_buffered_events_on_server(
        "a-gap",
        sequence=3,
        buffered_events=[
            {
                "sequence": 1,
                "event_type": "telemetry",
                "payload": {
                    "hostname": "lab-1",
                    "firewall_status": {"enabled": False, "collected": True},
                },
            },
            {
                "sequence": 3,
                "event_type": "telemetry",
                "payload": {
                    "hostname": "lab-1",
                    "firewall_status": {"enabled": True, "collected": True},
                    "defender_status": {"enabled": True},
                },
            },
        ],
        request_missing_from=1,
        last_acked_seq=0,
    )
    assert out["acked_sequences"] == [1]
    assert out["last_acked_seq"] == 1
    assert out.get("missing_from") == 2
    assert out.get("gap", {}).get("detected") is True
    assert out.get("gap", {}).get("missing_from") == 2
    # Newest *ACKed* host payload is seq 1 (seq 3 not ACKed across the hole).
    host = out.get("newest_acked_host_payload") or {}
    assert host.get("hostname") == "lab-1"
    assert host.get("firewall_status", {}).get("enabled") is False
    assert 3 not in (out.get("acked_sequences") or [])


def test_server_sequence_acked_host_payload_newest():
    from app.agent_offline_buffer import process_buffered_events_on_server

    out = process_buffered_events_on_server(
        "a2",
        sequence=2,
        buffered_events=[
            {
                "sequence": 1,
                "payload": {"firewall_status": {"enabled": False}, "hostname": "old"},
            },
            {
                "sequence": 2,
                "payload": {
                    "firewall_status": {"enabled": True},
                    "ssh_config": {"PermitRootLogin": "no"},
                    "hostname": "new",
                },
            },
        ],
        request_missing_from=None,
        last_acked_seq=0,
    )
    assert out["last_acked_seq"] == 2
    host = out.get("newest_acked_host_payload") or {}
    assert host.get("hostname") == "new"
    assert host.get("firewall_status", {}).get("enabled") is True
    assert "ssh_config" in host


def test_command_lifecycle_mapping():
    from app.agents import command_lifecycle

    assert command_lifecycle("pending_approval") == "PENDING"
    assert command_lifecycle("queued") == "APPROVED"
    assert command_lifecycle("sent") == "DELIVERED"
    assert command_lifecycle("acked") == "ACKNOWLEDGED"
    assert command_lifecycle("done") == "COMPLETED"
    assert command_lifecycle("done", verification_status="pending") == "VERIFICATION"
    assert command_lifecycle("done", verification_status="verified") == "VERIFIED"
    assert command_lifecycle("error") == "FAILED"
    assert command_lifecycle("rejected") == "REJECTED"
    assert command_lifecycle("timeout") == "TIMEOUT"
    assert (
        command_lifecycle("timeout", error="Command expired before delivery") == "EXPIRED"
    )
    assert command_lifecycle("acked", phase="EXECUTING") == "EXECUTING"


def test_ed25519_sign_verify_roundtrip():
    from app.agent_security import ed25519_sign, ed25519_verify, generate_ed25519_keypair

    kp = generate_ed25519_keypair()
    msg = b"securaiq-realtime-task-j"
    sig = ed25519_sign(msg, private_key=kp["private_b64"])
    assert ed25519_verify(msg, sig, public_key=kp["public_b64"])
    assert not ed25519_verify(b"tampered", sig, public_key=kp["public_b64"])
    # PEM forms also work
    sig2 = ed25519_sign(msg, private_key=kp["private_pem"])
    assert ed25519_verify(msg, sig2, public_key=kp["public_pem"])


def test_ed25519_command_canonical_roundtrip():
    from app.agent_security import (
        canonical_command_payload,
        ed25519_sign_command,
        ed25519_verify,
        generate_ed25519_keypair,
    )

    kp = generate_ed25519_keypair()
    kwargs = dict(
        command_id="c1",
        agent_id="a1",
        kind="patch_package",
        payload={"package": "curl"},
        nonce="n1",
        event_id="e1",
    )
    sig = ed25519_sign_command(**kwargs, private_key=kp["private_b64"])
    msg = canonical_command_payload(**kwargs)
    assert ed25519_verify(msg, sig, public_key=kp["public_b64"])


def test_seal_both_and_verify_sealed_command(monkeypatch):
    from app.agent_security import (
        generate_ed25519_keypair,
        seal_command_for_delivery,
        verify_sealed_command,
    )

    kp = generate_ed25519_keypair()
    monkeypatch.setenv("AGENT_COMMAND_SIGNING_ALG", "both")
    monkeypatch.setenv("SECURAIQ_AGENT_ED25519_PRIVATE_KEY", kp["private_b64"])
    monkeypatch.setenv("SECURAIQ_AGENT_ED25519_PUBLIC_KEY", kp["public_b64"])
    monkeypatch.setenv("SECURAIQ_AGENT_SIGNING_KEY", "test-hmac-lab-key")
    # Force settings reload path used by helpers (env is primary for keys/alg).
    try:
        from app.config import settings

        monkeypatch.setattr(settings, "agent_command_signing_alg", "both")
        monkeypatch.setattr(settings, "agent_ed25519_private_key", kp["private_b64"])
        monkeypatch.setattr(settings, "agent_ed25519_public_key", kp["public_b64"])
        monkeypatch.setattr(settings, "agent_signing_key", "test-hmac-lab-key")
    except Exception:
        pass

    sealed = seal_command_for_delivery(
        {"id": "cmd-both", "agent_id": "agent-1", "kind": "patch_package", "created_at": 1.0},
        {"package": "curl"},
    )
    assert sealed.get("event_id")
    assert sealed.get("nonce")
    assert sealed.get("signature")
    assert sealed.get("signature_ed25519")
    assert sealed.get("signature_alg") == "both"
    assert sealed.get("signing_public_key") == kp["public_b64"]
    assert verify_sealed_command(sealed) is True

    bad = dict(sealed)
    bad["signature"] = "0" * 64
    assert verify_sealed_command(bad) is False

    bad_ed = dict(sealed)
    bad_ed["signature_ed25519"] = sealed["signature_ed25519"][:-4] + "AAAA"
    assert verify_sealed_command(bad_ed) is False


def test_verify_sealed_command_hmac_default(monkeypatch):
    from app.agent_security import seal_command_for_delivery, verify_sealed_command

    monkeypatch.setenv("AGENT_COMMAND_SIGNING_ALG", "hmac")
    monkeypatch.setenv("SECURAIQ_AGENT_SIGNING_KEY", "hmac-only-lab")
    try:
        from app.config import settings

        monkeypatch.setattr(settings, "agent_command_signing_alg", "hmac")
        monkeypatch.setattr(settings, "agent_signing_key", "hmac-only-lab")
    except Exception:
        pass

    sealed = seal_command_for_delivery(
        {"id": "cmd-hmac", "agent_id": "a2", "kind": "agent_upgrade", "created_at": 2.0},
        {"expected_sha256": "abc"},
    )
    assert sealed.get("signature_alg") == "hmac"
    assert sealed.get("signature")
    assert not sealed.get("signature_ed25519")
    assert verify_sealed_command(sealed) is True


def test_rt17_require_signature_stamps_and_verifies(monkeypatch):
    """RT-17: require flag produces require_verify + valid seal that verifies."""
    from app.agent_security import seal_command_for_delivery, verify_sealed_command

    monkeypatch.setenv("AGENT_COMMAND_SIGNING_ALG", "hmac")
    monkeypatch.setenv("SECURAIQ_AGENT_SIGNING_KEY", "rt17-lab-hmac-key")
    monkeypatch.setenv("AGENT_REQUIRE_COMMAND_SIGNATURE", "true")
    try:
        from app.config import settings

        monkeypatch.setattr(settings, "agent_command_signing_alg", "hmac")
        monkeypatch.setattr(settings, "agent_signing_key", "rt17-lab-hmac-key")
        monkeypatch.setattr(settings, "agent_require_command_signature", True)
    except Exception:
        pass

    sealed = seal_command_for_delivery(
        {"id": "cmd-rt17", "agent_id": "a-rt17", "kind": "patch_package", "created_at": 3.0},
        {"package": "openssl"},
    )
    assert sealed.get("require_verify") is True
    assert sealed.get("signature")
    assert sealed.get("event_id") and sealed.get("nonce")
    assert verify_sealed_command(sealed) is True


def test_rt17_require_flag_rejects_unsigned_dispatch(tmp_path, monkeypatch):
    """RT-17: when require=True, unsigned/failed seals are not marked sent."""
    from app.agent_security import seal_command_for_delivery, verify_sealed_command
    from tests._http_test_utils import configure_isolated_settings

    configure_isolated_settings(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENT_REQUIRE_COMMAND_SIGNATURE", "true")
    monkeypatch.setenv("AGENT_COMMAND_SIGNING_ALG", "hmac")
    monkeypatch.setenv("SECURAIQ_AGENT_SIGNING_KEY", "rt17-dispatch-key")

    from app.config import settings

    monkeypatch.setattr(settings, "agent_require_command_signature", True)
    monkeypatch.setattr(settings, "agent_command_signing_alg", "hmac")
    monkeypatch.setattr(settings, "agent_signing_key", "rt17-dispatch-key")

    from app.agents import (
        _dispatch_queued_commands,
        approve_command,
        enroll_agent,
        ensure_schema,
        request_command,
    )
    from app.db import get_conn
    import app.agent_security as sec

    ensure_schema()
    enrolled = enroll_agent("u-rt17", name="rt17-host", org_id=None)
    aid = enrolled["agent_id"]
    req = request_command(
        "u-rt17",
        aid,
        kind="patch_package",
        payload={"package": "curl"},
    )
    cid = req["id"]
    approve_command("u-rt17", aid, cid, approver_id="u-rt17")

    # Force seal to fail → dispatch must hold queued (not send unsigned).
    real_seal = seal_command_for_delivery

    def _boom(*_a, **_k):
        raise RuntimeError("forced seal failure")

    monkeypatch.setattr(sec, "seal_command_for_delivery", _boom)
    out = _dispatch_queued_commands(aid)
    assert out == []
    row = dict(
        get_conn()
        .execute("SELECT status FROM securaiq_agent_commands WHERE id = ?", (cid,))
        .fetchone()
    )
    assert row["status"] == "queued"

    # Restore real seal — valid signed delivery succeeds and stamps require_verify.
    monkeypatch.setattr(sec, "seal_command_for_delivery", real_seal)
    out2 = _dispatch_queued_commands(aid)
    assert len(out2) == 1
    assert out2[0].get("require_verify") is True
    assert out2[0].get("signature")
    assert verify_sealed_command(out2[0]) is True
    row2 = dict(
        get_conn()
        .execute("SELECT status FROM securaiq_agent_commands WHERE id = ?", (cid,))
        .fetchone()
    )
    assert row2["status"] == "sent"


def test_rt17_agent_refuses_unsigned_when_require_verify(monkeypatch):
    """Agent refuses when require_verify stamped or SECURAIQ_REQUIRE_COMMAND_VERIFY=1."""
    import importlib.util
    from pathlib import Path

    agent_path = Path(__file__).resolve().parents[1] / "scripts" / "securaiq_agent.py"
    spec = importlib.util.spec_from_file_location("securaiq_agent_rt17", agent_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    unsigned = {"id": "c1", "kind": "patch_package", "payload": {}, "require_verify": True}
    assert mod._command_signatures_ok(unsigned, agent_id="a1") is False

    monkeypatch.setenv("SECURAIQ_REQUIRE_COMMAND_VERIFY", "1")
    unsigned2 = {"id": "c2", "kind": "patch_package", "payload": {}}
    assert mod._command_signatures_ok(unsigned2, agent_id="a1") is False


def test_seal_includes_issued_at_expires_at(monkeypatch):
    from app.agent_security import seal_command_for_delivery, verify_sealed_command

    monkeypatch.setenv("AGENT_COMMAND_SIGNING_ALG", "hmac")
    monkeypatch.setenv("SECURAIQ_AGENT_SIGNING_KEY", "seal-expiry-lab")
    try:
        from app.config import settings

        monkeypatch.setattr(settings, "agent_command_signing_alg", "hmac")
        monkeypatch.setattr(settings, "agent_signing_key", "seal-expiry-lab")
        monkeypatch.setattr(settings, "agent_command_ttl_sec", 120)
    except Exception:
        pass

    sealed = seal_command_for_delivery(
        {"id": "cmd-exp", "agent_id": "a3", "kind": "enable_firewall", "created_at": 3.0},
        {"action": "enable_firewall"},
    )
    assert sealed.get("issued_at") is not None
    assert sealed.get("expires_at") is not None
    assert float(sealed["expires_at"]) > float(sealed["issued_at"])
    assert verify_sealed_command(sealed) is True


def test_verify_sealed_command_rejects_expired(monkeypatch):
    from app.agent_security import seal_command_for_delivery, verify_sealed_command

    monkeypatch.setenv("AGENT_COMMAND_SIGNING_ALG", "hmac")
    monkeypatch.setenv("SECURAIQ_AGENT_SIGNING_KEY", "seal-expired-lab")
    try:
        from app.config import settings

        monkeypatch.setattr(settings, "agent_command_signing_alg", "hmac")
        monkeypatch.setattr(settings, "agent_signing_key", "seal-expired-lab")
    except Exception:
        pass

    sealed = seal_command_for_delivery(
        {"id": "cmd-old", "agent_id": "a4", "kind": "patch_package", "created_at": 4.0},
        {"package": "curl"},
    )
    # Tamper times without re-signing → signature must fail.
    bad = dict(sealed)
    bad["expires_at"] = float(sealed["issued_at"]) - 10
    assert verify_sealed_command(bad) is False

    # Re-sign with past expiry, then clock skew check must fail.
    from app.agent_security import sign_command

    past = dict(sealed)
    past["issued_at"] = float(sealed["issued_at"]) - 10_000
    past["expires_at"] = float(sealed["issued_at"]) - 9_000
    past["signature"] = sign_command(
        command_id=past["id"],
        agent_id=past["agent_id"],
        kind=past["kind"],
        payload=past["payload"],
        nonce=past["nonce"],
        event_id=past["event_id"],
        issued_at=past["issued_at"],
        expires_at=past["expires_at"],
    )
    assert verify_sealed_command(past) is False


def test_agent_refuses_expired_seal(monkeypatch):
    import importlib.util
    import time
    from pathlib import Path

    agent_path = Path(__file__).resolve().parents[1] / "scripts" / "securaiq_agent.py"
    spec = importlib.util.spec_from_file_location("securaiq_agent_expiry", agent_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    expired = {
        "id": "c-exp",
        "kind": "enable_firewall",
        "payload": {},
        "expires_at": time.time() - 120,
        "require_verify": True,
        "signature": "deadbeef",
    }
    assert mod._command_signatures_ok(expired, agent_id="a1") is False


def test_agent_replay_headers_include_sig():
    import hashlib
    import hmac
    import importlib.util
    from pathlib import Path

    from app.agent_auth import sign_payload

    agent_path = Path(__file__).resolve().parents[1] / "scripts" / "securaiq_agent.py"
    spec = importlib.util.spec_from_file_location("securaiq_agent_replay", agent_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    token = "agentid123.agentkey456"
    body = b'{"hostname":"lab"}'
    headers = mod._replay_headers(token, body)
    assert headers.get("X-SecuraIQ-Ts")
    assert headers.get("X-SecuraIQ-Nonce")
    assert headers.get("X-SecuraIQ-Sig")
    expected = sign_payload("agentkey456", headers["X-SecuraIQ-Ts"], headers["X-SecuraIQ-Nonce"], body)
    assert hmac.compare_digest(headers["X-SecuraIQ-Sig"], expected)
    # Sanity: body digest is in the signed message
    digest = hashlib.sha256(body).hexdigest()
    assert digest in f"{headers['X-SecuraIQ-Ts']}.{headers['X-SecuraIQ-Nonce']}.{digest}"


def test_checkin_sequence_ack(tmp_path, monkeypatch):
    from tests._http_test_utils import configure_isolated_settings

    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents import checkin, enroll_agent, ensure_schema, get_agent

    ensure_schema()
    enrolled = enroll_agent("u1", name="seq-host", org_id=None)
    aid = enrolled["agent_id"]
    result = checkin(
        aid,
        {
            "hostname": "seq-host",
            "os": "linux",
            "sequence": 2,
            "buffered_events": [
                {"sequence": 1, "event_type": "telemetry", "payload": {"x": 1}},
                {"sequence": 2, "event_type": "telemetry", "payload": {"x": 2}},
            ],
            "request_missing_from": 1,
        },
    )
    assert result.get("ok")
    assert result.get("last_acked_seq") == 2
    assert 1 in (result.get("acked_sequences") or [])
    agent = get_agent(aid)
    assert int(agent.get("last_telemetry_seq") or 0) == 2


def test_checkin_sequence_gap_publishes_and_keeps_watermark(tmp_path, monkeypatch):
    """RT-05 — gap in buffered_events → missing_from + sequence_gap publish; no ACK across hole."""
    from tests._http_test_utils import configure_isolated_settings

    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents import checkin, enroll_agent, ensure_schema, get_agent

    ensure_schema()
    enrolled = enroll_agent("u1", name="gap-host", org_id=None)
    aid = enrolled["agent_id"]
    publishes: list[dict] = []
    monkeypatch.setattr(
        "app.realtime_bus.publish",
        lambda **kw: publishes.append(kw),
    )
    result = checkin(
        aid,
        {
            "hostname": "gap-host",
            "os": "linux",
            "sequence": 3,
            "buffered_events": [
                {
                    "sequence": 1,
                    "event_type": "telemetry",
                    "payload": {
                        "hostname": "gap-host",
                        "firewall_status": {"enabled": False, "collected": True},
                    },
                },
                {
                    "sequence": 3,
                    "event_type": "telemetry",
                    "payload": {"firewall_status": {"enabled": True}},
                },
            ],
            "request_missing_from": 1,
        },
    )
    assert result.get("ok")
    assert result.get("last_acked_seq") == 1
    assert result.get("acked_sequences") == [1]
    assert result.get("missing_from") == 2
    assert (result.get("gap") or {}).get("detected") is True
    agent = get_agent(aid)
    assert int(agent.get("last_telemetry_seq") or 0) == 1
    assert any(
        p.get("type") == "agent" and p.get("status") == "sequence_gap" and p.get("id") == aid
        for p in publishes
    )
