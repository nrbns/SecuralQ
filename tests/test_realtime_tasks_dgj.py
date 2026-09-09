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
