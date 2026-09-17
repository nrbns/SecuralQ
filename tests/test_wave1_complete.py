"""Wave 1 complete: HA metrics, sequence/gap, SQLite offline queue, commercial profile, control overrides."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests._http_test_utils import configure_isolated_settings


def test_sentinel_failover_dry_run_and_metrics():
    from scripts.sentinel_failover_measure import collect_stream_metrics, dry_run, metrics_only

    assert dry_run() == 0
    assert metrics_only() == 0
    m = collect_stream_metrics()
    assert isinstance(m, dict)
    assert "dlq_count" in m
    assert "stream_length" in m


def test_expected_next_seq_and_contiguous_apply_ack(tmp_path):
    from app.agent_offline_buffer import OfflineTelemetryBuffer, expected_next_seq

    assert expected_next_seq(0) == 1
    assert expected_next_seq(102) == 103

    buf = OfflineTelemetryBuffer("seq-agent", path=tmp_path / "q.json", max_events=50)
    for i in range(1, 6):
        buf.enqueue("telemetry", {"n": i})
    # Sparse ack list with hole must not jump watermark past 2
    removed = buf.apply_server_ack({"acked_sequences": [1, 2, 4]})
    assert removed >= 2
    assert buf.last_acked_seq == 2
    assert expected_next_seq(buf.last_acked_seq) == 3
    assert 4 in buf.pending_sequences() or 5 in buf.pending_sequences()


def test_sqlite_offline_queue_survives_reload(tmp_path):
    from app.agent_offline_buffer import OfflineTelemetryBuffer

    path = tmp_path / "offline.sqlite"
    buf = OfflineTelemetryBuffer("sql-agent", path=path, backend="sqlite", max_events=100)
    for i in range(1, 6):
        buf.enqueue("telemetry", {"i": i})
    assert buf.pending_count == 5
    buf.apply_server_ack({"last_acked_seq": 3})
    assert buf.last_acked_seq == 3
    assert buf.pending_sequences() == [4, 5]

    buf2 = OfflineTelemetryBuffer("sql-agent", path=path, backend="sqlite")
    assert buf2.last_acked_seq == 3
    assert buf2.pending_sequences() == [4, 5]


def test_checkin_returns_expected_next_seq_on_gap(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents import checkin, enroll_agent
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("seq_gap_user", "password123", role="admin")
    user, _tok = login("seq_gap_user", "password123")
    agent = enroll_agent(user.id, name="seq-gap")
    aid = agent["agent_id"]

    # Establish watermark at 1
    r1 = checkin(
        aid,
        {
            "hostname": "h",
            "os": "linux",
            "sequence": 1,
            "firewall_status": {"collected": True, "enabled": True, "backend": "ufw"},
        },
    )
    assert r1.get("ok") is True
    assert int(r1.get("expected_next_seq") or 0) == 2

    # Jump to 4 with buffer missing 2 → gap, watermark stays / expected_next=2
    r2 = checkin(
        aid,
        {
            "hostname": "h",
            "os": "linux",
            "sequence": 4,
            "buffered_events": [
                {"sequence": 3, "event_type": "telemetry", "payload": {}},
                {"sequence": 4, "event_type": "telemetry", "payload": {}},
            ],
            "request_missing_from": 2,
            "firewall_status": {"collected": True, "enabled": True, "backend": "ufw"},
        },
    )
    assert r2.get("ok") is True
    assert int(r2.get("expected_next_seq") or 0) == 2
    gap = r2.get("gap") or {}
    assert gap.get("detected") is True or r2.get("missing_from") == 2


def test_commercial_profile_enforce_blocks_incomplete(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.config import settings
    from app.production_profile import assert_commercial_profile, production_profile_status

    monkeypatch.setattr(settings, "commercial_profile_enforce", False, raising=False)
    assert_commercial_profile()  # no-op
    st = production_profile_status()
    assert st["production_ready_agent_security"] is False

    monkeypatch.setattr(settings, "commercial_profile_enforce", True, raising=False)
    with pytest.raises(RuntimeError, match="COMMERCIAL_PROFILE"):
        assert_commercial_profile()


def test_commercial_profile_ready_when_complete(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.config import settings
    from app.production_profile import assert_commercial_profile, production_profile_status

    for flag in (
        "agent_mtls_enabled",
        "agent_mtls_proxy_verify",
        "agent_mtls_require_fingerprint_match",
        "agent_require_command_signature",
        "agent_require_replay_protection",
    ):
        monkeypatch.setattr(settings, flag, True, raising=False)
    monkeypatch.setattr(settings, "agent_command_signing_alg", "ed25519", raising=False)
    monkeypatch.setattr(settings, "agent_ed25519_private_key", "PRIV", raising=False)
    monkeypatch.setattr(settings, "agent_ed25519_public_key", "PUB", raising=False)
    monkeypatch.setattr(settings, "commercial_profile_enforce", True, raising=False)
    st = production_profile_status()
    assert st["commercial_ready_command_signing"] is True
    assert_commercial_profile()


def test_custom_control_registry_override(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    import app.controls.test_registry as reg

    custom = tmp_path / "custom_tests.json"
    custom.write_text(
        json.dumps(
            {
                "tests": [
                    {
                        "test_name": "host_firewall",
                        "control_bindings": [["iso27001", "A.8.20"]],
                        "remediation_hint": "custom hint",
                        "frequency": "checkin",
                        "verifiability": "machine",
                        "data_sources": ["securaiq_agent.firewall_status"],
                        "expected_state": {"enabled": True},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SECURAIQ_CONTROL_REGISTRY_PATH", str(custom))
    reg._CUSTOM_CACHE = None
    entry = reg.get_test_entry("host_firewall")
    assert entry is not None
    bindings = {(b[0], b[1]) for b in entry["control_bindings"]}
    assert ("iso27001", "A.8.20") in bindings
    assert entry.get("remediation_hint") == "custom hint"
    cmap = reg.build_control_test_map()
    assert "host_firewall" in cmap.get(("iso27001", "A.8.20"), [])
    reg._CUSTOM_CACHE = None


def test_ops_example_files_exist():
    root = Path(__file__).resolve().parents[1]
    assert (root / "data/ops/.gitkeep").is_file() or (root / "data/ops").is_dir()
    assert (root / "data/ops/sentinel_failover_measurements.example.jsonl").is_file()
    assert (root / "data/controls/custom_tests.example.json").is_file()
