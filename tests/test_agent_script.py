"""Tests for scripts/securaiq_agent.py -- the standalone, stdlib-only agent
script (not part of the `app` package, so it's imported directly by path).

Covers the deep-telemetry collectors added for task #140 (each must return
{"collected": bool, "reason": str, ...} and never raise) and the self-upgrade
checksum-verification logic (execute_agent_upgrade) -- the one narrowly-
scoped self-modification this agent is allowed, and it must refuse to touch
disk on any checksum mismatch or missing expected_sha256.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "securaiq_agent.py"


@pytest.fixture(scope="module")
def agent_mod():
    spec = importlib.util.spec_from_file_location("securaiq_agent_script", _SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["securaiq_agent_script"] = mod
    spec.loader.exec_module(mod)
    return mod


# --- deep telemetry collectors: always a dict, never raises, honest degrade --


COLLECTOR_NAMES = [
    "_services",
    "_local_users",
    "_firewall_status",
    "_disk_encryption_status",
    "_defender_status",
    "_startup_apps",
    "_ssh_config",
]


@pytest.mark.parametrize("name", COLLECTOR_NAMES)
def test_collector_returns_dict_with_collected_key(agent_mod, name):
    fn = getattr(agent_mod, name)
    result = fn()
    assert isinstance(result, dict)
    assert "collected" in result
    assert isinstance(result["collected"], bool)
    if not result["collected"]:
        assert result.get("reason"), f"{name} reported collected=False with no reason"


def test_local_users_reads_real_etc_passwd_on_linux(agent_mod):
    """On this sandbox (Linux), local_users must actually read /etc/passwd,
    not silently degrade -- confirms the honest-degrade path isn't
    swallowing a real, available signal."""
    result = agent_mod._local_users()
    assert result["collected"] is True
    assert isinstance(result["items"], list)


def test_ssh_config_reports_not_applicable_when_no_sshd_config(agent_mod, tmp_path, monkeypatch):
    """When no sshd_config exists, this must be reported as "not applicable"
    (collected=False + a real reason), never a fabricated empty-but-collected
    result."""
    import os

    monkeypatch.setattr(os.path, "isfile", lambda p: False)
    result = agent_mod._ssh_config()
    assert result["collected"] is False
    assert "sshd_config" in result["reason"].lower() or "ssh" in result["reason"].lower()


def test_defender_status_not_applicable_on_non_windows(agent_mod, monkeypatch):
    monkeypatch.setattr(agent_mod.platform, "system", lambda: "Linux")
    result = agent_mod._defender_status()
    assert result["collected"] is False
    assert "not applicable" in result["reason"].lower()


def test_collect_safe_falls_back_honestly_on_collector_crash(agent_mod):
    def _boom():
        raise RuntimeError("simulated collector crash")

    result = agent_mod._collect_safe(_boom, {"collected": False, "items": []})
    assert result["collected"] is False
    assert "simulated collector crash" in result["reason"]


def test_collect_snapshot_includes_all_deep_telemetry_keys(agent_mod):
    snapshot = agent_mod.collect_snapshot()
    for key in (
        "services", "local_users", "firewall_status", "disk_encryption_status",
        "defender_status", "startup_apps", "ssh_config",
    ):
        assert key in snapshot
        assert isinstance(snapshot[key], dict)
        assert "collected" in snapshot[key]


# --- self-upgrade: checksum-verified, never blind ----------------------------


def test_execute_agent_upgrade_refuses_without_expected_sha256(agent_mod):
    result = agent_mod.execute_agent_upgrade({}, server="https://example.invalid")
    assert result["ok"] is False
    assert "expected_sha256" in result["error"]


def test_execute_agent_upgrade_rejects_checksum_mismatch(agent_mod, monkeypatch):
    """If the server's install-script content doesn't match what was
    approved, nothing on disk is touched and the mismatch is reported."""
    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"print('this is not what was approved')"

    monkeypatch.setattr(agent_mod.urllib.request, "urlopen", lambda *a, **k: _FakeResp())

    wrong_hash = hashlib.sha256(b"something else entirely").hexdigest()
    result = agent_mod.execute_agent_upgrade({"expected_sha256": wrong_hash}, server="https://example.invalid")
    assert result["ok"] is False
    assert "checksum mismatch" in result["error"].lower()
    assert result["expected_sha256"] == wrong_hash


def test_execute_agent_upgrade_writes_file_on_checksum_match(agent_mod, tmp_path, monkeypatch):
    fake_content = b"# a legitimate new agent script\nprint('hello')\n"
    real_hash = hashlib.sha256(fake_content).hexdigest()

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_content

    monkeypatch.setattr(agent_mod.urllib.request, "urlopen", lambda *a, **k: _FakeResp())

    # point __file__ at a throwaway path so this test never touches the real script
    fake_self = tmp_path / "securaiq_agent.py"
    fake_self.write_text("# old content\n")
    monkeypatch.setattr(agent_mod, "__file__", str(fake_self))

    result = agent_mod.execute_agent_upgrade({"expected_sha256": real_hash}, server="https://example.invalid")
    assert result["ok"] is True
    assert result["sha256"] == real_hash
    assert fake_self.read_bytes() == fake_content


def test_execute_agent_upgrade_handles_download_failure(agent_mod, monkeypatch):
    def _raise(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(agent_mod.urllib.request, "urlopen", _raise)
    result = agent_mod.execute_agent_upgrade({"expected_sha256": "abc123"}, server="https://example.invalid")
    assert result["ok"] is False
    assert "download" in result["error"].lower()


def test_run_commands_exits_process_after_successful_upgrade(agent_mod, tmp_path, monkeypatch):
    """run_commands() must exit the process after a successful agent_upgrade
    so a service supervisor restarts it with the new code -- but only AFTER
    reporting the result back to the server."""
    fake_content = b"# new agent code\n"
    real_hash = hashlib.sha256(fake_content).hexdigest()

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_content

    reported = []

    def _fake_send_result(server, token, command_id, status, result, *, insecure=False):
        reported.append((command_id, status, result))
        return {"ok": True}

    fake_self = tmp_path / "securaiq_agent.py"
    fake_self.write_text("# old\n")
    monkeypatch.setattr(agent_mod, "__file__", str(fake_self))
    monkeypatch.setattr(agent_mod.urllib.request, "urlopen", lambda *a, **k: _FakeResp())
    monkeypatch.setattr(agent_mod, "send_command_result", _fake_send_result)

    with pytest.raises(SystemExit) as exc_info:
        agent_mod.run_commands(
            "https://example.invalid", "tok",
            [{"id": "cmd-1", "kind": "agent_upgrade", "payload": {"expected_sha256": real_hash}}],
        )
    assert exc_info.value.code == 0
    assert len(reported) == 1
    assert reported[0][1] == "done"


def test_run_commands_reports_unknown_kind_as_error(agent_mod, monkeypatch):
    reported = []

    def _fake_send_result(server, token, command_id, status, result, *, insecure=False):
        reported.append((command_id, status, result))
        return {"ok": True}

    monkeypatch.setattr(agent_mod, "send_command_result", _fake_send_result)
    agent_mod.run_commands("https://example.invalid", "tok", [{"id": "cmd-2", "kind": "delete_everything", "payload": {}}])
    assert len(reported) == 1
    assert reported[0][1] == "error"
    assert "Unknown command kind" in reported[0][2]["error"]
