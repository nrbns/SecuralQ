"""Unit tests for allowlisted disable_ssh_root file rewrite (no real sshd)."""

from __future__ import annotations

from unittest import mock


def test_execute_disable_ssh_root_rewrites_temp_config(tmp_path, monkeypatch):
    from scripts import securaiq_agent as agent

    cfg = tmp_path / "sshd_config"
    cfg.write_text("# comment\nPermitRootLogin yes\nPasswordAuthentication yes\n", encoding="utf-8")

    monkeypatch.setattr(agent.platform, "system", lambda: "Linux")
    monkeypatch.setattr(agent.os.path, "isfile", lambda p: False)
    monkeypatch.setattr(agent, "_run", lambda *a, **k: (True, "reloaded"))

    import builtins

    orig_open = builtins.open

    def gated_open(path, *args, **kwargs):
        if str(path) == "/etc/ssh/sshd_config":
            return orig_open(cfg, *args, **kwargs)
        return orig_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", gated_open)

    result = agent.execute_disable_ssh_root({})
    assert result["ok"] is True
    text = cfg.read_text(encoding="utf-8")
    assert "PermitRootLogin no" in text
    assert "PermitRootLogin yes" not in text


def test_execute_disable_ssh_root_windows_honest(monkeypatch):
    from scripts import securaiq_agent as agent

    monkeypatch.setattr(agent.platform, "system", lambda: "Windows")
    result = agent.execute_disable_ssh_root({})
    assert result["ok"] is False
    assert "Windows" in result["error"]
