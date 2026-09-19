"""Unit tests for HTTP load ladder wave mode (no live server required)."""

from __future__ import annotations


def test_run_wave_counts_success(monkeypatch):
    import scripts.realtime_load_test as m

    calls = {"n": 0}

    def fake_checkin(server, token, *, insecure=False, timeout=90.0):
        calls["n"] += 1
        return True, 0.05

    monkeypatch.setattr(m, "_checkin", fake_checkin)
    out = m.run_wave(
        server="http://127.0.0.1:8080",
        tokens=[f"t{i}" for i in range(10)],
        agents=10,
        workers=4,
        insecure=False,
    )
    assert out["mode"] == "wave"
    assert out["checkin_ok"] == 10
    assert out["checkin_fail"] == 0
    assert out["success_rate_pct"] == 100.0
    assert calls["n"] == 10


def test_run_wave_counts_timeouts_as_fail(monkeypatch):
    import scripts.realtime_load_test as m

    def fake_checkin(server, token, *, insecure=False, timeout=90.0):
        return False, 1.0

    monkeypatch.setattr(m, "_checkin", fake_checkin)
    out = m.run_wave(
        server="http://x",
        tokens=["a", "b", "c"],
        agents=3,
        workers=2,
        insecure=False,
    )
    assert out["checkin_ok"] == 0
    assert out["checkin_fail"] == 3
    assert out["success_rate_pct"] == 0.0
