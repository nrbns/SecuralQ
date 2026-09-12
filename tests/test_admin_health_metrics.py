"""Admin health + metrics include Streams / agent crypto posture."""

from __future__ import annotations


def test_admin_health_includes_event_bus_and_crypto(tmp_path, monkeypatch):
    from tests._http_test_utils import configure_isolated_settings

    configure_isolated_settings(monkeypatch, tmp_path)
    from app.admin_health import collect_admin_health

    board = collect_admin_health()
    assert board["overall"] in ("green", "yellow", "red")
    comps = board["components"]
    assert "api" in comps
    assert "database" in comps
    assert "event_bus" in comps
    assert "agent_gateway" in comps
    assert "agent_crypto" in comps
    assert comps["event_bus"]["status"] in ("green", "yellow", "red")


def test_metrics_include_stream_gauges():
    from app.metrics import render_prometheus

    text = render_prometheus()
    assert "securaiq_uptime_seconds" in text
    assert "securaiq_stream_length" in text
    assert "securaiq_stream_dlq_length" in text
    assert "securaiq_stream_pending" in text
    assert "securaiq_agents_total" in text
