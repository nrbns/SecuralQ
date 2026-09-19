"""Immediate #3 — soft-poll is SSE-offline/stall fallback only.

Asserts static/app.js keeps Command Center + notification badge polls
gated behind `_sseRealtimeLive` / `__securaiqSseLive`.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_JS = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
WS_JS = (ROOT / "static" / "workspace.js").read_text(encoding="utf-8")


def test_soft_poll_helper_exported():
    assert "function _sseRealtimeLive" in APP_JS
    assert "window.__securaiqSseLive = _sseRealtimeLive" in APP_JS
    assert "SSE_STALL_MS" in APP_JS
    assert "SSE stall" in APP_JS


def test_command_center_poll_gated():
    assert "if (currentView === \"command\" && !_sseRealtimeLive()) loadCommandCenter()" in APP_JS


def test_workspace_refresh_poll_gated():
    # Soft refresh interval must early-return when SSE live
    idx = APP_JS.find("Fallback live refresh if SSE offline/stalled")
    assert idx > 0
    chunk = APP_JS[idx : idx + 600]
    assert "if (_sseRealtimeLive()) return;" in chunk


def test_notif_badge_poll_gated():
    assert "setInterval(refreshNotifBadge, 45000)" not in APP_JS
    assert "_sseRealtimeLive()) return" in APP_JS
    assert "refreshNotifBadge();" in APP_JS
    # gated interval body calls refreshNotifBadge after live check
    idx = APP_JS.find("Badge soft-poll only when SSE is down")
    assert idx > 0
    chunk = APP_JS[idx : idx + 350]
    assert "_sseRealtimeLive()" in chunk
    assert "refreshNotifBadge()" in chunk


def test_software_poll_uses_shared_helper():
    assert "window.__securaiqSseLive" in WS_JS
    assert "startSoftwarePollFallback" in WS_JS
