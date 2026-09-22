"""Soft chaos local buffer — CI gate (not Redis kill / Sentinel)."""

from __future__ import annotations

from scripts.realtime_chaos_test import run_local_buffer_chaos


def test_realtime_chaos_local_only():
    out = run_local_buffer_chaos()
    assert out["ok"] is True
    assert out["enqueued"] == 5
    assert out["pending_after_ack"] == 0
    assert "not production proof" in (out.get("note") or "")
