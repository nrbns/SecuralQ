"""Phase-1 ops remaining board + owned-host gate."""

from __future__ import annotations

import os


def test_phase1_ops_remaining_board():
    from app.phase1_ops_remaining import phase1_ops_remaining

    board = phase1_ops_remaining()
    assert board["code_unblocked_complete"] is True
    ids = {i["id"] for i in board["items"]}
    assert "owned_host_acceptance" in ids
    assert "redis_sentinel_ha" in ids
    assert "http_capacity_ladder" in ids
    assert "authenticode_notarize" in ids
    assert "worm_object_lock" in ids
    # Without live measure / Docker inject, ops_still_open is expected
    assert isinstance(board["ops_still_open"], list)


def test_owned_host_gate(monkeypatch):
    from app.phase1_ops_remaining import owned_host_authorized, owned_host_status

    monkeypatch.delenv("SECURAIQ_OWNED_HOST", raising=False)
    assert owned_host_authorized() is False
    assert owned_host_status()["live_mutation_authorized"] is False
    monkeypatch.setenv("SECURAIQ_OWNED_HOST", "1")
    assert owned_host_authorized() is True
    st = owned_host_status()
    # Recorded acceptance_server_owned pass keeps the board lab without env.
    if st.get("live_server_acceptance_ok"):
        assert st["status"] == "lab"


def test_acceptance_server_requires_owned_host(monkeypatch):
    import scripts.realtime_acceptance_demo as demo

    monkeypatch.delenv("SECURAIQ_OWNED_HOST", raising=False)
    rc = demo.main(["--server", "http://127.0.0.1:8080", "--token", "x"])
    assert rc == 3


def test_soft_ladder_uses_capacity_status(tmp_path, monkeypatch):
    from tests._http_test_utils import configure_isolated_settings

    class _MP:
        def setattr(self, target, name=None, value=None, raising=True):
            if isinstance(target, str) and value is None and name is not None:
                import importlib

                mod_name, _, attr = target.rpartition(".")
                obj = importlib.import_module(mod_name)
                setattr(obj, attr, name)
                return
            setattr(target, name, value)

    configure_isolated_settings(_MP(), tmp_path)
    from app.capacity_soft import soft_checkin_ladder
    from app.db import reset_conn_for_tests
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    try:
        out = soft_checkin_ladder("t-soft", [5, 10])
        assert out["ok"] is True
        assert "http_500_measured" in out
        assert all(r.get("truncated_checkin") for r in out["rungs"])
    finally:
        reset_conn_for_tests()


def test_checkin_payload_empty_host_dicts_excluded():
    """API must not inject empty {} host blobs that force host-control work."""
    from app.agents_api import CheckinPayload

    p = CheckinPayload(hostname="h", truncated=True)
    dumped = p.model_dump(exclude_none=True)
    assert dumped.get("truncated") is True
    assert "firewall_status" not in dumped
    assert "defender_status" not in dumped


def test_platform_ready_shape():
    from app.platform_ready import platform_ready

    body = platform_ready()
    assert "ready" in body
    assert "checks" in body
    assert "database" in body["checks"]


def test_capacity_board_sees_http_500():
    from app.phase1_ops_remaining import capacity_http_status

    cap = capacity_http_status()
    assert cap.get("http_500_measured") is True
    assert int(cap.get("http_top_measured") or 0) >= 500

