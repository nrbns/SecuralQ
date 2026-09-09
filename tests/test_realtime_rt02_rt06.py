"""SSE tenant filter + RT-06 processor idempotency foundations."""

from __future__ import annotations

import importlib

import pytest

from app import event_idempotency, event_processor, realtime_bus


def _iso_db(monkeypatch, tmp_path):
    data_dir = tmp_path / "rt06"
    data_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)
    event_idempotency.clear_processed_for_tests()
    return data_dir


@pytest.fixture(autouse=True)
def _reset_bus():
    realtime_bus.clear_replay_buffer_for_tests()
    event_processor.reset_processor_for_tests()
    yield
    realtime_bus.clear_replay_buffer_for_tests()
    event_processor.reset_processor_for_tests()


# --- SSE tenant filter -------------------------------------------------------


def test_sse_push_allowed_auth_off_delivers_unscoped():
    assert realtime_bus.sse_push_allowed_for_client(
        {"type": "job", "event_id": "e1"},
        auth_enabled=False,
        client_user_id="local",
    )


def test_sse_push_allowed_auth_on_drops_unscoped():
    assert not realtime_bus.sse_push_allowed_for_client(
        {"type": "job", "event_id": "e1"},
        auth_enabled=True,
        client_user_id="user-a",
        client_org_ids=["org-a"],
    )


def test_sse_push_allowed_auth_on_matches_user_id():
    assert realtime_bus.sse_push_allowed_for_client(
        {"type": "vuln", "user_id": "user-a", "event_id": "e2"},
        auth_enabled=True,
        client_user_id="user-a",
        client_org_ids=[],
    )
    assert not realtime_bus.sse_push_allowed_for_client(
        {"type": "vuln", "user_id": "user-b", "event_id": "e3"},
        auth_enabled=True,
        client_user_id="user-a",
        client_org_ids=[],
    )


def test_sse_push_allowed_auth_on_matches_org_id():
    assert realtime_bus.sse_push_allowed_for_client(
        {"type": "incident", "org_id": "org-a", "event_id": "e4"},
        auth_enabled=True,
        client_user_id="user-a",
        client_org_ids=["org-a", "org-z"],
    )
    assert realtime_bus.sse_push_allowed_for_client(
        {"type": "incident", "organization_id": "org-z", "event_id": "e5"},
        auth_enabled=True,
        client_user_id="user-a",
        client_org_ids=["org-a", "org-z"],
    )
    assert not realtime_bus.sse_push_allowed_for_client(
        {"type": "incident", "org_id": "org-other", "event_id": "e6"},
        auth_enabled=True,
        client_user_id="user-a",
        client_org_ids=["org-a"],
    )


def test_sse_push_allowed_rejects_non_dict():
    assert not realtime_bus.sse_push_allowed_for_client(
        None, auth_enabled=True, client_user_id="u1"
    )
    assert not realtime_bus.sse_push_allowed_for_client(
        None, auth_enabled=False, client_user_id="local"
    )


# --- RT-06 idempotency -------------------------------------------------------


def test_idempotency_mark_and_already_processed(tmp_path, monkeypatch):
    _iso_db(monkeypatch, tmp_path)
    from app import event_idempotency as eid

    eid.ensure_processed_events_schema()
    assert not eid.already_processed("evt-100")
    eid.mark_processed("evt-100")
    assert eid.already_processed("evt-100")
    assert not eid.already_processed("")
    assert not eid.already_processed(None)


def test_process_event_skips_side_effects_when_already_processed(tmp_path, monkeypatch):
    _iso_db(monkeypatch, tmp_path)
    calls: list[str] = []
    original = event_processor.HANDLERS.get("vuln")

    def _handler(ev):
        calls.append(str(ev.get("event_id")))

    monkeypatch.setitem(event_processor.HANDLERS, "vuln", _handler)
    try:
        event_processor.process_event(
            {"type": "vuln", "event_type": "vuln", "event_id": "idem-1", "user_id": "u1"}
        )
        assert calls == ["idem-1"]

        event_processor.process_event(
            {"type": "vuln", "event_type": "vuln", "event_id": "idem-1", "user_id": "u1"}
        )
        assert calls == ["idem-1"]
    finally:
        if original is not None:
            event_processor.HANDLERS["vuln"] = original


def test_process_event_marks_only_after_success(tmp_path, monkeypatch):
    _iso_db(monkeypatch, tmp_path)
    from app import event_idempotency as eid

    original = event_processor.HANDLERS.get("gap")

    def _boom(_ev):
        raise RuntimeError("handler blew up")

    monkeypatch.setitem(event_processor.HANDLERS, "gap", _boom)
    try:
        event_processor.process_event(
            {"type": "gap", "event_type": "gap", "event_id": "fail-1", "user_id": "u1"}
        )
        assert not eid.already_processed("fail-1")
    finally:
        if original is not None:
            event_processor.HANDLERS["gap"] = original


def test_publish_still_works_when_idempotency_store_broken(monkeypatch):
    """Writers must never fail because of the processed-events ledger."""

    def _boom(*_a, **_k):
        raise RuntimeError("db down")

    monkeypatch.setattr("app.event_idempotency.already_processed", _boom)
    monkeypatch.setattr("app.event_idempotency.mark_processed", _boom)
    event_processor.process_event(
        {"type": "vuln", "event_type": "vuln", "event_id": "w1", "user_id": "u1"}
    )
    realtime_bus.publish(type="job", id="j-writer-ok", event_id="writer-ok-1")
