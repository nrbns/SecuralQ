"""Job completion → SSE domain event mapping."""

from app.realtime_events import publish_job_completion


def test_publish_job_completion_xdr(monkeypatch):
    events: list[dict] = []

    def _capture(**kwargs):
        events.append(kwargs)

    monkeypatch.setattr("app.realtime_bus.publish", _capture)
    publish_job_completion("xdr_sync", {"new": 3, "user_id": "local"}, job_id="j1", status="done")
    types = [e.get("type") for e in events]
    assert "tool" in types
    assert "xdr_batch" in types


def test_publish_job_completion_error_only_tool(monkeypatch):
    events: list[dict] = []

    def _capture(**kwargs):
        events.append(kwargs)

    monkeypatch.setattr("app.realtime_bus.publish", _capture)
    publish_job_completion("scan_execute", {}, job_id="j2", status="error")
    assert len(events) == 1
    assert events[0].get("type") == "tool"
    assert events[0].get("status") == "error"
