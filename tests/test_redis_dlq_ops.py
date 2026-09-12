"""Unit tests for Redis client factory + DLQ admin helpers (mocked Redis)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest


def test_redis_client_url_mode(monkeypatch):
    from app import redis_client

    redis_client.reset_clients_for_tests()
    monkeypatch.setattr(redis_client, "redis_url", lambda: "redis://localhost:6379/0")
    monkeypatch.setattr(redis_client, "sentinel_hosts", lambda: [])
    assert redis_client.redis_enabled() is True
    assert redis_client.connection_mode() == "url"
    desc = redis_client.describe_backend()
    assert desc["mode"] == "url"
    assert desc["url_set"] is True


def test_redis_client_sentinel_mode(monkeypatch):
    from app import redis_client

    redis_client.reset_clients_for_tests()
    monkeypatch.setattr(redis_client, "redis_url", lambda: "")
    monkeypatch.setattr(redis_client, "sentinel_hosts", lambda: [("redis-sentinel", 26379)])
    monkeypatch.setattr(redis_client, "sentinel_master", lambda: "mymaster")
    assert redis_client.redis_enabled() is True
    assert redis_client.connection_mode() == "sentinel"
    desc = redis_client.describe_backend()
    assert desc["sentinel_hosts"] == ["redis-sentinel:26379"]
    assert desc["sentinel_master"] == "mymaster"


def test_sentinel_hosts_parse(monkeypatch):
    from app import redis_client
    from app import config as config_mod

    monkeypatch.setattr(config_mod.settings, "redis_sentinel_hosts", "a:26379, b:26380", raising=False)
    hosts = redis_client.sentinel_hosts()
    assert hosts == [("a", 26379), ("b", 26380)]


def test_list_dlq_entries_no_redis(monkeypatch):
    from app import event_processor

    monkeypatch.setattr(event_processor, "_redis_configured", lambda: False)
    assert event_processor.list_dlq_entries() == []


def test_list_dlq_entries_mocked(monkeypatch):
    from app import event_processor

    monkeypatch.setattr(event_processor, "_redis_configured", lambda: True)
    monkeypatch.setattr(event_processor, "_dlq_key", lambda: "securaiq:events:dlq")

    client = MagicMock()
    client.xrange.return_value = [
        (
            "1-0",
            {
                "payload": json.dumps({"event_id": "e1", "type": "vuln"}),
                "error": "boom",
                "delivery_count": "5",
                "stream_id": "0-1",
                "source_stream": "securaiq:events",
                "ts": "1",
            },
        )
    ]

    monkeypatch.setattr(
        "app.redis_client.get_sync_redis",
        lambda **kwargs: client,
    )
    rows = event_processor.list_dlq_entries(limit=10)
    assert len(rows) == 1
    assert rows[0]["id"] == "1-0"
    assert rows[0]["event_id"] == "e1"
    assert rows[0]["error"] == "boom"
    client.close.assert_called()


def test_replay_dlq_entries_mocked(monkeypatch):
    from app import event_processor

    monkeypatch.setattr(event_processor, "_redis_configured", lambda: True)
    monkeypatch.setattr(event_processor, "_dlq_key", lambda: "securaiq:events:dlq")
    monkeypatch.setattr(event_processor, "_stream_key", lambda: "securaiq:events")

    client = MagicMock()
    client.xrange.return_value = [
        ("9-0", {"payload": json.dumps({"event_id": "r1", "type": "agent"}), "error": "x"}),
    ]
    client.xadd.return_value = "10-0"
    client.xdel.return_value = 1
    monkeypatch.setattr("app.redis_client.get_sync_redis", lambda **kwargs: client)

    out = event_processor.replay_dlq_entries(["9-0"], limit=5)
    assert out["ok"] is True
    assert out["replayed"] == 1
    assert out["deleted"] == 1
    client.xadd.assert_called_once()
    client.xdel.assert_called_once()


def test_purge_dlq_entries_by_id(monkeypatch):
    from app import event_processor

    monkeypatch.setattr(event_processor, "_redis_configured", lambda: True)
    monkeypatch.setattr(event_processor, "_dlq_key", lambda: "securaiq:events:dlq")
    client = MagicMock()
    client.xdel.return_value = 1
    monkeypatch.setattr("app.redis_client.get_sync_redis", lambda **kwargs: client)
    out = event_processor.purge_dlq_entries(["1-0", "2-0"])
    assert out["ok"] is True
    assert out["deleted"] == 2
