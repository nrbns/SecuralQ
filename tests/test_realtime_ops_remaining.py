"""CI-safe remaining ops proofs (Sentinel pipeline, multiworker soak, signing scaffolds)."""

from __future__ import annotations

import json
from pathlib import Path


def test_inprocess_multiworker_soak(tmp_path):
    from app.realtime.ops_proofs import run_inprocess_soak

    out = run_inprocess_soak(subscribers=3, events=12, data_dir=tmp_path / "soak")
    assert out["ok"] is True
    assert out["all_subscribers_complete"] is True
    assert out["duplicates_dropped"] >= 5
    assert out["per_subscriber_unique"] == [12, 12, 12]


def test_signing_scaffolds_present():
    from app.realtime.ops_proofs import verify_signing_scaffolds

    out = verify_signing_scaffolds()
    assert out["ok"] is True
    assert not out["missing"]


def test_sentinel_pipeline_self_test_cli(tmp_path, monkeypatch):
    import scripts.sentinel_failover_measure as m

    log = tmp_path / "meas.jsonl"
    note = tmp_path / "NOTE.md"
    note.write_text("# lab\n", encoding="utf-8")
    monkeypatch.setattr(m, "LOG", log)
    monkeypatch.setattr(m, "NOTE", note)
    assert m.simulate_pipeline_self_test() == 0
    assert log.is_file()
    row = json.loads(log.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert row["simulated"] is True
    assert row["mode"] == "pipeline_self_test"
    assert row["ok"] is True
    assert row["xautoclaim_reclaim_ok"] is True
    assert row["sse_resume_ok"] is True
    assert "inprocess_failover_chain" in row


def test_redis_ping_helper_without_redis(monkeypatch):
    from app import redis_client

    monkeypatch.setattr(redis_client, "redis_enabled", lambda: False)
    assert redis_client.redis_ping() is False
    monkeypatch.setattr(redis_client, "redis_enabled", lambda: True)
    monkeypatch.setattr(redis_client, "get_sync_redis", lambda **kw: None)
    assert redis_client.redis_ping() is False
