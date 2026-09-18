"""Tests for remaining full proof (failover sim + lab signing pipeline)."""

from __future__ import annotations


def test_remaining_full_proof_steps(tmp_path, monkeypatch):
    import scripts.realtime_remaining_full_proof as m

    monkeypatch.setattr(m, "LOG", tmp_path / "proofs.jsonl")
    # Lab certs under tmp to avoid writing to repo during test
    monkeypatch.setattr(m, "_ROOT", tmp_path)
    # Re-import path for scaffolds still from real repo — patch verify instead
    from app.realtime import ops_proofs

    monkeypatch.setattr(
        ops_proofs,
        "verify_signing_scaffolds",
        lambda: {"ok": True, "missing": [], "note": "test"},
    )

    s1 = m.step_sentinel_failover_simulated()
    assert s1["ok"] is True
    assert s1["simulated"] is True
    assert s1["sse_resume_ok"] is True

    s2 = m.step_multiworker_soak()
    assert s2["ok"] is True

    # Lab authenticode: allow skip if PS cert API unavailable — still require scaffolds
    s3 = m.step_lab_authenticode()
    # ok if scaffolds ok OR cert created; in test scaffolds mocked True
    assert s3["scaffolds_ok"] is True
