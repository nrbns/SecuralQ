"""P0 realtime failure-scenario matrix (lab)."""

from __future__ import annotations

from scripts.realtime_failure_acceptance import run_failure_matrix


def test_realtime_failure_acceptance_matrix(tmp_path, monkeypatch):
    """All recovery/security edges must pass in-process (not Sentinel HA)."""
    # run_failure_matrix configures its own isolated settings via MiniPatch;
    # pass tmp_path so DB lands under pytest's temp dir.
    report = run_failure_matrix(tmp_path=tmp_path)
    failed = [s.name for s in report.steps if not s.ok]
    assert report.ok, f"failed steps: {failed} details={[s.detail for s in report.steps if not s.ok]}"
    assert len(report.steps) >= 15


def test_realtime_ops_metrics_shape():
    from app.realtime_ops import pipeline_metrics

    m = pipeline_metrics()
    assert m["ok"] is True
    assert "ingress" in m
    assert "stream" in m
    assert "sse" in m
    assert "disclaimer" in m
