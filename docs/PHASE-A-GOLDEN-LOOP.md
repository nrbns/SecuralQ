# Phase A — Golden loop freeze

**Product definition:** Continuous Security Control & Verified Risk Reduction.

```text
SEE → UNDERSTAND → PRIORITIZE → ACT → VERIFY → PROVE
```

## Freeze rule

Do **not** expand Phase C/D (attack graph depth, cloud/identity/SBOM/AppSec
integrations, AI SecOps missions) until Phase A acceptance is green on owned
lab hosts and Phase B commercial packaging gates exist.

## Phase A checklist (harden, don’t replace)

| # | Capability | Status |
|---|------------|--------|
| 1 | Realtime Streams / DLQ / XAUTOCLAIM / SSE / RealtimeManager | Near-done (CI `phase1-realtime-gate`) |
| 2 | Agent mTLS + cert lifecycle + signed commands + replay flags | Foundations + production profile (Sprint 2) |
| 3 | Control engine (last-result + history + affected recompute) | Done (P1) |
| 4 | Automatic evidence on control/remediation transitions | Done for host FAIL/PASS (+ UNKNOWN emit) |
| 5 | **Live compliance recalculation** (`live_percent` from last-results) | **Done** — `publish_live_compliance_update` |
| 6 | Remediation → approve → execute → verify | Closed loop for host remediations |
| 7 | **Risk reduction on verified PASS** (`risk.changed` + score_delta) | **Done** — org risk on host PASS/FAIL |
| 8 | Dashboard / Compliance Center SSE invalidation | **Done** — Live activity + KPI patch + soft-poll fallback |
| 9 | Tenant isolation automated tests | Expanded (agents, control_results, SecOps, RBAC) |
| 10 | MFA + licensing commercial layer | Phase B foundations (`docs/PHASE-B-COMMERCIAL.md`) |

## Sprint 1 finish (this slice)

- Host UNKNOWN persisted + `control.unknown` (never invent PASS)
- Host FAIL/PASS use `publish_aliased`; processor skips when `host_side_effects_done`
- POA&M close → `remediation.completed` / `remediation.verified`
- UI: truth states PASS/FAIL/UNKNOWN/STALE, Live activity labels, remediations dotted SSE, CC KPI patch

## Honesty

- Gap `compliance_percent` = pasted-evidence heuristic (not certification).
- `continuous.live_percent` = operating-effectiveness from agent control results.
- Lab defaults keep production security flags **off**; enable via production profile.

## APIs

- `GET /api/compliance/live-score`
- `GET /api/compliance/overview` → `continuous.live_percent`
- Bus: `compliance.updated` (`live_percent`, `percent_delta`), `risk.changed` (`score_delta`)
- `control.passed` / `control.failed` processors → evidence + risk + live compliance

## Ops

- Sentinel lab measure: `docs/ops/SENTINEL-FAILOVER-LAB.md`, `scripts/sentinel_failover_measure.py`
- HA/DR draft: `docs/ops/HA-DR.md`

## Tests

```bash
pytest -v \
  tests/test_phase_a_live_compliance_risk.py \
  tests/test_p1_control_history_timeline.py \
  tests/test_cross_tenant_isolation.py \
  tests/test_phase_ab_commercial_foundations.py
```
