# India DPDP in SecuraIQ

SecuraIQ treats **Digital Personal Data Protection Act, 2023** and **Digital Personal Data Protection Rules, 2025** as first-class frameworks in the existing catalog engine (`data/frameworks/*.json`) — not a hard-coded DPDP-only UI.

## Official source & phased commencement

MeitY notified the **Digital Personal Data Protection Rules, 2025** on **13 November 2025** (G.S.R. 846(E)). Rule 1 sets phased commencement:

| Phase | Effective (from Gazette 13 Nov 2025) | Rules |
|-------|--------------------------------------|-------|
| A | 2025-11-13 (publication) | 1, 2, 17–21 |
| B | 2026-11-13 (one year) | 4 |
| C | 2027-05-13 (eighteen months) | 3, 5–16, 22, 23 |

Each Rules control in `dpdp_rules_2025.json` carries `effective_from`. Use:

```http
GET /api/frameworks/dpdp_rules_2025/commencement?as_of=2026-11-13
```

## Catalogs

| Id | Name |
|----|------|
| `dpdp_act_2023` | India DPDP Act 2023 (operational control pack) |
| `dpdp_rules_2025` | India DPDP Rules 2025 (phased) |

Aliases: `dpdp` / `india_dpdp` → Rules; `dpdp_act` → Act.

Regenerate from `scripts/refresh_frameworks.py` (`dpdp_act_2023()`, `dpdp_rules_2025()`).

## Evidence loop (unchanged architecture)

```text
Framework → Requirement/Control → Test → Data source → Observation → Evidence → Result → Risk → Remediation → Verification
```

Live security tests (firewall, encryption, Defender, vuln/patch/inventory) bind into DPDP Rule-6 / Act-8 where machine evidence exists. Notice, consent, rights, processors, SDF, and children's data remain **declaration + evidence** via data governance — agents cannot invent legal purpose.

## Data governance API

```text
/api/data-governance/profile
/api/data-governance/posture
/api/data-governance/dpdp-overview
/api/data-governance/data-map
/api/data-governance/elements|activities|flows|processors|retention|requests
```

UI: **Compliance → India DPDP** workspace (`data-workspace="privacy"`) shows inventory posture, phased Rules commencement, critical gaps, and the data map.

SDF status defaults to `unknown` and is never auto-declared `applicable`.

## Honest product boundary

SecuraIQ produces an **evidence-backed readiness assessment**. It does **not** declare that a customer is legally “DPDP compliant.” Applicability (including Significant Data Fiduciary) requires human/legal review.

## Fleet scale direction

- Check-ins update `app/realtime/fleet_aggregator.py` and publish `fleet.health.changed` aggregates (not 100k heartbeats to the browser).
- Partition helpers: `app/realtime/partitioner.py`; optional workload streams: `app/realtime/workload_streams.py`.
- Event vocabulary: `app/realtime/event_registry.py` (fleet aggregates vs high-volume).
- Incremental recompute: `app/controls/recompute.py` (`privacy.*` → inventory tests only — never invents notice/consent PASS).
- Measure with `scripts/fleet_simulator.py --ladder` / `--extended-ladder` + `scripts/realtime_load_test.py`. **No 5K+ / 100K claim until `docs/ops/CAPACITY-LAB.md` is filled.**
