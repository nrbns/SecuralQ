# CMMC Assessment Layer

**Does not rebuild Evidence Spine.** Extends existing catalogs, live SSP, scoping,
affirmations, and vault/evidence.

Cross-links: [EVIDENCE-SPINE.md](./EVIDENCE-SPINE.md) · [RELEASE-GATES.md](./RELEASE-GATES.md) ·
`data/frameworks/cmmc_l2.json`

## Honesty

| Claim | Reality |
|-------|---------|
| C3PAO / certification | **No** |
| SPRS submission | **No** — preparation snapshot only |
| Assessment Guide verbatim text | **No** — Examine/Interview/Test scaffolds |
| Catalog version / DoD status note | From framework JSON `status_note` |

## Model

```text
CMMC Framework (versioned catalog)
  ↓
Control (AC.L2-3.1.1 …)
  ↓
Assessment Objectives (examine | interview | test scaffolds)
  ↓
Method Evidence → Evidence Spine
  ↓
Finding / POA&M (policy-gated) → Verification
  ↓
SPRS Preparation snapshot
```

## APIs (`/api/cmmc`)

| Endpoint | Purpose |
|----------|---------|
| `GET /version` | Framework version + status_note |
| `POST /objectives/seed` | Seed 3 method objectives × 110 controls |
| `GET /objectives` | List objectives |
| `POST /objectives/{id}/status` | Set met/not_met/partial + evidence |
| `GET /controls/{id}/assessment` | Objectives + rollup + live SSP + POA&M policy |
| `POST /method-evidence` | Examine / Interview / Test → spine |
| `GET /poam/policy` | Framework/control POA&M rules |
| `POST /poam` | Open POA&M (blocked if not eligible) |
| `POST /poam/{id}/close` | Close only with `verified=true` |
| `POST /cui-programs` | CUI program / boundary container |
| `GET /sprs-preparation` | Score/scope/POA&M/affirmation prep pack |

## POA&M policy

- Level 1 style: POA&Ms not permitted
- Level 2: permitted only when catalog `poam_eligible=true`; due within **180 days**
- Close requires independent `verified=true`

## Already elsewhere (reuse)

- Asset CMMC scope categories: `app/cmmc_scoping.py`
- Live SSP: `/api/compliance/ssp/{framework}/live`
- Affirmations: `/api/cmmc/affirmations`
- Evidence vault / freshness / reconciliation: Evidence Spine
