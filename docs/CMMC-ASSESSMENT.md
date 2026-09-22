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
| Cloud WORM / Object Lock | **Local hash markers** until object store configured |
| Readiness confidence | Heuristic bands — not assessor findings |

## Model

```text
CMMC Framework (versioned catalog)
  ↓
CUI Program (boundary → assets → systems → users → ESPs → flows)
  ↓
Control (AC.L2-3.1.1 …)
  ↓
SSP implementation statement (authored or derived)
  ↓
Assessment Objectives (examine | interview | test)
  ↓
Method Evidence → Evidence Spine (+ CUI classification ACL)
  ↓
Interview workflow → Attestation
  ↓
Readiness Confidence (multi-signal)
  ↓
Evidence Gap Autopilot → tasks
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
| `GET /controls/{id}/readiness` | Readiness Confidence signals |
| `GET /controls/{id}/ssp` | SSP pack: implementation + Examine/Interview/Test matrix |
| `GET /ssp` | Full SSP engine snapshot |
| `POST /ssp/implementation` | Author implementation statement |
| `POST /evidence-gap-plan` | Evidence Gap Autopilot |
| `POST /method-evidence` | Examine / Interview / Test → spine |
| `POST /interviews` | Assign interview |
| `POST /interviews/{id}/submit` | Record response |
| `POST /interviews/{id}/review` | Approve → method evidence + attestation |
| `GET /poam/policy` | Framework/control POA&M rules |
| `POST /poam` | Open POA&M (blocked if not eligible) |
| `POST /poam/{id}/close` | Close only with `verified=true` |
| `POST /cui-programs` | CUI program + assets/systems/users/repos |
| `GET /cui-programs/{id}/scope` | CUI → boundary → assets chain |
| `POST /evidence/classify` | Stamp CUI classification on evidence |
| `GET /evidence/{id}/access` | Enforce CUI ACL (403 if denied) |
| `GET /management-view` | Executive readiness (scope/POA&M/evidence/risk) |
| `GET /audit-pack` | Assessor prep ZIP (SSP/readiness/POA&M/interviews/SPRS) |
| `GET /sprs-preparation` | Score/scope/POA&M/affirmation prep pack |
| `GET /readiness` | Framework readiness rollup |

Related spine:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/evidence-spine/worm/status` | Object-lock backend status (honest) |
| `POST /api/evidence-spine/worm/locks` | Record WORM intent / local marker |
| `GET /api/realtime/reconstruct` | Reconnect events + sequence gap detection |

## POA&M policy

- Level 1 style: POA&Ms not permitted
- Level 2: permitted only when catalog `poam_eligible=true`; due within **180 days**
- Close requires independent `verified=true`

## Already elsewhere (reuse)

- Asset CMMC scope categories: `app/cmmc_scoping.py`
- Live SSP: `/api/compliance/ssp/{framework}/live`
- Affirmations: `/api/cmmc/affirmations`
- Evidence vault / freshness / reconciliation: Evidence Spine
- Org-wide risk on evidence write: `record_evidence` → `_maybe_publish_org_risk`
