# Evidence Spine

**Evidence is the common language** between agents, documents, controls, compliance, risk, remediation, and Compliance Operations.

Do **not** rebuild SecuraIQ. This module unifies paths that already existed (`securaiq_evidence`, `evidence_links`, host control tests, doc library).

## Model

```text
SERVER / AGENT / DOCUMENT
         ↓
   OBSERVATION | UPLOAD
         ↓
      EVIDENCE          (securaiq_evidence)
         ↓
 evidence_control_map   (many-to-many)
         ↓
   CONTROL RESULT       (evaluate_control_from_evidence)
         ↓
 RISK / COMPLIANCE / TASK / SSE
```

### Important honesty rules

| Source | Meaning |
|--------|---------|
| **Observed** (agent) | Runtime signal — can drive PASS / FAIL |
| **Declared** (document) | Policy/governance support — alone → **partial**, not host PASS |

Example: firewall control can be supported by Policy.pdf **and** satisfied by Windows/Linux agent observations. Evaluation prefers fresh observed FAIL over PASS; documents never alone certify operating effectiveness.

## API

Prefix: `/api/evidence-spine`

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/observations` | Agent/server → Observation → Evidence → control links |
| POST | `/documents` | Document → Evidence → control links |
| POST | `/link` | Map existing evidence to a control |
| DELETE | `/link` | Unmap |
| GET | `/controls/{id}/evidence` | All evidence for a control |
| GET | `/controls/{id}/evaluate` | Rollup result + WHY note |
| GET | `/evidence/{id}/controls` | Controls linked to one evidence row |

Existing Evidence Store remains at `/api/evidence`.

## Wired into product

- **Host control checks** — FAIL/PASS evidence is mapped to framework controls + observation ledger
- **Compliance Doc Library approve** — Document → Evidence (declared) + control map (in addition to `evidence_links`)
- **Compliance Operations** — task evidence notes become Evidence rows linked to the task's control

## SSE events

`evidence.created` · `evidence.updated` · `evidence.linked`

## Out of scope (next)

- Full event-driven email worker for every transition
- Automatic org-wide risk recalculation from every evidence write (hooks exist; broaden)
- Generic multi-cloud data-source check engine
- Drag-and-drop Evidence Vault UI polish

## Tests

```bash
pytest -v tests/test_evidence_spine.py
```
