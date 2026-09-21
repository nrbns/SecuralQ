# Evidence Spine

**Evidence is the common language** between agents, documents, controls, compliance, risk, remediation, and Compliance Operations.

Do **not** rebuild SecuraIQ. This module unifies paths that already existed (`securaiq_evidence`, `evidence_links`, host control tests, doc library).

## Model

```text
SERVER / AGENT / DOCUMENT
         ↓
   OBSERVATION | VAULT UPLOAD
         ↓
      EVIDENCE          (securaiq_evidence)
         ↓
 evidence_control_map   (many-to-many)
         ↓
   CONTROL RESULT       (+ freshness → STALE)
         ↓
 RISK / COMPLIANCE / TASK / SSE
```

### Important honesty rules

| Source | Meaning |
|--------|---------|
| **Observed** (agent) | Runtime signal — can drive PASS / FAIL |
| **Declared** (document) | Policy/governance support — alone → **partial**, not host PASS |

Example: firewall control can be supported by Policy.pdf **and** satisfied by Windows/Linux agent observations. Evaluation prefers fresh observed FAIL over PASS; documents never alone certify operating effectiveness.

## Evidence Vault (first-class documents)

Critical rule: **supersede creates a new version** — historical evidence is never overwritten.

```text
policy-v1.pdf → Evidence EV-1 (v1, sha256=…)
policy-v2.pdf → Evidence EV-2 (v2, previous=EV-1)  ← EV-1 retained + superseded
```

Each vault item tracks:

- kind (document / screenshot / certificate / …)
- owner, collector, review status (`draft` → `pending_review` → `accepted` / `rejected`)
- `content_sha256`, file_id, version chain
- access log (upload / supersede / review / accept / reject)

## Freshness

PASS cannot last forever. Policies (examples):

| Control | Stale after |
|---------|------------:|
| Firewall / Defender | 15 min |
| Patch state | 6 hr |
| MFA | 24 hr |
| Access review | 30 days |
| Security policy | 365 days |

`evaluate_control_from_evidence` can return `stale` when observed evidence ages past policy.

## API

Prefix: `/api/evidence-spine`

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/observations` | Agent/server → Observation → Evidence → control links |
| POST | `/documents` | Document metadata → Evidence → control links |
| POST | `/vault/upload` | Multipart file → vault v1 + SHA-256 |
| POST | `/vault/{id}/supersede` | New version (history preserved) |
| POST | `/vault/{id}/review` | draft / pending_review / accepted / rejected |
| GET | `/vault` · `/vault/{id}` | List / detail + versions |
| GET | `/freshness-policies` | Control freshness table |
| POST | `/freshness/apply` | Apply policy to a result + last_observed |
| POST | `/link` | Map existing evidence to a control |
| DELETE | `/link` | Unmap |
| GET | `/controls/{id}/evidence` | All evidence for a control |
| GET | `/controls/{id}/evaluate` | Rollup result + WHY note |
| GET | `/evidence/{id}/controls` | Controls linked to one evidence row |

Existing Evidence Store remains at `/api/evidence`.

## Wired into product

- **Host control checks** — FAIL/PASS evidence mapped to framework controls + observation ledger
- **Compliance Doc Library approve** — Document → Evidence (declared) + control map
- **Compliance Operations** — task evidence notes become Evidence rows
- **Evidence Vault** — upload / version / review with integrity hash

## SSE events

`evidence.created` · `evidence.updated` · `evidence.linked` · `evidence.verified` · `evidence.rejected` · `evidence.superseded` · `control.stale`

## Out of scope (next)

- Full malware sandbox scanning
- WORM / object-lock storage
- Org-wide auto risk recalc on every write
- Email notification worker
- Drag-and-drop vault UI polish

## Tests

```bash
pytest -v tests/test_evidence_spine.py tests/test_evidence_vault.py
```
