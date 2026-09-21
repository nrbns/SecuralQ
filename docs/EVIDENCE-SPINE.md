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
 control_runtime_state  (CURRENT / PREVIOUS / VERSION)
         ↓
 RISK / COMPLIANCE / TASK / SSE
```

### Evidence dependency packs

A control may require **multiple evidence slots** before it can be PASS:

```text
AC-1 Access control
  ├── policy     (documents)  — Access control policy
  └── runtime    (satisfies)  — Live MFA / access observation
```

If any required slot is missing or expired → reconcile returns **partial** (not PASS).
Default packs: `AT-2`, `AC-1`, `host_firewall`. Seed via `POST /dependencies/seed`.

### Control runtime state machine

States: `unknown` → `evaluating` → `pass` | `fail` | `partial` → `stale` → (recollect) …

Each row tracks `state`, `previous_state`, `changed_at`, `last_observed_at`, `version`, `source`.
Job `control_stale_tick` (every 5 min) ages PASS/FAIL past freshness into STALE and opens host recollection tasks.

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
- owner, collector, review status  
  (`draft`/`uploaded` → `pending_review` → `accepted` / `rejected` / `invalid` / `expired`)
- `content_sha256`, file_id, version chain, `expires_at` (retention/TTL)
- access log (upload / supersede / review / accept / reject / expired)
- Job `vault_expiry_tick` (hourly) marks past-`expires_at` docs **expired** — never keep ACCEPTED forever

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

## Multi-source reconciliation

When Agent / Cloud / Scanner disagree on the same check for the same subject:

```text
Source → Observation → Freshness → Conflict detection → Canonical state
```

| Status | Meaning |
|--------|---------|
| `agreed` | All fresh sources report the same result |
| `conflict` | Fresh sources disagree — **human resolve required** (advisory severity only) |
| `insufficient` | No fresh observations |

Canonical rows live in `observation_canonical_state` (CURRENT + VERSION + sources).  
Ingest of observations triggers a best-effort reconcile hook. SSE: `observation.conflict` · `observation.reconciled`.

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
| GET | `/controls/{id}/dependencies` | Dependency pack completeness |
| POST | `/controls/{id}/reconcile` | Evaluate + deps + state transition |
| GET | `/controls/{id}/state` | Runtime state row |
| GET | `/control-state` | List runtime states |
| POST | `/control-state/transition` | Manual/agent state transition |
| POST | `/control-state/stale-tick` | Run stale tick for current user |
| GET | `/dependencies` | List requirement slots |
| POST | `/dependencies` | Upsert a requirement slot |
| POST | `/dependencies/seed` | Seed default packs (AT-2, AC-1, host_firewall) |
| POST | `/observations/reconcile` | Multi-source conflict → canonical state |
| GET | `/observations/canonical` | List canonical / conflict rows |
| GET | `/observations/canonical/{check_id}` | One subject+check canonical row |
| POST | `/observations/resolve` | Human resolve a conflict |
| GET | `/evidence/{id}/controls` | Controls linked to one evidence row |

Existing Evidence Store remains at `/api/evidence`.

## Wired into product

- **Host control checks** — FAIL/PASS evidence mapped to framework controls + observation ledger
- **Compliance Doc Library approve** — Document → Evidence (declared) + control map
- **Compliance Operations** — task evidence notes become Evidence rows
- **Evidence Vault** — upload / version / review with integrity hash
- **Dependency packs** — control requires N evidence slots before PASS
- **Control state machine** — CURRENT/PREVIOUS/VERSION + stale tick job + SSE
- **Observation reconciliation** — multi-source conflict detection + human resolve

## SSE events

`evidence.created` · `evidence.updated` · `evidence.linked` · `evidence.verified` · `evidence.rejected` · `evidence.superseded` · `control.stale` · `control.passed` · `control.failed` · `control.evaluating` · `control.updated` · `observation.conflict` · `observation.reconciled`

## Out of scope (next)

- Full malware sandbox scanning
- WORM / object-lock storage
- Org-wide auto risk recalc on every write
- Email notification worker → **shipped** (`notification_outbox` + `notification_delivery_tick`)
- Drag-and-drop vault UI polish
- Full asset identity / entity-resolution graph → **shipped** (`asset_aliases` — see [ASSET-IDENTITY.md](./ASSET-IDENTITY.md))

## Tests

```bash
pytest -v tests/test_evidence_spine.py tests/test_evidence_vault.py tests/test_control_state.py tests/test_observation_reconciliation.py
```
