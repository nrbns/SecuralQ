# SecuraIQ — Release gates (prove closes, do not add breadth)

**Rule:** every change must close a partial on the golden path, or prove failure/recovery/capacity.  
Do **not** add domain screens (Cloud / K8s / AppSec / Identity depth) until Release 1 stays green.

Cross-links: [GOLDEN-PATH.md](./GOLDEN-PATH.md) · [MASTER-EXECUTION-PLAN.md](./MASTER-EXECUTION-PLAN.md) · [production-readiness.md](./production-readiness.md) · [ops/CAPACITY-LAB.md](./ops/CAPACITY-LAB.md) · [WORLD-CLASS-CHECKLIST.md](./WORLD-CLASS-CHECKLIST.md)

## Governing question (six)

> **WHAT** happened → **WHY** it matters → **EVIDENCE** → **IMPACT** → **ACTION** → **VERIFIED**

If a feature cannot answer all six, do not ship it yet.

---

## RELEASE 0 — Foundation

| Piece | Status on main | Honesty |
|-------|----------------|---------|
| Event contract (`event_id` / type / sequence) | **Partial→improved** | Normalized on publish; not HA exactly-once |
| Observation → Evidence | **Shipped** | Spine ingest + vault |
| Evidence → Control map | **Shipped** | `evidence_control_map` + evaluate |
| Universal evidence envelope | **Shipped** | `evidence_envelope()` on every evidence row (org/source/asset/sha256/status/freshness) |
| Requirement first-class | **Shipped** | Domain model + API (not legal text) |
| Realtime state (Streams + SSE) | **Improved→lab-production** | Soft BP shed, recovery/gap frames, correlation_id, MC worker degrade, stage meters; Sentinel live Docker still ops |
| Document vault + versioning | **Shipped** | SHA-256, supersede, review; lifecycle expired/invalid + tick |
| Freshness (never show old PASS as current) | **Shipped** | Policies + `control_stale_tick` |
| Source reconciliation / CONFLICT | **Shipped** | Canonical + human resolve |
| Platform Mission Control | **Shipped (lab)** | `GET /api/ops/mission-control` — component health; not multi-node HA |
| CMMC assessment layer | **Shipped (Tier-1 deepen)** | Objectives · Examine/Interview/Test · SSP engine · readiness confidence · evidence gap plan · interview workflow · CUI scope/ACL · policy-gated POA&M · SPRS prep · versioned catalog — [CMMC-ASSESSMENT.md](./CMMC-ASSESSMENT.md). Not C3PAO/SPRS submit |

## RELEASE 1 — Closed loop

| Piece | Status | Honesty |
|-------|--------|---------|
| Detect → risk → finding | **Partial→improved** | Host loops in acceptance; richer risk still thin |
| Remediation → approval → signed command | **Improved** | Allowlist + seals; production flags optional in lab |
| Independent verification | **Enforced** | Execute ≠ verified (host + campaign) |
| New evidence → control PASS → risk recalc | **Improved→shipped** | `record_evidence` triggers `_maybe_publish_org_risk` on every write/touch |

**Prove:** `pytest tests/test_realtime_acceptance_local.py` · `scripts/realtime_acceptance_demo.py --local`

## RELEASE 2 — Compliance operations

| Piece | Status | Honesty |
|-------|--------|---------|
| Calendar / tasks / my-work | **MVP shipped** | |
| Document review + attestation | **Shipped** | Who/What/When/Decision |
| Exceptions with expiry + renew | **Shipped→hardened** | Compensating evidence/text required on approve; tick flips lapsed → `expired` |
| Reminders / escalation | **Lab-production** | L1–L3 escalation fan-out, priority bump, SLA breach events; not legal determination |
| CMMC audit pack / management view | **Lab-production** | `/api/cmmc/audit-pack` · `/management-view` · `/tier1-readiness`; not C3PAO/SPRS submit |
| SCIM Groups | **Shipped (minimal)** | `/scim/v2/Groups` CRUD; Users already present; not full RFC |
| Cross-framework evidence write-through | **Shipped (opt-in)** | `propagate_canonical` on evidence link → sibling `supports` maps |
| Continuous Posture Engine | **Shipped (Layer B)** | 30m ± jitter reconciliation — **not** Nmap/Nuclei/ZAP; see [POSTURE-ENGINE.md](./POSTURE-ENGINE.md) |
| Notification worker (queue, not inline SMTP) | **Shipped** | `notification_delivery_tick` |

## RELEASE 3 — Enterprise

| Piece | Status | Honesty |
|-------|--------|---------|
| Tenant isolation (REST/SSE/spine/exports) | **Lab-production** | Cross-tenant tests + object-store org key fail-closed. Remaining: cloud WORM object-lock |
| Platform Mission Control | **Shipped (lab)** | `GET /api/ops/mission-control` |
| SSO / SCIM | **Lab-production (facades)** | OIDC/SAML readiness + SCIM Groups; full IdP depth still open |
| HA / Redis Sentinel live failover | **CI self-test** | Docker `--inject-stop` still ops |
| DR / backup restore | **Partial** | Docs + scripts; automate more |
| Signed installers / update-rollback | **Partial** | Packages exist; Authenticode/notarize missing |

## RELEASE 4 — Scale (measure only)

| Rung | In-proc fleet sim | HTTP check-in wave |
|------|-------------------|--------------------|
| 100 | Measured | **Measured 2026-09-21** (100% ok) |
| 1K–100K | Measured (aggregator only) | 500+ **unmeasured** |

Advertise **largest measured** number only. See [ops/CAPACITY-LAB.md](./ops/CAPACITY-LAB.md).

## RELEASE 5 — Differentiation (frozen)

Attack paths / business graph / advanced risk / digital twin / AI SecOps autonomy — **frozen** until Releases 0–1 stay green on owned-host + measured HA/load.

---

## Immediate next closes (ordered)

1. ~~Document vault lifecycle honesty~~ — done  
2. ~~Tenant SSE / agent gateway / notification path proofs~~ — done  
3. ~~Remaining tenant paths (jobs/files/RAG) + evidence envelope + Mission Control~~ — done this pass  
4. ~~Continuous Posture Engine (Layer B)~~ — done (`64d7463`)  
5. ~~Acceptance path uses sealed dispatch (not raw SQL → sent)~~ — done  
6. ~~DLQ soft-recover + named failure-matrix contract~~ — done this pass  
7. ~~Approve/execute auto-evidence + stage latency meters~~ — done this pass  
8. HTTP ladder 500+ when lab can sustain it — Release 4 (**ops measure**; harness + truncated check-in + soft 1000 **code-done**)  
9. Live Docker Sentinel failover when Docker available — Release 3 (**ops**; pipeline self-test **code-done**)  
10. Owned-host live acceptance — Release 1 prove (**ops**; gate `SECURAIQ_OWNED_HOST` / `--i-own-this-host` **code-done**)  
11. WORM/object-lock · full SSO/SCIM · signed installers — Release 3 leftovers (scaffolds + lab PFX **code-done**; EV/cloud **ops**)

One-shot lab close (no Docker faking):

```bash
python scripts/phase1_ops_complete_lab.py
python scripts/phase1_ops_complete_lab.py --http-ladder --max-agents 500 --workers 8
```

Board: `GET /api/admin/ops/phase1-remaining` · LB probe: `GET /ready`

### Production control-plane freeze (customer roadmap)

Do **not** start Release 5 / cloud-depth / twin / AI autonomy. Finish the closed loop:

| Freeze item | Gate status |
|-------------|-------------|
| Realtime fabric | Lab-production — soft DLQ recover, BP shed, correlation/causation, SSE recovery honesty; not HA exactly-once |
| 30-min Posture Engine | **Shipped** (Layer B) |
| Agent security | Lab-production — allowlist/seals/mTLS APIs; flags off by default; commercial five-flag + proxy still opt-in |
| Evidence Spine | Shipped (local); cloud WORM ops |
| Risk recalc | Shipped |
| Remediation → Verify | Shipped |
| Compliance Ops | Lab-production — L1–L3 escalation + SLA breach |
| CMMC | Lab-production Tier-1 (`/tier1-readiness`); not C3PAO/SPRS submit |
| Tenant / RBAC / MFA / SSO | Lab-production — object-store org guard + IdP readiness facades |
| Audit trail | Lab-production — hash chain + sealed export; SQLite ≠ cloud WORM |
| HA / DR | Ops-blocked (live) / **code-unblocked** | CI `--pipeline-self-test` + `GET /ready`; live Sentinel inject needs Docker |
| Load · Self-sec | Lab-production | HTTP 100 + soft→1000; HTTP 500+ via load_test `--persist`; board `/api/admin/ops/phase1-remaining` |

See [PRODUCTION-CONTROL-PLANE.md](./PRODUCTION-CONTROL-PLANE.md).

### Still blocked on this Windows lab (do not fake)

| Item | Why | Code-unblocked |
|------|-----|----------------|
| Docker Redis Sentinel `--inject-stop` | Docker absent | pipeline self-test + compose profile |
| Owned-host OS mutation acceptance | Needs authorized host | `SECURAIQ_OWNED_HOST` / `--i-own-this-host` gate |
| HTTP 500/1k wave | 500 measured 2026-09-22; 1000 unmeasured | harness + soft 1000 + truncated check-in fix |
| Authenticode / notarization | Signing certs (EV) | scaffolds + lab self-signed PFX |
| WORM object-lock | Cloud backend needs object store; **local markers + API shipped** | yes |
| Release 5 differentiation | Frozen until 0–1 green on owned-host + HA | — |
