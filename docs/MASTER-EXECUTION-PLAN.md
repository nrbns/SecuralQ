# SecuraIQ — Master Execution Plan

**Source of truth for build order from current `main`.**  
Phases 1–46 detail: [master-build-plan.md](./master-build-plan.md).  
Honesty: [production-readiness.md](./production-readiness.md).

**Rule:** finish the control-plane loop and production proof **before** expanding into every security domain (Cloud / K8s / AppSec / Identity depth).

---

## Definition of done

> A real security/privacy event on any enrolled endpoint can travel through SecuraIQ in realtime, become an evidence-backed finding/control/risk/compliance state, generate an approved remediation, execute on the authorized agent, be independently verified, update risk and compliance, and show the entire chain in the UI without refresh.

Only after that works reliably: scale 1 → 1K → 10K → 100K (publish **largest measured** number only).

---

## PHASE 0 — Freeze the architecture

**Do not start another backend or another realtime system.**

```text
Rust Agent → Agent Gateway → FastAPI → Redis Streams → Workers
  → Security / Risk / Compliance → Evidence → Remediation → Verification
  → SSE → UI
```

---

## Immediate 10 (execute in this order)

| # | Task | Status on main |
|---|------|----------------|
| 1 | Owned-host / lab acceptance loop (detect→risk→evidence→approve→remediate→verify→SSE timeline) | **CI green** — `realtime_acceptance_demo.py --local` + step 12 timeline; live OS mutation still ops/owned-host |
| 2 | Measure Redis Sentinel failover | **CI in-process green** — reconnect + XAUTOCLAIM + SSE resume via `--pipeline-self-test`; live Docker `--inject-stop --record` still ops (Docker absent on this Windows lab) |
| 3 | Remove unnecessary polling → RealtimeManager only when SSE live | **Done** — soft-poll + notif badge only when SSE offline/stalled; stall force-reconnect |
| 4 | Telemetry → controls → evidence → compliance (beyond firewall) | **Improved** — configurable registry fields + `host_risky_listeners` + disk encryption / risky-listener acceptance loops |
| 5 | Remediation → agent → independent verification (never “fixed” from execute alone) | Done for host remediations in acceptance |
| 6 | Requirements first-class | **Shipped** — domain Requirement model + `/api/controls/requirements*` + Frameworks UI strip (not legal text) |
| 7 | DPDP Privacy Center | **Deepened** — data_map activities/requests/retention + Privacy Center sections (not a DPDP compliance claim) |
| 8 | Command Center UX (WHAT→WHY→EVIDENCE→IMPACT→ACTION→VERIFY) | **Shipped** — ops decision card + `renderNarrativeBlock` on remediations/assets/agents/evidence/findings |
| 9 | Measure scale ladder 100→100K | **In-proc to 100K + HTTP wave to 100** — see [ops/CAPACITY-LAB.md](./ops/CAPACITY-LAB.md); HTTP 500/1k and Redis path still TBD |
| 10 | Then Cloud / Identity / AppSec / SBOM / K8s | **Frozen** until 1–5 stay green |

### Compliance Operations (new module — after Immediate loop)

Calendar-driven workflow engine (not domain expansion): see [COMPLIANCE-OPERATIONS.md](./COMPLIANCE-OPERATIONS.md).  
MVP shipped: tasks · schedules · evidence gate · my-work · calendar · escalation tick · SSE events.  
Board + approvals + control FAIL/PASS bridge shipped.

### Evidence Spine (common language — after Compliance Ops)

Observation + Document → Evidence → control map → evaluate: see [EVIDENCE-SPINE.md](./EVIDENCE-SPINE.md).  
Does not rebuild the product — unifies `securaiq_evidence`, host controls, doc library, and Compliance Ops tasks.  
**Vault shipped:** SHA-256 integrity, version supersede (no overwrite), review accept/reject, freshness policies.  
**State machine shipped:** evidence dependency packs + `control_runtime_state` + `control_stale_tick` job (PASS→STALE).  
**Reconciliation shipped:** multi-source Observation conflict → `observation_canonical_state` (agreed | conflict | insufficient) + human resolve. Never silently picks a winner.

### Commercial backbone (north star — do not random-feature)

```text
AGENTS / CLOUD / DOCUMENTS → OBSERVATIONS → EVIDENCE
  → CONTROLS + ASSETS → COMPLIANCE + RISK → TASKS + FINDINGS
  → REMEDIATION → VERIFY → NEW EVIDENCE → AUDIT PROOF → REALTIME UI
```

**Frozen architecture (do not rebuild):** finish the existing control-plane so every module participates in the same golden path — do not add competing architectures or Phase 22+ domain expansion.

```text
SERVER CHANGE → AGENT → GATEWAY → REDIS → OBSERVATION → EVIDENCE
  → CONTROL → RISK / COMPLIANCE → FINDING → REMEDIATION → APPROVAL
  → SIGNED COMMAND → AGENT EXECUTION → INDEPENDENT VERIFICATION
  → NEW EVIDENCE → RISK+COMPLIANCE RECALC → SSE → UI
```

| Backbone piece | Status on main |
|----------------|----------------|
| Evidence Spine (obs+docs→controls) | Shipped |
| Evidence Vault (SHA-256, supersede, review) | Shipped |
| Control runtime state + stale tick | Shipped |
| Observation reconciliation / conflict | Shipped |
| Asset identity / aliases | Shipped |
| Compliance Ops (tasks/calendar/approvals) | MVP shipped |
| Notification outbox worker | Shipped |
| Human attestation (Who/What/When/Decision) | Shipped — `/api/attestations` + vault/exception hooks |
| Exception renew (no permanent accept) | Shipped — `POST /api/exceptions/{id}/renew` |
| Audit pack completeness | Improved — attestations + exceptions + vault index in ZIP |
| Command execute ≠ verified | Enforced (host + campaign) |
| Redis Sentinel live Docker failover | Ops / needs Docker |
| HTTP load ladder 100+ | **Measured to 100** — see [ops/CAPACITY-LAB.md](./ops/CAPACITY-LAB.md); 50-agent p95 cliff fixed; 500+ still TBD |
| Tenant fail-closed completeness | Improved — spine lists (control state / vault / requirements / canonical) + exceptions + outbox stats scoped; exception expiry tick notifies renew |
| Document vault lifecycle | Improved — expired/invalid statuses + `vault_expiry_tick`; WORM/object-lock still missing |
| WORM / object-lock | Missing |
| Cloud / K8s / Identity / AppSec depth | **Frozen** |

Next 🔴: tenant path proofs still missing · HTTP 500+ · owned-host live · Docker Sentinel · WORM · SSO/SCIM.  

Organizing principle: [RELEASE-GATES.md](./RELEASE-GATES.md) — close partials on the golden path; do not add Release 5 breadth yet.

**Sprint A+B closed this pass:** human attestation (Who/What/When/Evidence/Decision) · vault/exception → attestation + evidence · exception renew (no open-ended accept) · audit pack includes attestations/exceptions/vault · vault/alias list tenant-scoped.  

**Tenant deepen (prior):** `tenant_visibility_sql` on spine list APIs · cross-tenant isolation coverage · `exception_expiry_tick` · outbox stats org-aware.

**This pass:** HTTP ladder re-measure 25/50/100 (100% ok; p95 cliff gone) · `RELEASE-GATES.md` · vault lifecycle `expired`/`invalid` + `vault_expiry_tick`.
Frozen until loop stays green: Cloud/K8s/AppSec/Identity depth · business-service graph expansions · AI SecOps autonomy.

### Prove #1

```bash
pytest -v tests/test_realtime_acceptance_local.py
python scripts/realtime_acceptance_demo.py --local --firewall-only
python scripts/realtime_failure_acceptance.py
# Owned host (optional):
python scripts/realtime_acceptance_demo.py --server http://HOST:8080 --token "$ADMIN_JWT"
```

### Prove #2

```bash
docker compose --profile redis-ha up -d
python scripts/sentinel_failover_measure.py --inject-stop --record
# CI without Docker:
python scripts/sentinel_failover_measure.py --pipeline-self-test
```

---

## Track legend

- 🔴 Foundation / production proof — do first  
- 🔵 UX / moat — after loop is green  
- 🟠 Domain expansion — after freeze lifts  

Full phase list with honest Done/Partial/Missing: [master-build-plan.md](./master-build-plan.md).

---

## Explicitly frozen until acceptance stays green

Cloud CSPM · Kubernetes · deep AppSec platform · full identity graph · digital twin · business-service graph expansions beyond current connectors.
