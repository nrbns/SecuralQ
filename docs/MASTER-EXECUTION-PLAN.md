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
| 9 | Measure scale ladder 100→100K | **In-proc to 100K + HTTP wave to 50** — see [ops/CAPACITY-LAB.md](./ops/CAPACITY-LAB.md); HTTP 100/500/1k and Redis path still TBD |
| 10 | Then Cloud / Identity / AppSec / SBOM / K8s | **Frozen** until 1–5 stay green |

### Compliance Operations (new module — after Immediate loop)

Calendar-driven workflow engine (not domain expansion): see [COMPLIANCE-OPERATIONS.md](./COMPLIANCE-OPERATIONS.md).  
MVP shipped: tasks · schedules · evidence gate · my-work · calendar · escalation tick · SSE events.

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
