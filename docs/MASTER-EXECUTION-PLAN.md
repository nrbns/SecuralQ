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
| 2 | Measure Redis Sentinel failover | **Harness ready** — Docker not on this Windows lab; run `--inject-stop --record` where compose HA is up |
| 3 | Remove unnecessary polling → RealtimeManager only when SSE live | **In progress** — soft-poll is SSE-offline fallback only |
| 4 | Telemetry → controls → evidence → compliance (beyond firewall) | **Improved** — configurable registry fields + `host_risky_listeners` + disk encryption / risky-listener acceptance loops |
| 5 | Remediation → agent → independent verification (never “fixed” from execute alone) | Done for host remediations in acceptance |
| 6 | Requirements first-class | Partial / Sprint C+ |
| 7 | DPDP Privacy Center | Foundations shipped (catalogs + data-governance UI); deepen inventory/rights/processors |
| 8 | Command Center UX (WHAT→WHY→EVIDENCE→IMPACT→ACTION→VERIFY) | Partial |
| 9 | Measure scale ladder 100→100K | In-proc ladder measured to 10K; HTTP/Redis path TBD — see [ops/CAPACITY-LAB.md](./ops/CAPACITY-LAB.md) |
| 10 | Then Cloud / Identity / AppSec / SBOM / K8s | **Frozen** until 1–5 stay green |

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
