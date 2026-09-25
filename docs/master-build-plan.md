# SecuraIQ — Master Build Plan

**Canonical product strategy:** Continuous Security, Risk & Compliance Control Plane  
**Status key:** **Done** · **Partial** · **Missing** — vs current `main` (honest; do not invent Done)

**Lab board:** `GET /api/phases/total` and `python scripts/complete_total_phase.py` — phases 1–46 are **lab** when in-repo proofs exist. EV / C3PAO / cloud Object Lock / production IdP / digital twin / 5k–100k HTTP remain ops and are never marked done.

**Working queue (immediate 10):** [MASTER-EXECUTION-PLAN.md](./MASTER-EXECUTION-PLAN.md) — finish control-plane loop + production proof before domain expansion.

Related: [securaiq-architecture.md](./securaiq-architecture.md) (Phase 0 — Rust agent + control plane freeze) ·
[agent-protocol-v1.md](./agent-protocol-v1.md) ·
[production-readiness.md](./production-readiness.md) ·
[realtime-v1.md](./realtime-v1.md) ·
[realtime-controls-evidence-spec.md](./realtime-controls-evidence-spec.md) ·
[control-plane-roadmap.md](./control-plane-roadmap.md) ·
[control-config-engine.md](./control-config-engine.md) ·
[agent-platform.md](./agent-platform.md) ·
[PHASE-A-GOLDEN-LOOP.md](./PHASE-A-GOLDEN-LOOP.md)

---

## Control-plane loop (north star)

```text
                    SECURAIQ
                       │
       ┌───────────────┼────────────────┐
       ▼               ▼                ▼
   SECURITY           RISK          COMPLIANCE
       │               │                │
       └───────────────┼────────────────┘
                       ▼
                    EVIDENCE
                       ▼
                 REMEDIATION
                       ▼
                    APPROVAL
                       ▼
                     AGENT
                       ▼
                      FIX
                       ▼
                  VERIFICATION
                       ▼
             RISK + COMPLIANCE
                 RECALCULATED
                       ▼
                  AUDIT PROOF
```

**Rule: don't add random features.** Finish foundations, then connect every security signal through:

```text
security → risk → compliance → evidence → remediation → verification
```

Modules reinforce this loop. AI may recommend; it must not claim success unless the system executed and verified.

---

## Immediate build order

**Priority: prove firewall closed loop (`realtime_acceptance_demo.py`) before Phase 22+ / full OS config trees.**

**Sprint order (do not skip ahead):** 1 Realtime foundation → 2 Agent security (mTLS) → 3 Controls+Evidence → 4 Closed-loop remediation depth → 5 Commercial (MFA/licensing/signed installers) → 6 Production ops. Freeze Phase 22+ until Sprint 1–4 closed loop is reliable.

**Phase 1 remaining** (Realtime Foundation):

1. ~~Dead-letter queue~~ (**done** when `REDIS_URL` set)
2. ~~Pending reclaim / XAUTOCLAIM~~ (**done**)
3. ~~Stream metrics~~ (**done** — `stream_monitor_snapshot` / health / Realtime Health UI)
4. ~~Default Streams fan-out~~ (**done** — `REALTIME_STREAMS_FANOUT=true` default)
5. ~~Soft backpressure signal~~ (**done** — flag + metric near maxlen; still durable XADD)
6. ~~Acceptance harness~~ (**done** — `realtime_acceptance_demo.py --local` + CI `phase1-realtime-gate`)
7. ~~Once-only multi-worker / reclaim proof (CI)~~ (**done** — `tests/test_realtime_phase1_proof.py`, `app/realtime/`)
8. Redis Sentinel **measured** failover (ops) — lab compose + `scripts/realtime_phase1_proof.py --document`; **not** Cluster certification

CI release gate: `.github/workflows/tests.yml` job `phase1-realtime-gate` (acceptance + durability + once-only + `--simulate`).

Compose lab HA stub: `docker compose --profile redis-ha up -d` + `REDIS_SENTINEL_HOSTS=127.0.0.1:26379` (see `deploy/redis/README.md`).
Admin DLQ ops: `GET/POST /api/admin/realtime/dlq` (list / replay / purge).

Run `scripts/realtime_acceptance_demo.py` / `scripts/realtime_phase1_proof.py` on owned lab endpoints.

**Freeze Phase 22+** (cloud / container / AppSec / identity / data / TPRM / malware depth / AI SecOps expansions) until the acceptance workflow works reliably on lab endpoints you own.

**Sprints 2–6 foundations (extended, not rewritten):** see [SPRINTS-2-6-PRODUCTION.md](./SPRINTS-2-6-PRODUCTION.md) — mTLS issue/rotate/revoke, control auto-evidence, closed-loop lifecycle vocabulary, licensing/MFA facades, SHA-256 release manifest. Commercial Authenticode and measured HA capacity remain ops claims.

Then deepen Phases 2–21 (agents, security pipeline, risk/compliance/evidence) before orange/blue expansion.

---

## Phases 1–46 (scope + status vs main)

Legend by track: **🔴** foundation / production · **🟠** domain expansion · **🔵** UX / moat

### 🔴 Phase 1 — Realtime foundation

- Universal event model (`event_id`, org/agent/asset, sequence, type/version, severity, payload, evidence IDs)
- Durable Redis Streams bus (consumer groups, ACK, retry, DLQ, replay, reclaim, backpressure, monitoring)
- Per-agent ordering + gap recovery
- Deduplication (one security action per `event_id`)
- Bounded offline agent queue → reconnect → ACK

**Status: lab** — event schema, Streams `XADD`, processor, offline
buffer, ordering, DLQ + XAUTOCLAIM + stream metrics, **default Streams fan-out**
(when `REDIS_URL` set), acceptance + once-only proofs in CI. Remaining for full
Phase 1 **ops** claim: commercial multi-AZ Sentinel (lab Desktop inject already measured).
Lab without Redis: in-process SSE bus is the supported realtime path.

---

### 🔴 Phase 2 — Real agent platform

- Windows / Linux / macOS inventory + host telemetry depth (OS, software, services, processes, firewall, Defender/SSH, logs, network, …)
- **One Rust core + OS adapters** (`securaiq-agent/`); Python lab agent until v0.1 parity

**Status: lab** — Python bridge has inventory + remediations; Rust agent **v0.3**
inventory/FIM/logs/`enable_*`. **Phase 4 (architecture):** agent packages → advisory CVE
match on check-in (debounced) → enterprise vuln bridge with listening-port exposure hint.
OS package→OSV accuracy still improving; full CPE/NVD mirror deferred.  
See [securaiq-architecture.md](./securaiq-architecture.md) · [agent-platform.md](./agent-platform.md).

---

### 🔴 Phase 3 — Agent security

- Enrollment → device identity → certs → mTLS → short-lived creds → rotation
- Replay protection, signed commands, policy, signed updates / rollback

**Status: lab** — bearer + HMAC + opt-in Ed25519; **RT-17** mandatory seals when
`AGENT_REQUIRE_COMMAND_SIGNATURE=true` (+ replay). **mTLS:** issue / renew / rotate / revoke
+ revocation denylist + proxy verify (`app/agent_certs.py`, agent certificate APIs). Signed
commercial installers still secrets-gated.

---

### 🔴 Phase 4 — Realtime command system

- Lifecycle: PENDING → APPROVED → … → VERIFIED (+ REJECTED / TIMEOUT / FAILED / EXPIRED)
- Controlled actions (patch, isolate, stop process, firewall, collect, scan, config) under approval/policy

**Status: lab** — command lifecycle dual-write on the bus with closed-loop
vocabulary (`RECOMMENDED`…`VERIFIED` + failure paths); allowlisted kinds include
`enable_firewall`, `enable_defender`, `disable_ssh_root`, `patch_package`, `agent_upgrade`,
`rollback` with host-control verification on next PASS/FAIL check-in. Not full isolate/kill-process yet.

---

### 🔴 Phase 5 — Security event engine

- Normalize → detection rules → correlation → threat → risk → incident → evidence → dashboard
- Severity, confidence, suppression, grouping, MITRE, IOC, tuning

**Status: lab** — foundations (threat ingest, processor hooks, RT-07 burst/keyword → incident);
check-in FIM modify/delete + **allowlisted** `security_logs` feed native `securaiq_agent_threats`;
knowledge graph hotspots include those detections; active threats bump risk priority
`threat_intel`. **Not** a full XDR / Sigma rule engine.

---

### 🔴 Phase 6 — EDR depth

- Process / file / network / persistence telemetry → behavior → IOC → MITRE → threat

**Status: lab** — snapshot + Sentinel heuristics + FIM; commercial EDR connectors are code-present, not live-tenant proven. **Not** a full EDR product.

---

### 🔴 Phase 7 — Vulnerability management

- CVE + CVSS/EPSS/KEV/CPE → assets → exposure → business criticality → attack path → fix → verify

**Status: lab** — agent check-in now triggers scoped advisory refresh + enterprise vuln bridge
(`software:advisory`) with listening-port exposure hints; KEV/NVD/OSV hooks exist. Still missing:
full CPE/NVD mirror, path-aware prioritization depth, OS-package match coverage.

---

### 🔴 Phase 8 — Patch management

- Software → vuln → plan → campaign → rings/windows → agent patch → inventory refresh → verify → evidence → risk reduction

**Status: lab** — campaigns + patch verification + queued campaign rollback; OS package-manager undo is not guaranteed.

---

### 🔴 Phase 9 — Risk engine

- Combine severity, exploitability, EPSS/KEV, exposure, criticality, attack path, controls, threat activity → technical / business / compliance / path risk

**Status: lab** — risk engine + org scoring exist; live host PASS/FAIL adjusts
compensating_controls; **active agent threats** bump threat_intel / priority reasons
(architecture Phase 6–7 Detect→Prioritize closed for this arc);
multi-lens business/compliance risk still deepening.

---

### 🔴 Phase 10 — Risk simulator

- “What should I fix first?” / “What if I fix these five?” → risk Δ, paths disrupted, compliance improved

**Status: lab** — risk simulator API exists; **≠** full digital twin (see Phase 33).

---

### 🔴 Phase 11 — Attack path engine

- CONFIRMED / INFERRED / UNVERIFIED edges with evidence; remediations that break dangerous paths

**Status: lab** — attack graph + RT-09 refresh hooks; no fake edges invented; twin-grade correlation missing.

---

### 🔴 Phase 12 — Compliance engine

- Framework → Requirement → Control → Test → Data source → Evidence → Result → Gap → Rem → Verify

**Status: lab** — frameworks + gap + remediations; Requirement entities still folded / not first-class.

---

### 🔴 Phase 13 — Control test engine

- Control metadata + test definition + data sources + pass/fail + evidence rules + frequency

**Status: lab** — live host control tests (firewall / Defender / SSH / disk encryption)
from agent telemetry; curated map only. Sprint 1 package: [control-config-engine.md](./control-config-engine.md)
(`app/controls/`, `/api/controls`). Task #144 Live Test UI remains frozen.

---

### 🔴 Phase 14 — Continuous compliance

- Telemetry → control test → PASS/FAIL → evidence → score/risk; FAIL → remediate → verify → PASS (no manual score editing)

**Status: lab** — continuous compliance panel + RT-10/11 host control loops
(firewall / Defender / SSH approve→verify lab parity; disk encryption observe→test→POA&M
recommend-only); not certification / C3PAO / full auto rem.

---

### 🔴 Phase 15 — Framework library

- Security (NIST CSF/800-53, CIS, ISO 27001, SOC 2, PCI), privacy/regulatory, sector, CMMC/DORA/NIS2/… with real mappings + tests

**Status: lab** — many catalogs in tree; depth and live-test coverage vary; do not claim full framework support.

---

### 🔴 Phase 16 — Cross-framework mapping

- One implementation (e.g. MFA) → evidence for multiple applicable controls

**Status: lab** — cross-map exists in catalogs/services; canonical UI map still Sprint C+.

---

### 🔴 Phase 17 — Evidence engine

- Auto-evidence on threat / control fail / patch / verify / pass; full metadata (hash, retention, links)

**Status: lab** — evidence store + observed/derived stamps in several paths; not every claim auto-records.

---

### 🔴 Phase 18 — Evidence integrity

- SHA-256, custody chain, signatures, object storage, **WORM** / immutable high-assurance packages

**Status: lab** — hashing / append-only audit + local FS WORM markers; cloud Object Lock remains **ops**.

---

### 🔴 Phase 19 — Audit center

- Framework drill-down → export audit package

**Status: lab** — Audit Center + audit ZIP paths exist; package completeness / attestation workflow thin.

---

### 🔴 Phase 20 — Compliance exceptions

- Owned, expiring exceptions with compensating control, approver, review — never permanent silent “fixed”

**Status: lab** — exceptions model/UI foundations; not a complete enterprise exception lifecycle.

---

### 🔴 Phase 21 — Policy management

- Policies (password, MFA, patch, backup, …) → control → test → evidence

**Status: lab** — policy docs / gap paste + compliance tasks exist; full policy→control engine still deepening.

---

### 🟠 Phases 22–32 — Domain expansion (condensed)

| Phase | Scope (short) | Status vs main |
|-------|---------------|----------------|
| **22** Cloud security / CSPM (AWS · Azure · GCP) | Connectors / posture stubs | **lab** — code present; **not** live-tenant verified CSPM |
| **23** Container / Kubernetes | Image/RBAC/netpol/privileged | **lab** — scanner adapters + packaging; ≠ K8s posture / Helm product |
| **24** Application security | SAST/DAST/SCA/secrets/IaC/API + VCS/CI | **lab** — import adapters + web scanner; not full AppSec platform |
| **25** SBOM / supply chain | SPDX/CycloneDX, provenance, license | **lab** — CI SBOM + adapters; do not overclaim |
| **26** Identity security | Entra/AD/Okta/… MFA, privilege, anomalies | **lab** — graph identity depth; no full live IdP product |
| **27** Data security | PII/PHI/PCI discovery, classification, flows | **lab** — data governance API; not full DLP |
| **28** Third-party risk | Vendor questionnaire → evidence → risk | **lab** — enterprise vendor path; deepen questionnaires |
| **29** Malware analysis | Hash → static → behavior → sandbox (isolated) | **lab** — intel only; no malware engine |
| **30** Incident response | Detection → entities → MITRE → path → response → verify | **lab** — TheHive + SOC desk + playbooks; deep IR timeline incomplete |
| **31** AI Security Operations | Investigate → recommend → **approve** → execute → verify | **lab** — `app/secops` allowlisted tools + propose-only remediations; not unrestricted tool autonomy |
| **32** AI Security (AISPM) | Models, keys, prompt injection, AI governance | **lab** — AI security tests; not a full AISPM product |

**Freeze note:** do not expand these until Phase 1 completion + acceptance workflow greens.

---

### 🔵 Phases 33–34 — Moat (roadmap P2)

| Phase | Scope | Status |
|-------|-------|--------|
| **33** Security Digital Twin | Full env model; “what if I patch WEB-01?” | **lab** — risk sim exists; twin depth remains **ops** / frozen |
| **34** Business services | Service → apps → assets → data → controls → risk | **lab** — service-impact API; twin graph still deepening |

---

### 🔵 Phases 35–39 — Product UX

| Phase | Scope | Status |
|-------|-------|--------|
| **35** Realtime UI | One `RealtimeManager` → router → state; major screens live | **lab** — SSE + manager; some panels still poll |
| **36** UI/UX pattern | WHAT → WHY → EVIDENCE → IMPACT → ACTION → VERIFY | **lab** |
| **37** Executive mode | CISO posture without raw telemetry flood | **lab** — Mission Control / exec views |
| **38** SOC mode | Events, threats, MITRE, timeline, response | **lab** |
| **39** Compliance mode | Frameworks, tests, evidence, gaps, exceptions, audits | **lab** |

---

### 🔴 Phases 40–46 — Enterprise platform & proof

| Phase | Scope | Status |
|-------|-------|--------|
| **40** Multi-tenancy | `organization_id` + server-side authz | **lab** — high-value tables scoped; intentional leftovers stay isolated |
| **41** Enterprise auth | SAML/OIDC/SSO/SCIM + MFA + RBAC + API keys | **lab** — auth/RBAC/API keys/MFA + SAML/OIDC facades; live IdP **ops** |
| **42** Audit (platform) | WHO/WHAT/WHEN/BEFORE/AFTER on sensitive actions | **lab** — `audit_log` + SIEM forward option |
| **43** HA / DR | API/worker/Redis HA, Postgres backup, restore drills | **lab** — Sentinel lab inject + backup drill; Postgres HA / multi-AZ **ops** |
| **44** Security of SecuraIQ | Dogfood SAST/DAST/SCA/SBOM/secrets/container/IaC | **lab** — suites + Trust Center; third-party pentest **ops** |
| **45** Realtime load testing | 100 → 5,000 agents with p50/p95/loss metrics | **lab** — ladder ≤1k measured; **do not claim 5k** |
| **46** Chaos testing | Kill API/Redis/worker/DB; reconnect agents; no lost events / no cross-tenant leak | **lab** — soft chaos harness; Redis kill manual; chaos@5k **ops** |

---

## Target architecture (after foundations)

```text
                         SECURAIQ
                            │
                   ┌────────┴────────┐
                   │  API / Gateway  │
                   └────────┬────────┘
                            │
                     Redis Streams
                            │
        ┌───────────────────┼────────────────────┐
        ▼                   ▼                    ▼
    Detection              Risk              Compliance
        │                   │                    │
        └───────────────────┼────────────────────┘
                            ▼
                         Evidence
                            │
                    ┌───────┴────────┐
                    ▼                ▼
               Incidents       Remediation
                                      │
                                   Approval
                                      │
                                      ▼
                                    Agent → Fix → Verification
                                      │
                         ┌────────────┴───────────┐
                         ▼                        ▼
                       Risk                  Compliance
                         └──────────┬─────────────┘
                                    ▼
                                  Audit → Dashboard SSE
```

---

## 10 most important remaining things

1. **Durable realtime event pipeline** — Redis HA/Sentinel (Phase 1 almost done: DLQ/reclaim/metrics/default Streams fan-out)
2. **Fully wired offline-capable secure agents** — mTLS/certs + richer telemetry (Phases 2–3)
3. **Detection → Risk → Incident → Evidence** pipeline depth (Phases 5–6)
4. **Agent telemetry → Control Test → Compliance → Evidence** (Phases 13–14)
5. **Remediation → Agent → Verification → Risk/Compliance** closed loop (Phases 4, 8, 11–14)
6. **Complete realtime dashboard** without unnecessary polling (Phase 35)
7. **Multi-tenant + RBAC + SSO + agent crypto** (Phases 3, 40–41)
8. **Cloud / Identity / Application / Supply-chain** coverage — *after* acceptance greens (Phases 22–26)
9. **Load + chaos + recovery** testing — measure before claiming scale (Phases 45–46)
10. **Security Digital Twin + Risk Simulator** as long-term moat (Phases 10, 33–34) — sim exists ≠ twin

---

## Acceptance test workflow

Use this as the single product acceptance bar (authorized lab / owned systems only):

```text
Endpoint change
      → detect
      → risk updates
      → compliance control updates
      → evidence created
      → (AI explains — optional)
      → approved remediation executes
      → endpoint fixed
      → verification confirms
      → risk + compliance improve
      → entire chain live in the UI (SSE)
```

If that chain works reliably, SecuraIQ is a **control plane**, not a feature checklist or a Wazuh-style dashboard clone.

---

## How this doc relates

| Doc | Role |
|-----|------|
| **This file** | Canonical 46-phase Master Build Plan + honest status |
| [securaiq-architecture.md](./securaiq-architecture.md) | Phase 0 freeze: Rust agent + 3 layers + build order |
| [agent-protocol-v1.md](./agent-protocol-v1.md) | Agent ↔ server wire contracts |
| [agent-platform.md](./agent-platform.md) | Agent platform module map + allowlisted commands |
| [realtime-v1.md](./realtime-v1.md) | Task-level realtime implementation (RT-01…RT-20) |
| [production-readiness.md](./production-readiness.md) | Ship / enterprise marketing gate |
| [control-plane-roadmap.md](./control-plane-roadmap.md) | Pillars + P0–P2 priority narrative |
