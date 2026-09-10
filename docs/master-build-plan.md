# SecuraIQ — Master Build Plan

**Canonical product strategy:** Continuous Security, Risk & Compliance Control Plane  
**Status key:** **Done** · **Partial** · **Missing** — vs current `main` (honest; do not invent Done)

Related: [securaiq-architecture.md](./securaiq-architecture.md) (Phase 0 — Rust agent + control plane freeze) ·
[agent-protocol-v1.md](./agent-protocol-v1.md) ·
[production-readiness.md](./production-readiness.md) ·
[realtime-v1.md](./realtime-v1.md) ·
[control-plane-roadmap.md](./control-plane-roadmap.md) ·
[control-config-engine.md](./control-config-engine.md) ·
[agent-platform.md](./agent-platform.md)

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

**Next only: complete Phase 1** (Realtime Foundation durability):

1. Dead-letter queue (`XADD` to DLQ after max deliveries)
2. Pending reclaim (`XAUTOCLAIM` / idle pending recovery)
3. Stream metrics / monitoring (lag, pending, DLQ depth)
4. Acceptance harness for the end-to-end workflow below

Run the local acceptance demo with `scripts/realtime_acceptance_demo.py` once Redis Streams durability (DLQ + reclaim) is up.

**Freeze Phase 22+** (cloud / container / AppSec / identity / data / TPRM / malware depth / AI SecOps expansions) until the acceptance workflow works reliably on lab endpoints you own.

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

**Status: Near-done (lab)** — event schema, Streams `XADD`, processor, offline
buffer, ordering, **DLQ + XAUTOCLAIM + stream metrics** (when `REDIS_URL` set),
firewall FAIL→PASS acceptance harness green. Remaining for full Phase 1 claim:
default Streams fan-out + Redis HA/Sentinel (multi-worker production).
Lab without Redis: in-process SSE bus is the supported realtime path.

---

### 🔴 Phase 2 — Real agent platform

- Windows / Linux / macOS inventory + host telemetry depth (OS, software, services, processes, firewall, Defender/SSH, logs, network, …)
- **One Rust core + OS adapters** (`securaiq-agent/`); Python lab agent until v0.1 parity

**Status: Partial** — Python bridge has inventory + allowlisted remediations; Rust agent
**v0.3** deep inventory, FIM, security log samples, and **`enable_firewall` / `enable_defender`**
(fixed argv + seal verify). Patch/upgrade still Python. **Not** full EDR.  
See [securaiq-architecture.md](./securaiq-architecture.md) · [agent-platform.md](./agent-platform.md).

---

### 🔴 Phase 3 — Agent security

- Enrollment → device identity → certs → mTLS → short-lived creds → rotation
- Replay protection, signed commands, policy, signed updates / rollback

**Status: Partial** — bearer + HMAC + opt-in Ed25519 + require-signature flag; **missing** mTLS / cert rotation.

---

### 🔴 Phase 4 — Realtime command system

- Lifecycle: PENDING → APPROVED → … → VERIFIED (+ REJECTED / TIMEOUT / FAILED / EXPIRED)
- Controlled actions (patch, isolate, stop process, firewall, collect, scan, config) under approval/policy

**Status: Partial** — command lifecycle dual-write on the bus; **limited** action kinds.

---

### 🔴 Phase 5 — Security event engine

- Normalize → detection rules → correlation → threat → risk → incident → evidence → dashboard
- Severity, confidence, suppression, grouping, MITRE, IOC, tuning

**Status: Partial** — foundations (threat ingest, processor hooks, RT-07 burst/keyword → incident); **not** full XDR correlation / rule engine depth.

---

### 🔴 Phase 6 — EDR depth

- Process / file / network / persistence telemetry → behavior → IOC → MITRE → threat

**Status: Missing** (EDR depth) — snapshot + Sentinel heuristics only; commercial EDR connectors are code-present, not live-tenant proven.

---

### 🔴 Phase 7 — Vulnerability management

- CVE + CVSS/EPSS/KEV/CPE → assets → exposure → business criticality → attack path → fix → verify

**Status: Partial** — vuln import/register, KEV/NVD hooks, inventory bridges exist; full path-aware prioritization incomplete.

---

### 🔴 Phase 8 — Patch management

- Software → vuln → plan → campaign → rings/windows → agent patch → inventory refresh → verify → evidence → risk reduction

**Status: Partial** — campaigns + patch verification hooks exist; OS/package/rollback depth limited.

---

### 🔴 Phase 9 — Risk engine

- Combine severity, exploitability, EPSS/KEV, exposure, criticality, attack path, controls, threat activity → technical / business / compliance / path risk

**Status: Partial** — risk engine + org scoring exist; multi-lens business/compliance risk not complete.

---

### 🔴 Phase 10 — Risk simulator

- “What should I fix first?” / “What if I fix these five?” → risk Δ, paths disrupted, compliance improved

**Status: Partial** — risk simulator API exists; **≠** full digital twin (see Phase 33).

---

### 🔴 Phase 11 — Attack path engine

- CONFIRMED / INFERRED / UNVERIFIED edges with evidence; remediations that break dangerous paths

**Status: Partial** — attack graph + RT-09 refresh hooks; no fake edges invented; twin-grade correlation missing.

---

### 🔴 Phase 12 — Compliance engine

- Framework → Requirement → Control → Test → Data source → Evidence → Result → Gap → Rem → Verify

**Status: Partial** — frameworks + gap + remediations; Requirement entities still folded / not first-class.

---

### 🔴 Phase 13 — Control test engine

- Control metadata + test definition + data sources + pass/fail + evidence rules + frequency

**Status: Partial** — live host control tests (firewall / Defender / SSH) from agent telemetry; curated map only. Sprint 1 package: [control-config-engine.md](./control-config-engine.md) (`app/controls/`, `/api/controls`). Task #144 Live Test UI remains frozen.

---

### 🔴 Phase 14 — Continuous compliance

- Telemetry → control test → PASS/FAIL → evidence → score/risk; FAIL → remediate → verify → PASS (no manual score editing)

**Status: Partial** — continuous compliance panel + RT-10/11 firewall stub loop; not certification / full auto rem.

---

### 🔴 Phase 15 — Framework library

- Security (NIST CSF/800-53, CIS, ISO 27001, SOC 2, PCI), privacy/regulatory, sector, CMMC/DORA/NIS2/… with real mappings + tests

**Status: Partial** — many catalogs in tree; depth and live-test coverage vary; do not claim full framework support.

---

### 🔴 Phase 16 — Cross-framework mapping

- One implementation (e.g. MFA) → evidence for multiple applicable controls

**Status: Partial** — cross-map exists somewhat in catalogs/services; canonical UI map still Sprint C+.

---

### 🔴 Phase 17 — Evidence engine

- Auto-evidence on threat / control fail / patch / verify / pass; full metadata (hash, retention, links)

**Status: Partial** — evidence store + observed/derived stamps in several paths; not every claim auto-records.

---

### 🔴 Phase 18 — Evidence integrity

- SHA-256, custody chain, signatures, object storage, **WORM** / immutable high-assurance packages

**Status: Partial** — hashing / append-only audit patterns; **missing** WORM / object-lock completeness.

---

### 🔴 Phase 19 — Audit center

- Framework drill-down → export audit package

**Status: Partial** — Audit Center + audit ZIP paths exist; package completeness / attestation workflow thin.

---

### 🔴 Phase 20 — Compliance exceptions

- Owned, expiring exceptions with compensating control, approver, review — never permanent silent “fixed”

**Status: Partial** — exceptions model/UI foundations; not a complete enterprise exception lifecycle.

---

### 🔴 Phase 21 — Policy management

- Policies (password, MFA, patch, backup, …) → control → test → evidence

**Status: Missing / Partial** — policy docs / gap paste exist; full policy→control engine missing.

---

### 🟠 Phases 22–32 — Domain expansion (condensed)

| Phase | Scope (short) | Status vs main |
|-------|---------------|----------------|
| **22** Cloud security / CSPM (AWS · Azure · GCP) | Connectors / posture stubs | **Partial connectors** — code present; **not** live-tenant verified CSPM |
| **23** Container / Kubernetes | Image/RBAC/netpol/privileged | **Missing / thin** — scanner adapters ≠ K8s posture product |
| **24** Application security | SAST/DAST/SCA/secrets/IaC/API + VCS/CI | **Partial** — import adapters + web scanner; not full AppSec platform |
| **25** SBOM / supply chain | SPDX/CycloneDX, provenance, license | **Missing / Partial** — do not overclaim |
| **26** Identity security | Entra/AD/Okta/… MFA, privilege, anomalies | **Missing / Partial** — identity baseline on roadmap; no full IdP product |
| **27** Data security | PII/PHI/PCI discovery, classification, flows | **Missing** |
| **28** Third-party risk | Vendor questionnaire → evidence → risk | **Missing / Partial** |
| **29** Malware analysis | Hash → static → behavior → sandbox (isolated) | **Missing** (lab knowledge only) |
| **30** Incident response | Detection → entities → MITRE → path → response → verify | **Partial** — SOC desk + playbooks; deep IR timeline incomplete |
| **31** AI Security Operations | Investigate → recommend → **approve** → execute → verify | **Partial** — AI Analyst / investigate + approvals; not unrestricted tool autonomy |
| **32** AI Security (AISPM) | Models, keys, prompt injection, AI governance | **Missing** |

**Freeze note:** do not expand these until Phase 1 completion + acceptance workflow greens.

---

### 🔵 Phases 33–34 — Moat (roadmap P2)

| Phase | Scope | Status |
|-------|-------|--------|
| **33** Security Digital Twin | Full env model; “what if I patch WEB-01?” | **Missing** / roadmap P2 — risk sim ≠ twin |
| **34** Business services | Service → apps → assets → data → controls → risk | **Missing** |

---

### 🔵 Phases 35–39 — Product UX

| Phase | Scope | Status |
|-------|-------|--------|
| **35** Realtime UI | One `RealtimeManager` → router → state; major screens live | **Partial** — SSE + manager; some panels still poll |
| **36** UI/UX pattern | WHAT → WHY → EVIDENCE → IMPACT → ACTION → VERIFY | **Partial** |
| **37** Executive mode | CISO posture without raw telemetry flood | **Partial** — Mission Control / exec views |
| **38** SOC mode | Events, threats, MITRE, timeline, response | **Partial** |
| **39** Compliance mode | Frameworks, tests, evidence, gaps, exceptions, audits | **Partial** |

---

### 🔴 Phases 40–46 — Enterprise platform & proof

| Phase | Scope | Status |
|-------|-------|--------|
| **40** Multi-tenancy | `organization_id` + server-side authz | **Partial→near-done** — high-value tables scoped; intentional lab leftovers |
| **41** Enterprise auth | SAML/OIDC/SSO/SCIM + MFA + RBAC + API keys | **Partial** — auth/RBAC/API keys/MFA paths; **missing** full SSO/SCIM |
| **42** Audit (platform) | WHO/WHAT/WHEN/BEFORE/AFTER on sensitive actions | **Partial** — `audit_log` + SIEM forward option |
| **43** HA / DR | API/worker/Redis HA, Postgres backup, restore drills | **Missing / Partial** — scripts + docs; not proven HA |
| **44** Security of SecuraIQ | Dogfood SAST/DAST/SCA/SBOM/secrets/container/IaC | **Partial** — suites + tooling; no full posture report product |
| **45** Realtime load testing | 100 → 5,000 agents with p50/p95/loss metrics | **Partial** — ladder ≤1k; **do not claim 5k** |
| **46** Chaos testing | Kill API/Redis/worker/DB; reconnect agents; no lost events / no cross-tenant leak | **Partial** — soft chaos harness; Redis kill manual; **missing** chaos@5k |

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

1. **Durable realtime event pipeline** — DLQ, reclaim, default Streams fan-out, metrics (finish Phase 1)
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
