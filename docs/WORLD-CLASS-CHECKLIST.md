# SecuraIQ — World-Class Build List (honest status)

**Objective:** world-class + sellable + scalable toward **100,000 assets** — without marketing unmeasured capacity or unfinished depth.

**Philosophy:** Do not win with the most scanners. Win with:

> We know what you have, what is exposed, why it matters, what business impact it has, what compliance it affects, what to do, whether the fix worked, and what evidence proves it.

**Status key**

| Mark | Meaning |
|------|---------|
| **done** | Shipped and usable in lab/product path |
| **lab** | Lab-production — code-ready; commercial/ops leftovers called out |
| **partial** | Exists; depth or coverage incomplete |
| **ops** | Blocked on Docker/certs/owned-host/live measure — do not fake |
| **frozen** | Release 5 / breadth — wait for Phase 1 green on owned-host + HA/load |
| **missing** | Not started as a first-class capability |

**Governing six:** WHAT → WHY → EVIDENCE → IMPACT → ACTION → VERIFY

Cross-links: [PRODUCTION-CONTROL-PLANE.md](./PRODUCTION-CONTROL-PLANE.md) · [RELEASE-GATES.md](./RELEASE-GATES.md) · [USP-CLAIMS.md](./USP-CLAIMS.md) · [production-readiness.md](./production-readiness.md) · [ops/CAPACITY-LAB.md](./ops/CAPACITY-LAB.md) · [POSTURE-ENGINE.md](./POSTURE-ENGINE.md)

**Freeze:** Do not expand Phase 5 twin / cloud-depth / AI autonomy until Phase 1 stays green on **owned-host** + measured HA/load.

---

## Priority order (execute in this sequence)

| Phase | Theme | Focus |
|-------|--------|--------|
| **1** | Trustworthy | Realtime → Agent security → Evidence → Risk → Tenant isolation → HA/DR |
| **2** | Powerful | Built-in scanners → Exposure → Cloud → Identity → AppSec → Attack paths |
| **3** | Operational | Remediation → Verification → Compliance Ops → CMMC → AI SecOps |
| **4** | Enterprise | SSO/SCIM depth → On-prem → Air-gap → MSP → SLA → 100K measure → certs |
| **5** | Differentiated | Business graph → Risk simulation depth → Digital twin → AI evidence/remediation |

---

## 1. Core platform foundation — P0

| Item | Status | Notes |
|------|--------|-------|
| Multi-tenant architecture | **lab** | Orgs + `org_id` on high-value tables |
| Strict tenant isolation | **lab** | Fail-closed tests + object-store org keys; cloud WORM ops |
| RBAC | **lab** | `require_perm` + org roles; lab AUTH-off = global admin |
| MFA | **done** | TOTP + recovery codes |
| SSO/OIDC/SAML | **lab** | Facades + readiness; full IdP depth open |
| SCIM | **lab** | Users + Groups; not full RFC depth |
| API authentication | **done** | Sessions + bearer; agent keys |
| Service accounts | **partial** | Agent identities; dedicated SA model thin |
| Rate limiting | **done** | `RateLimitMiddleware` |
| Audit logging | **lab** | Hash chain + sealed export; SQLite ≠ WORM |
| Secrets management | **partial** | Envelope crypto; no KMS/HSM |
| PostgreSQL HA | **ops** | Docs/scripts; operator-owned |
| Redis HA | **lab** | Live Desktop inject measured (`docker exec` + optional lab assist); ≠ multi-AZ |
| Backup + restore | **partial** | Scripts + runbooks |
| Disaster recovery | **partial** | Documented; not automated product test |
| Encryption at rest/in transit | **partial** | TLS scaffolding; at-rest = OS/volume |
| Key rotation | **partial** | Agent certs rotate; app/KMS rotation thin |
| Object storage | **lab** | Local + S3/MinIO path; org-keyed |
| Immutable/WORM evidence | **lab** | Local FS readonly markers; cloud Object Lock still **ops** |
| Data retention policies | **partial** | Retention module exists; deepen |
| Data deletion workflows | **partial** | GDPR export/delete paths |

---

## 2. Universal realtime engine — P0

| Item | Status |
|------|--------|
| Universal event schema | **lab** |
| Event IDs | **lab** |
| Idempotency | **lab** |
| Deduplication | **lab** |
| Ordering | **partial** (best-effort; no per-tenant authority) |
| Sequence numbers | **lab** |
| Gap detection | **lab** |
| Replay | **lab** |
| DLQ | **lab** (+ soft recover) |
| Retry | **lab** |
| Backpressure | **lab** (soft shed) |
| Event retention | **partial** |
| Tenant-aware streams | **partial** (SSE filter; stream key global) |
| Worker pools | **partial** (processor + jobs) |
| Queue monitoring | **lab** (Mission Control) |
| Event tracing | **lab** (correlation/causation) |
| Event latency metrics | **lab** (stage meters; unclaimed SLO) |
| SSE replay | **lab** |
| Reconnect | **lab** |
| Live state synchronization | **partial** (SSE + some poll) |

**Honesty:** Not HA exactly-once. Redis Streams when `REDIS_URL` set; in-proc otherwise.

---

## 3. Continuous Posture Engine — P0

| Layer | Status | Notes |
|-------|--------|-------|
| Realtime telemetry (agent, firewall, Defender, FIM, threats) | **lab** | Host controls + agent check-in |
| Process/user/config change depth | **partial** | Some signals; not full EDR |
| 30-min reconciliation (asset, controls, freshness, risk, compliance, tasks, notify) | **done** | Layer B — **never** Nmap/Nuclei/ZAP |
| Drift detection | **partial** | Freshness/stale; deepen |
| Deep scans (net/web/API/cloud/DAST/EASM/SBOM/config) | **partial** | Engines exist; **not** on 30-min cadence |

---

## 4. Built-in SecuraIQ Security Engine — P0/P1

| Domain | Status | Notes |
|--------|--------|-------|
| Discovery (asset/network) | **partial** | Agent + scans; EASM/DNS/subdomain thin |
| Network (TCP/ports/services/TLS) | **partial** | Nmap/builtin paths |
| Vulnerability (CVE/CVSS/KEV/CPE/prio) | **lab** | EPSS/aging deepen |
| Web / DAST | **lab** | Builtin web + ZAP/Nuclei optional |
| API scanner (branded) | **lab** | Facade over web/ZAP/Nuclei |
| Configuration / CIS / hardening | **partial** | Host controls + HardeningKitty path |
| Secret / Config scanners (branded) | **lab** | Facades over Gitleaks / Checkov |

---

## 5. Endpoint agent — P0

| OS | Status |
|----|--------|
| Windows (services, Defender, firewall, users, processes, FIM, …) | **partial→lab** (core loops; deepen registry/tasks) |
| Linux (packages, systemd, SSH, firewall, FIM, …) | **partial→lab** |
| macOS | **partial** (lighter coverage) |

---

## 6. Agent security — P0

| Item | Status |
|------|--------|
| mTLS + device identity + cert rotate/revoke | **lab** (flags off by default; commercial five-flag) |
| Short-lived credentials | **partial** |
| Signed commands + expiry + nonce/replay | **lab** (`AGENT_LAB_SEALED_MODE`) |
| Command authorization (allowlist) | **done** |
| Agent policy | **partial** |
| Secure update / signed packages / rollback | **lab** (sha256 + lab Authenticode; EV/SmartScreen **ops**) |
| Tamper detection | **missing** |
| Offline queue + bounded storage | **lab** |
| Secure bootstrap | **partial** |

---

## 7. Asset Intelligence — P0

| Item | Status |
|------|--------|
| Rich asset object (identity, software, vulns, controls, risk, paths, history) | **partial→lab** |
| Dedup / identity resolution / IP·hostname·agent·scanner correlation | **lab** (`asset_aliases`) |
| Ownership / criticality / lifecycle | **lab** |
| Business service mapping | **partial** / Phase 5 depth **frozen** |

---

## 8. Exposure Management — P0/P1

| Item | Status |
|------|--------|
| Internet-facing / vuln exposure | **lab** |
| Identity / cloud / app / data exposure | **partial** |
| Attack paths | **lab** (narrow computed graph) |
| Toxic combinations / misconfig chains | **partial** / deepen in Phase 2 |

---

## 9. Risk Engine — P0

| Item | Status |
|------|--------|
| Factor risk (criticality, exposure, KEV, controls, …) | **lab** |
| Org / asset risk + explanation + simulation | **lab** |
| Technical / business / compliance risk facets | **partial** |
| Risk history / trend | **partial** |
| “Why did risk increase” narrative | **lab** (`/api/risk/why-increased`) |

---

## 10. Business Service Graph — P1

| Item | Status |
|------|--------|
| Service → app → server → cloud → identity → data | **partial** / **frozen** for twin depth |
| “Which services does this vuln affect?” | **partial** |

---

## 11. Evidence Spine — P0

| Item | Status |
|------|--------|
| Universal envelope, SHA-256, source, collector, asset, agent, freshness, expiry | **done** |
| Versioning / review / accept-reject | **lab** |
| Lineage / access log | **partial** |
| WORM / object lock | **lab** (local FS markers); cloud Object Lock **ops** |
| Conflict resolution / reconciliation | **lab** |

**Rule:** Finish this spine — do **not** build a second evidence system.

---

## 12–14. Compliance + CMMC + Compliance Ops — P0

| Area | Status |
|------|--------|
| Framework model (req → control → test → evidence → task) | **lab** |
| Frameworks (NIST/ISO/SOC2/CIS/PCI/HIPAA/GDPR/DPDP/…) | **lab** (catalog depth varies) |
| CMMC Tier-1 (objectives, SSP, POA&M, examine/interview/test, CUI, affirmation, SPRS prep, audit pack) | **lab** — not C3PAO/SPRS submit |
| CMMC L3 / determination statements verbatim | **partial** / honesty-bound |
| Compliance Ops (calendar, tasks, escalation L1–L3, approvals, evidence gates) | **lab** |
| Email/Teams/Slack/webhooks for ops | **partial** (notify + connectors) |

---

## 15. Remediation Engine — P0

| Item | Status |
|------|--------|
| Recommend → approve → campaign → agent → execute → verify | **lab** |
| Safe allowlisted commands | **done** |
| Rings / maintenance windows | **partial** |
| Rollback | **partial** |
| Auto evidence on approve/execute | **lab** |

---

## 16. AI SecOps — P1

| Capability | Status |
|------------|--------|
| Explain why risk increased | **lab** (deterministic; LLM optional) |
| Prioritize / investigate / evidence gaps | **partial** |
| Policy → approval → signed command → verify action path | **lab** (seals); AI autonomy **frozen** |

---

## 17–22. Attack paths, Cloud, Identity, AppSec, Threat, IR — P1

| Area | Status |
|------|--------|
| Attack path engine | **lab** (narrow); twin depth **frozen** |
| Cloud security (AWS/Azure/GCP native depth) | **partial** (posture connectors); depth **frozen**/Phase 2 |
| Identity security (Entra/Okta/AD) | **partial** / Phase 2 |
| App/supply chain (SAST/SCA/SBOM/secrets/container/IaC/DAST) | **lab** (adapters + branded facades) |
| Threat detection normalization | **partial** |
| Incident response (timeline, containment actions) | **partial** |

---

## 23. Integrations — P1

| Family | Status |
|--------|--------|
| Wazuh, Defender, CrowdStrike, SentinelOne, Sophos, cloud SCC | **lab** (live connectors) |
| Splunk / Elastic | **lab** (export ingest + HEC forward; live when creds) |
| Nessus / Tenable / Qualys / Rapid7 / Wiz / OpenVAS | **lab** (export ingest; live API when creds) |
| Jira / ServiceNow | **partial** |
| Entra / Okta / Google IdP | **partial** (OIDC/SAML facades) |

---

## 24. MSP/MSSP edition — P1

| Item | Status |
|------|--------|
| Multi-customer tenancy | **lab** (orgs) |
| Delegated admin / white label / central SOC / cross-customer | **missing** / Phase 4 |
| Billing / portal | **partial** (Stripe path) |

---

## 25–26. Deployment + installers — P0/P1

| Item | Status |
|------|--------|
| SaaS / on-prem / Docker | **partial→lab** |
| Kubernetes / Helm / air-gap | **partial** / scaffolds |
| Private AI / local evidence | **lab** |
| Windows MSI/EXE | **lab** (lab PFX signed; EV Authenticode **ops**) |
| Linux DEB/RPM/TAR | **partial** |
| macOS PKG/DMG + notarize | **partial** (**ops**) |

---

## 27. Scale 1 → 100,000 — P0

| Rung | In-proc | Soft check-in | HTTP check-in |
|------|---------|---------------|---------------|
| 100 | Measured | Measured | **Measured** |
| 500 | Measured | Measured | **Measured** |
| 1K | Measured | Measured | **Measured (99.3%, 2026-09-22)** |
| 5K–100K | Measured (aggregator) | Soft to 1k | Unmeasured |

Measure events/sec, API p50/p95/p99, queue lag, Redis/PG, workers, SSE, loss/dupes, 30-min refresh — see [ops/CAPACITY-LAB.md](./ops/CAPACITY-LAB.md).

**Never market a capacity number before measuring it.**

Live verify: `python scripts/live_lab_verify.py --server http://127.0.0.1:8080 --i-own-this-host`

---

## 28. Chaos / failure testing — P0

| Item | Status |
|------|--------|
| Soft chaos (dupes, order, DLQ, BP, SSE recovery) | **lab** |
| Redis/DB/worker kill, Sentinel inject | **lab** (Desktop inject measured; ≠ multi-AZ) |

---

## 29. SecuraIQ must secure itself — P0

| Item | Status |
|------|--------|
| Bandit / Semgrep / Gitleaks / Trivy / Checkov / ZAP / SBOM CI | **lab** |
| Dogfood product report | **lab** |
| Pentest / fuzz / Trust Center page | **partial** / missing public Trust Center |

---

## 30–34. UI modes — Command / WHY / Exec / SOC / Compliance

| Mode | Status |
|------|--------|
| Command Center / Security Pulse | **partial→lab** (Mission Control + posture) |
| WHAT/WHY/EVIDENCE/IMPACT/ACTION/VERIFY | **lab** (pattern in UI; deepen) |
| Executive / SOC / Compliance modes | **partial** (views exist; not fully separated products) |

---

## 35–38. Trust Center, commercial, onboarding, ROI metrics

| Area | Status |
|------|--------|
| Customer Trust Center | **missing** / thin docs |
| Commercial (license, Stripe, trial, entitlements) | **lab** |
| Killer onboarding (org → agent → asset → risk → top 5) | **partial** |
| ROI metrics (exposure↓, MTTR↓, verified remediation↑) | **partial** |

---

## 39. Target architecture (north star)

```text
BUILT-IN ENGINES + CONNECTORS
            ↓
    UNIVERSAL EVENT BUS
            ↓
      SECURITY TRUTH
            ↓
   ASSET / EXPOSURE / RISK / BUSINESS GRAPH
            ↓
   COMPLIANCE + EVIDENCE SPINE
            ↓
   REMEDIATION → APPROVAL → AGENT → VERIFY
            ↓
   NEW TRUTH → POSTURE → SSE → COMMAND/SOC/EXEC
```

This matches the product philosophy. **Phases 2–5 breadth stay gated** by Phase 1 trust + measured scale.

---

## What to do next (ordered)

1. ~~Code-unblock Phase 1 leftovers~~ — **done**  
2. ~~HTTP 500 + 1000 measure~~ — **done** (truncated check-ins; not production SLO)  
3. ~~`/ready` live~~ — **done** (fixed Redis import; lab in-process ready)  
4. ~~Live lab verify harness~~ — **done** (`scripts/live_lab_verify.py`)  
5. ~~Live Sentinel inject~~ — **done** (lab Desktop measure; `failover_forced` assist OK; ≠ commercial HA)  
6. ~~Lab Authenticode + local FS WORM~~ — **done** (EV cert + cloud Object Lock still **ops**)  
7. **Ops-only (do not fake):** EV Authenticode secrets, cloud WORM Object Lock, Postgres HA, IdP production.  
8. **Do not** start Phase 5 twin / AI autonomy / cloud-module sprawl.  
9. World-class sections 2–5 breadth remain a multi-phase product roadmap — sell the closed loop that is lab-production today.

*Snapshot aligned to main · 2026-09-22 · Phase-1 lab board green; commercial leftovers stay ops.*
