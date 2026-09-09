# SecuraIQ — Control Plane Roadmap

**Product:** SecuraIQ — Continuous Security, Risk & Compliance Control Plane  
**Repo:** https://github.com/nrbns/SecuralQ  

Do **not** treat this as a feature dump. Close platform gaps that turn what already exists (scans, agents, compliance, evidence, risk, remediation) into an operating system for security → risk → compliance.

**Gate:** [production-readiness.md](./production-readiness.md) — not “framework names in a dropdown.”  
**Master plan (46 phases):** [master-build-plan.md](./master-build-plan.md)

---

## Operating loop

```text
DISCOVER → OBSERVE → DETECT → UNDERSTAND → PRIORITIZE
        → SIMULATE → REMEDIATE → VERIFY → PROVE
        → COMPLIANCE / RISK UPDATED
```

Every module should reinforce this loop. AI may recommend; it must not claim an action succeeded unless the system executed and verified it.

---

## Already in product (do not rebuild)

Scanning (Nmap / Nuclei / web / optional ZAP), assets, vulns, incidents, remediations, playbooks, compliance + continuous control checks, evidence, reports, agents + WebSocket gateway (HTTP fallback), packaging, risk/attack-path/approval foundations, local AI Analyst.

---

## Twelve pillars (long horizon)

1. Security Operations  
2. Vulnerability Management  
3. Endpoint / XDR  
4. Network & Cloud  
5. Identity  
6. Application / Supply Chain  
7. Data Security  
8. Threat Intelligence  
9. Risk Management  
10. Compliance / GRC  
11. AI Security Operations  
12. Enterprise Platform  

---

## Priority order

### P0 — Platform first (customers / production)

| # | Work | Why |
|---|------|-----|
| 1 | Multi-tenant architecture (`organization_id` + server-side authz) | Hard requirement for SaaS |
| 2 | Complete agent security (certs, signed commands, rotation) | Trust boundary |
| 3 | Unified event model + durable pipeline | SOC / XDR foundation |
| 4 | EDR-class agent telemetry (beyond inventory snapshots) | Endpoint depth |
| 5 | Identity security baseline | Enterprise compliance |
| 6 | Cloud security connectors (CSPM start) | Commercial layer |
| 7 | Universal compliance control engine (test → evidence → gap → fix → verify) | Moat core |
| 8 | Evidence → Control → Risk → Remediation → Verification end-to-end | Differentiator loop |
| 9 | Immutable audit trail | Enterprise trust |
| 10 | Real-time dashboard (truthful KPIs, no fake scores) | Operator UX |
| 11 | Load / failure testing (measure before claiming scale) | Honesty |
| 12 | Production security hardening (SAST/deps/TLS/rate limits/signing) | Secure the product |

### P1 — After P0 greens

CSPM depth · SAST/SCA/SBOM · container/K8s · API security · data discovery · third-party risk · privacy · malware sandbox · SIEM correlation · AI Security module

### P2 — Moat (unique vs Wazuh clones)

Security Digital Twin · What-if Risk Simulator · Autonomous-but-approved remediation · Continuous compliance automation · Cross-framework control reuse · Evidence Truth Layer (OBSERVED / DERIVED / INFERRED / VERIFIED) · Business attack-path intelligence · AI Security Operations missions

---

## Compliance honesty

Framework catalogs must ship with requirements, controls, mappings, tests, evidence rules, versions, and sources.  
**Never claim certification from heuristic scores.** Scores support assessment; they do not prove compliance.

Canonical chain:

```text
FRAMEWORK → REQUIREMENT → CONTROL → TEST → DATA SOURCE
         → EVIDENCE → RESULT → GAP → REMEDIATION → VERIFICATION
```

---

## UX pattern (every screen)

```text
SUMMARY → FILTER → TABLE → DETAIL → WHY? → EVIDENCE
        → RECOMMENDATION → ACTION → VERIFICATION
```

Navigation grows toward Security / Investigation / Response / Risk / Compliance / Governance / Admin — without cloning Wazuh menu-for-menu.

---

## Next build slice (recommended)

Start with **P0.1 Multi-tenant architecture** end-to-end:

1. Stamp `org_id` on high-value tables — **done** for assets/vulns/risks/agents, scans, incidents, evidence, archives, gap remediations, intel watch, XDR events, compliance attestations/CMMC affirmations.  
2. Enforce membership server-side on list/get/mutate — **done** via `tenant_visibility_sql` / `row_visible_to_user` (never trust client `org_id` alone).  
3. Isolation tests fail closed — **done** (`tests/test_cross_tenant_isolation.py`).  
4. Gate row updated in [production-readiness.md](./production-readiness.md) (**partial→near-done**).  

**Intentional leftovers:** notifications remain recipient-scoped (personal inbox; `org_id` stamped only); lab `local` / `AUTH_ENABLED=false` visibility bypass.

Then **P0.2–P0.3** (agent certs / signed commands + unified durable event model) before expanding EDR/cloud/identity UI.

Skip empty menus. Deepen the loop that already ships.
