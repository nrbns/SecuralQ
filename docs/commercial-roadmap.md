# SecuraIQ — Continuous Security, Risk & Compliance Control Plane

**Positioning (do not market as a chatbot):**

> An **operating control plane** that discovers, detects, prioritizes, remediates, verifies, and proves — updating risk and compliance from real evidence. AI orchestrates; humans approve; agents execute; verification closes the loop.

**Not** “ChatGPT for cyber.” **Not** a Wazuh clone feature-for-feature.  
**Yes** Security → Risk → Compliance → Remediation → Verification → Evidence.

Canonical roadmap: [control-plane-roadmap.md](./control-plane-roadmap.md) · Ship gate: [production-readiness.md](./production-readiness.md)

```
Security Tools / Agents / Evidence / Scans
              │
              ▼
     SecuraIQ Control Plane
              │
              ▼
 Detection · Risk · Compliance engines
              │
              ▼
 Remediate → Approve → Verify → Evidence
```

---

## World-class bar (every release)

1. **Workflow-first** — each module completes a real security/compliance job end-to-end  
2. **Evidence-based AI** — ground answers in uploads, frameworks, and register data; humans override  
3. **Enterprise readiness** — orgs, RBAC, audit, integrations, reporting  
4. **Open integration** — connect existing tools (Jira, scanners, cloud, SIEM later)  
5. **Trust & transparency** — show evidence, confidence, and leave critical decisions to reviewers  

---

## Capability matrix (code-backed, Jul 2026)

| Module | Status | Notes |
|--------|--------|--------|
| Document AI / RAG | Shipped ★★★ | Chroma default; Qdrant optional profile |
| Gap Analysis | Shipped ★★★★ | ISO · NIST · CIS · SOC2 · PCI · ASVS |
| Risk Register | Shipped ★★★ | Scored CRUD + export + heat map |
| Vulnerability Mgmt | Shipped ★★★★ | CSV/JSON/XML + Trivy/Semgrep/Gitleaks/Grype/Checkov/Bandit/Sonar/SecuraIQ Web Scanner |
| Compliance hub | Shipped ★★★ | Frameworks + evidence + control center (+ ISO 27701 / HIPAA / GDPR subsets) |
| Asset Inventory | Shipped ★★★ | CRUD + Ask AI |
| Threat Intel | Shipped ★★★ | Watchlist + CISA KEV + NVD |
| Knowledge Graph | Shipped ★★★ | `/api/graph` entity correlation |
| Incident Mgmt | Shipped ★★★ | SOC desk + playbooks |
| Executive Dashboard | Shipped ★★★★ | Mission Control KPIs + heat map |
| Reports | Shipped ★★★★ | PDF · DOCX · XLSX · Markdown |
| Workflow Automation | Shipped ★★★ | Jira + outbound webhooks |
| Organizations / RBAC | Shipped ★★★ | Invite by username; MFA/SSO later |
| Billing / SaaS metering | Usage metering + plan model shipped (`app/billing.py`); live Stripe payment processing still requires a real Stripe account (`app/billing_stripe.py` is wired but inert without keys) | Month 3 |

Differentiator workflows to deepen next:

1. **AI Evidence Mapper** — upload → map controls → missing evidence  
2. **AI Risk Engine** — scans + docs → register + roadmap  
3. **AI Executive Reports** — one-click board / compliance / technical PDFs  
4. **Security Knowledge Graph** — assets ↔ risks ↔ vulns ↔ controls ↔ evidence ↔ incidents  

---

## Suggested product IA (implemented in UI)

```
Dashboard (Command Center)
AI Assistant
Security → Assets · Vulnerabilities · Threat Intel · Incidents · Playbooks · Campaigns
Compliance → Frameworks · Gap Analysis · Controls/Remediations · Evidence · Policies
Risk → Risk Register (matrix on Dashboard)
Development → Code Review · Secrets · Dependencies
Automation · Reports
Administration → Orgs · Settings · Account
```

---

## 90-day roadmap

### Month 1 — Trust the workflow (in progress / shipped core)

- [x] Dashboard / Command Center → **Mission Control**
- [x] Organizations + RBAC (basic)
- [x] AI Workspace (agents + tools + files + memory + tasks)
- [x] Gap Analysis + remediations
- [x] Reports (Markdown + PDF)
- [x] AI Work Queue (priority, owner, due, one-click task)
- [x] Org context header + enterprise top nav + collapsible sidebar
- [x] Evidence Mapper UX polish (control detail drawer)  
- [x] Framework control center (Evidence · Owner · Risk · Status)
- [x] Integrations catalog (Jira live; others planned)
- [x] Usage metering + plan model (`app/billing.py`, `GET /api/billing/usage`) — this line previously claimed a "billing placeholder" existed when no billing code was actually in the repo; corrected here

### Month 2 — Depth

- [x] Expand frameworks: SOC 2, PCI DSS, OWASP ASVS (subsets)  
- [x] Risk register + heat map  
- [x] Asset + vulnerability modules  
- [x] Knowledge-graph style entity links in UI (`/api/graph`)  
- [x] Scanner adapters: Trivy · Semgrep · Gitleaks · Grype · Checkov · Bandit · SonarQube · SecuraIQ Web Scanner (ZAP export)
- [x] Enterprise integrations catalog (`/api/integrations/catalog`)  
- [x] Intel feeds: CISA KEV sync + NVD CVE lookup  
- [x] Office reports: DOCX + XLSX (plus existing PDF/MD)  
- [x] Optional Qdrant compose profile  
- [x] Webhooks automation stub (n8n/Temporal bridges)  
- [x] Wazuh SIEM connector (manager JWT + optional Indexer; SOC sync)  
- [x] Network inventory connector (cookie session API; Assets sync)  
- [x] HardeningKitty + CIS Downloads workflow (Audit/Config + report import)  
- [ ] TheHive connector (Month 3+)  
- [ ] Stronger executive trend charts  

See also: [open-source-architecture.md](./open-source-architecture.md) · [enterprise-integrations.md](./enterprise-integrations.md) · [ai-router.md](./ai-router.md)

### Month 3 — Enterprise & GTM

- [ ] MFA (TOTP) + SSO (OIDC)  
- [ ] More integrations (ServiceNow, Slack/Teams, cloud posture read-only)  
- [~] Billing / subscription / usage — usage metering + plans shipped; live Stripe payment collection needs your Stripe account + pricing decisions
- [ ] Help center + monitoring + backups docs  

---

## SaaS readiness checklist

| Item | Status |
|------|--------|
| Authentication | Done (optional locally) |
| Multi-tenant orgs | Done (basic) |
| Billing | Usage metering done; live payment processing todo (needs a Stripe account) |
| Subscription management | Todo |
| Usage tracking | Todo |
| Notifications | Done — in-app feed + email (`app/notifications.py`) |
| Help center / docs | Done — FAQ + support triage process (`docs/help-center.md`), plus existing in-app manual |
| Backups | Done — `scripts/backup.sh`/`.ps1` + `scripts/restore.sh`, runbook in `docs/backup-dr.md` |
| Monitoring / error reporting | Done — `GET /api/metrics` (Prometheus format) + optional Sentry (`docs/monitoring.md`) |
| Audit logs | Done (basic) |
| API keys | Done |

---

## Editions

| Edition | Audience |
|---------|----------|
| Community | Individuals / students (local) |
| Professional | Consultants (Swana Techno default) |
| Business | SMB teams + collaboration |
| Enterprise | SSO, RBAC, SLA, annual |
| On-premises | Regulated / air-gapped |

**GTM:** build → use on Swana engagements → refine → convert clients to subscribers.

**Launch readiness:** see [launch-readiness.md](./launch-readiness.md) — current estimate **~5.5/10** (private alpha, not enterprise public). Target **9.5+** before public launch.

### Suggested stages

1. **Private Alpha** — internal dogfood (now)  
2. **Closed Beta** — design partners + MFA/monitoring  
3. **Public** — docs, billing, status, TLS/DR  
4. **Enterprise** — SSO/SCIM/SLA  

---

## Explicit non-goals (near term)

- Replacing SIEM / EDR / full GRC suites  
- Crimeware / unauthorized access workflows  
- Claiming SecuraIQ’s own SOC 2 / ISO certification before dogfooding  
- Marketing “guaranteed compliance” or “100% secure”  
- Shipping every AI agent before workflows are solid  

Legal draft pages (counsel required): `/legal/`
