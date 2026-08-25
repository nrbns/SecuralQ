# SecuraIQ — Enterprise Integrations

**Doctrine:** integrate mature open-source and commercial tools; SecuraIQ is the **AI orchestration layer** (findings → evidence → risk → compliance → reports), not a replacement for scanners, SIEMs, or full GRC.

```
Scanners / SIEM / Cloud / SCM
            │
            ▼
     Import · Webhooks · APIs
            │
            ▼
        SecuraIQ AI OS
   (router · agents · graph · GRC)
            │
            ▼
   Reports · Tasks · Jira · n8n
```

Full live catalog: `GET /api/integrations/catalog` (also **Administration → Integrations** in the UI).

Each catalog item includes a `ui_action` so Mission Control can **Connect** to the real path:

| `ui_action.kind` | Behavior |
|------------------|----------|
| `workspace` | Opens Vulns / Intel / Frameworks / Evidence / Orgs |
| `settings` | Opens Settings (AI Router or Jira) |
| `webhooks` | Scrolls to outbound webhook form (n8n / Slack bridge) |
| `planned` | Disabled — connector not shipped |
| `info` | Available in-build (no extra connector) |

---

## Recommended MVP (limited budget)

| Category | Tool | SecuraIQ status |
|----------|------|----------------|
| AI | Qwen + OpenRouter / Ollama | Shipped ([AI Router](./ai-router.md)) |
| SAST | Semgrep + **SonarQube / SonarCloud** (live sync + JSON import) | Shipped |
| Secrets | Gitleaks | **import** |
| Containers / SCA | Trivy + Grype | **import** |
| IaC | Checkov | **import** |
| DAST | SecuraIQ Web Scanner + Nuclei | built-in + engine |
| Threat intel | MITRE + NVD + CISA KEV + built-in providers | Shipped (`/api/intel/*`) |
| SIEM | Wazuh | Shipped (manager JWT + optional Indexer alert pull; SOC sync) |
| CMDB / inventory | Network inventory | Shipped (cookie session API; Assets sync) |
| Hardening | HardeningKitty + CIS Downloads | Shipped (Audit/Config import; HailMary blocked in API) |
| Automation | n8n | Webhooks shipped |
| Case mgmt | TheHive | Planned |
| Identity | Keycloak / Authentik | Planned (SSO Month 3) |
| DB | SQLite → PostgreSQL | SQLite shipped |
| Vectors | Qdrant | Optional compose profile |
| Storage | Local → MinIO | Local shipped |
| Backend | FastAPI | Shipped |
| Frontend | Mission Control (static SPA) | Shipped |

---

## Scanner import (shipped)

Drop JSON into **Vulnerabilities → Import** (or lab fixtures):

| Adapter | Typical export |
|---------|----------------|
| Trivy | `trivy image -f json` |
| Semgrep | `semgrep --json` |
| Gitleaks | `gitleaks detect -r` |
| Grype | `grype -o json` |
| Checkov | `checkov -o json` |
| Bandit | `bandit -f json` |
| SonarQube | Issues API / export JSON |
| SecuraIQ Web Scanner | Built-in JSON / ZAP-format report |

AI interprets findings and drafts remediations — it does **not** invent scan results.

---

## Network inventory (shipped)

Optional discovery appliance using a cookie session API (POST logon, then JSON collections) — the password is never placed in a URL. Synced hosts appear on the **Assets** page.

| Setting | Example |
|---------|---------|
| `OPENAUDIT_BASE_URL` | `http://192.168.56.10` |
| `OPENAUDIT_USER` / `OPENAUDIT_PASSWORD` | admin + lab password |
| `OPENAUDIT_API_PREFIX` | `/index.php` path on the appliance (default set in Settings) |

Windows helper: `.\scripts\use_openaudit.cmd -BaseUrl http://192.168.56.10 -User admin` (SecureString prompt).

Then **Settings → Network inventory** (Test connection) or **Assets → Sync inventory**.

API: `GET /api/openaudit/status` · `POST /api/openaudit/sync` · `GET /api/openaudit/devices` · `GET /api/openaudit/networks`

---

## HardeningKitty + CIS Downloads (shipped)

[HardeningKitty](https://github.com/scipag/HardeningKitty) audits Windows against CIS-style finding lists (registry, audit policy, etc.). Official CIS Benchmark PDFs and CIS-CAT come from [CIS Downloads](https://downloads.cisecurity.org/#/) (account required).

| Setting | Purpose |
|---------|---------|
| `HARDENINGKITTY_MODULE_PATH` | Folder containing `HardeningKitty.psm1` |
| `HARDENINGKITTY_LIST` | Optional default finding list CSV |

Windows helper: `.\scripts\use_hardeningkitty.cmd -Download`

Then **Settings → Windows hardening**, **Frameworks → Run HardeningKitty audit**, or import an Audit report CSV under **Vulnerabilities**.

SecuraIQ exposes **Audit** and **Config** only. **HailMary** (apply settings) is intentionally not available via the HTTP API — run it in PowerShell on an owned lab host after backup.

API: `GET /api/hardeningkitty/status` · `GET /api/hardeningkitty/lists` · `POST /api/hardeningkitty/audit` · `POST /api/hardeningkitty/import`

---

## Compliance frameworks

Shipped catalogs for gap analysis (current editions; lab subsets where noted):

| ID | Standard |
|----|----------|
| `iso27001` | ISO/IEC 27001:**2022** Annex A (full 93) |
| `iso27701` | ISO/IEC 27701:**2025** PIMS |
| `nist_csf` | NIST CSF **2.0** |
| `nist_800_53` | NIST SP 800-53 **Rev. 5** (priority subset) |
| `nist_800_171` | NIST SP 800-171 (CUI) |
| `cmmc_l2` | CMMC **2.0** Level 2 |
| `cis_controls` | CIS Controls **v8.1** (IG1) |
| `soc2` | SOC 2 TSC (2017 / 2022 points of focus) |
| `pci_dss` | PCI DSS **v4.0.1** |
| `hipaa` | HIPAA Security Rule §164 |
| `gdpr` | GDPR (EU) 2016/679 |
| `nis2` | NIS2 Directive (EU) 2022/2555 |
| `owasp_asvs` | OWASP ASVS **5.0** |
| `owasp_top10` | OWASP Top 10:**2025** |

Regenerate catalogs with `python scripts/refresh_frameworks.py`.

Planned depth: NIST SP 800-53 full mapping.

---

## Threat intel providers

Built-in Security + Anti-Malware provider catalog (integrated in Threat intel → Lookup):

| Endpoint | Purpose |
|----------|---------|
| `GET /api/intel/free/catalog` | Every listed API with live / keyed / catalog / skipped status |
| `GET /api/intel/lookup?q=` | Unified IOC/CVE lookup (GreyNoise, OTX, URLScan, PhishStats, NVD, …) |
| `GET /api/intel/greynoise/{ip}` | GreyNoise community |
| `GET /api/intel/msrc` | Microsoft security updates |
| `GET /api/intel/filterlists` | Blocklist directory |

Optional keys (Settings / `.env`): AbuseIPDB, VirusTotal, Shodan, OTX, URLScan, HIBP, GreyNoise, Pulsedive, MalwareBazaar, EmailRep, URLhaus.

Skipped on purpose: criminal background checks, Privacy.com banking, hash-cracking APIs.

---

## Microsoft Defender XDR advanced hunting

Authorized-tenant KQL hunting (blue-team / IR labs) — **live poll**, no templates:

| Endpoint | Purpose |
|----------|---------|
| `POST /api/xdr/hunting/run` | Run KQL (`query`, optional `timespan` / `ingest`) |
| `POST /api/xdr/hunting/ping` | Capability probe |
| Chat tool `defender_hunt` | Heavy tool — paste \`\`\`kql\`\`\` or say “run defender hunt” |

SOC **XDR** panel: enable **Live** to re-query your Defender tenant on an interval. Requires `DEFENDER_*` — no demo/synthetic rows.

**Auth:** same `DEFENDER_*` app registration. Prefer Microsoft Graph `ThreatHunting.Read.All` → [`runHuntingQuery`](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery). Legacy MTP [`advancedhunting/run`](https://learn.microsoft.com/en-us/defender-xdr/api-advanced-hunting) remains as fallback (`DEFENDER_HUNTING_API=auto|graph|legacy`).

---

## Platform roadmap (do not build in-house)

| Layer | Prefer |
|-------|--------|
| SIEM | Wazuh, Elastic, Security Onion |
| CMDB / inventory | Network inventory appliance |
| SOAR | n8n, Shuffle, StackStorm |
| IR | TheHive + Cortex |
| EDR telemetry | Wazuh / Velociraptor / Osquery |
| Cloud | Security Hub / Defender / SCC (read-only) |
| K8s | Kubescape, kube-bench |
| Identity | Keycloak, Authentik |
| Queues | NATS / RabbitMQ / Kafka (SaaS scale) |
| Observability | Prometheus, Grafana, Loki, OTel, Sentry |
| SCM | GitHub / GitLab / Azure DevOps / Bitbucket |
| Comms | Slack / Teams via webhooks |

Commercial tools (Nessus, Qualys, GitGuardian, Docker Scout, …) are **customer-bring-your-own-license** — SecuraIQ should ingest their exports, not reimplement them.

---

## AI agents (orchestration personas)

SOC Analyst · Threat Hunter · Malware Analyst · Compliance Officer · Risk Manager · Cloud Security Architect · Secure Code Reviewer · DevSecOps Engineer · Incident Commander · Executive Advisor

Routed via [AI Router](./ai-router.md) lanes + workspace modes.

---

## Enterprise features

| Feature | Status |
|---------|--------|
| Multi-tenancy / orgs | Shipped (basic) |
| RBAC | Shipped (basic) |
| Audit logs | Shipped |
| API keys | Shipped |
| Webhooks | Shipped (GitHub + GitLab) |
| SSO / MFA | Shipped (OIDC + TOTP) |
| SCIM | Partial (Users CRUD; no Groups) |
| STIX/TAXII | Shipped (ingest/export + TAXII poll) |
| Realtime bus | Partial (in-process; Redis when `REDIS_URL` set) |
| Report scheduling | Planned |
| White-labeling | Planned |

---

## Explicit non-goals

- Replacing Wazuh / Elastic / full GRC
- Shipping every connector before MVP workflows are solid
- Crimeware or unauthorized scanning workflows
