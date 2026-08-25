# SecuraIQ — Open-Source-First Architecture

**Doctrine:** use mature open source wherever it is production-ready; use commercial APIs only when they clearly add value. SecuraIQ is an **AI orchestration platform**, not a replacement for scanners, SIEMs, or full GRC suites.

```
Security Tools → AI Orchestrator → Knowledge Graph → Risk Engine
                                              → Compliance Engine
                                              → Executive Dashboard
```

See the full tool catalog and MVP matrix: [enterprise-integrations.md](./enterprise-integrations.md).

---

## Design principles

1. **Local-first AI** — Ollama / LM Studio / Hermes; cloud models optional via the [AI Router](./ai-router.md).
2. **Import, don’t reinvent** — Trivy, Semgrep, Gitleaks, Grype, Checkov, SonarQube, SecuraIQ Web Scanner (ZAP export), etc. feed the register.
3. **Evidence-grounded answers** — RAG + structured modules; humans approve. Prefer trusted frameworks over “uncensored” models.
4. **SQLite → Postgres** — Community/on-prem stays SQLite; SaaS multi-tenant uses Postgres + Redis.
5. **Compose profiles** — core app alone; add Qdrant / Redis when needed.

---

## Recommended stack (adopted / planned)

| Layer | Choice | Status in SecuraIQ |
|-------|--------|-------------------|
| Chat LLMs | Qwen / Llama / Mistral / DeepSeek via Ollama; OpenAI / OpenRouter / Groq / Together / Fireworks | Shipped (multi-backend + [router](./ai-router.md)) |
| Code models | Qwen Coder / DeepSeek Coder / Code Llama | Via Ollama + OpenRouter code lane |
| Embeddings | MiniLM default; BGE-M3 optional | Shipped + config |
| Vector store | Chroma default; **Qdrant** optional profile | Shipped + compose profile |
| App DB | SQLite (local); Postgres (SaaS later) | SQLite shipped |
| Cache | Redis (SaaS later) | Planned |
| Object storage | Local `data/`; MinIO later | Local shipped |
| Auth | Built-in; Keycloak / Authentik for SSO | Built-in; SSO Month 3 |
| Frontend | FastAPI static Mission Control | Shipped |
| Intel | CISA KEV + NVD (ToS-aware) | Shipped sync |
| Scanners | Trivy · Semgrep · Gitleaks · Grype · Checkov · Bandit · SonarQube · SecuraIQ Web Scanner | Shipped adapters |
| Compliance | ISO 27001:2022/27701:2025, NIST CSF 2.0, 800-53/171, CMMC L2, CIS v8.1, SOC 2, PCI 4.0.1, HIPAA, GDPR, NIS2, ASVS 5.0, Top 10:2025 | Shipped catalogs |
| Reports | PDF + Markdown + **DOCX/XLSX** | Shipped |
| Automation | Webhooks + Jira; n8n/Temporal | Webhooks + Jira shipped |
| Observability | Prometheus/Grafana later | Planned |
| Deploy | Docker Compose; K8s later | Compose shipped |

---

## AI agents (workspace roles)

SOC Analyst · Threat Hunter · Malware Analyst · Compliance Officer · Risk Manager · Secure Code Reviewer · Cloud Security Architect · DevSecOps · Incident Commander · Executive Advisor

---

## Unique capability

Correlate **assets ↔ vulnerabilities ↔ risks ↔ controls ↔ evidence ↔ incidents** in one knowledge graph, then prioritize remediation and generate executive/technical/compliance reports with AI explanations grounded in that graph.

---

## Explicit non-goals

- Replacing SIEM / EDR / full GRC
- Crimeware / unauthorized access workflows
- Forcing customers off their existing security stack
