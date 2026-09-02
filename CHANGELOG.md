# Changelog

## 2026-09-02 — Native agents, delete completeness, packaging & docs

### Native monitoring
- Native SecuraIQ agent: enroll/checkin/threat-report API, real downloadable
  agent script, persistent-service installers (systemd/launchd/Windows
  Scheduled Task)
- SecuraIQ Sentinel: real-time detection fusing signature matching,
  behavioral heuristics, ransomware indicators, and file-integrity
  monitoring (persisted baseline, real add/modify/delete diffs)
- Fixed the SSE burst-coalescing bug that silently dropped same-tick
  realtime pushes (agent/threat/notification events) from the UI

### Completeness & security
- Delete actions for findings, remediations, and gap assessments (the
  last cascades to its generated remediation tasks)
- Web URL Scan now rejects loopback/private/link-local/internal-suffix
  targets — closes an SSRF path and keeps the tool scoped to public web
  apps (network/VAPT scan remains the tool for internal hosts)
- Fixed a NameError crash in the LAN inventory audit background job
  (missing `json` import — no test had covered that path)

### Packaging
- SecuraIQ.exe is now a true single-file build (was onedir); the
  packaging spec also bundles the agent install scripts, which had been
  missing (that feature 404'd in a built exe even though it worked from
  source)

### Docs
- User manual (docs/user-manual.md and the in-app /manual/ page)
  rewritten to cover native agents/Sentinel, the Web URL Scan
  restriction, and delete actions

## 2026-08-16 — Closed-beta hardening

### Security & tenancy
- Org RBAC / tenancy foundation; engagement `scope_json` tool policy
- Cross-tenant isolation tests (assets, findings, risks, chats)
- AI security suite (guardrails, scope bypass, approval consume-once)
- Docker Compose hardened: required bootstrap password, restrictive CORS, Postgres/Redis not publicly published; `saas` / `debug-ports` profiles

### Data & AI
- Postgres dual-backend selection (`DATABASE_URL`); SQLite remains lab default
- RAG queries can scope to `org_id` + global knowledge (tenant filter)

### Docs
- Production hardening, closed-beta checklist, connector validation matrix
- Partner onboarding, backup/restore drill, TLS deploy, commercial go-live, status notes
- Feature freeze: validate/harden/commercialize — no new scanners/agents/frameworks this cycle

### UI
- Assistant composer compact dock; vulnerability management layout polish; topbar/tabs fixes
