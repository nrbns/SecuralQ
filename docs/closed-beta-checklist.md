# SecuraIQ — Closed beta checklist (30 days)

**Goal:** 5–10 design partners on hardened builds. **Freeze** new product features until week 4 feedback.

## Week 1 — Production hardening

- [x] Harden Compose (CORS, secrets, internal DB/Redis) — `docs/production-hardening.md`
- [x] Cross-tenant isolation tests — assets/vulns/risks/chats/engagements; scans/incidents/evidence/archives (P0.1)
- [x] Engagement tool-scope enforcement tests
- [x] TLS runbook — `docs/tls-deploy.md` (DNS/cert still operator-owned)
- [x] Backup → restore drill doc — `docs/backup-dr.md`
- [x] `MFA_REQUIRED_FOR_ADMIN=true` default in Compose saas + `.env.example`

## Week 2 — AI security

- [x] Guardrail regression suite (`tests/test_ai_security.py`)
- [x] Scope bypass / tool policy tests
- [x] Human approval consume-once test
- [x] RAG org filter + poison-in-prompt guardrail (`tests/test_rag_tenancy.py`)
- [ ] Manual red-team of Investigate prompts with partners

## Week 3 — Live integrations

- [x] Validation matrix + `connector_verify.py --matrix`
- [ ] Wazuh trial
- [ ] One XDR vendor trial (CrowdStrike **or** Defender **or** SentinelOne **or** Sophos)
- [ ] Cloud posture trial (one of AWS/Azure/GCP)
- [ ] Update `docs/connector-validation-matrix.md` only after success

## Week 4 — Commercial + beta

- [x] Commercial go-live checklist — `docs/commercial-golive.md`
- [x] Partner onboarding runbook — `docs/partner-onboarding.md`
- [x] Status notes + changelog — `docs/status.md`, `CHANGELOG.md`
- [ ] Stripe test-mode checkout → webhook → entitlement (needs Stripe account)
- [ ] Collect: “what do you use every week?” — feed Investigate workflow, not new nav

## Marketing language during beta

Allowed:

- Closed beta / design partners
- Connectors implemented; configurations being validated
- Heuristic compliance mapping (not certification)

Forbidden:

- Enterprise launch-ready / production SaaS
- Guaranteed compliance / certified
- Named XDR vendor “supported” without a verified trial row
