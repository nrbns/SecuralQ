# SecuraIQ — Help Center

FAQ and support triage. Complements the in-app user manual at `/manual/` (`static/manual/index.html`).

## Frequently asked questions

**The dashboard shows score 0 and an empty checklist — is something broken?**
No — this is "zero-start mode" by design (see [user-manual.md](./user-manual.md) and Mission Control). A fresh workspace has no fake demo data. Import a scan (`POST /api/vulnerabilities/import`) or add an asset to populate it.

**Chat says the backend is offline / `needs_model`.**
Check `GET /api/health` — it reports which backend is configured (`MODEL_BACKEND` in `.env`) and whether it's reachable. For Ollama, run `ollama pull <model>` first; for `openai_compat` (LM Studio), confirm the local server is running on the configured port.

**I imported a scan but no vulnerabilities showed up.**
Confirm the `tool` query param matches a supported adapter (Trivy, Semgrep, Gitleaks, Grype, Checkov, Bandit, SonarQube, SecuraIQ Web Scanner / ZAP export — see `app/scanner_adapters.py`) and that the file is valid JSON in that tool's native export format, not a summary/HTML report.

**MFA is required and I'm locked out of the API.**
That's `MFA_REQUIRED_FOR_ADMIN=true` working as intended (see `docs/beta-deploy.md` § MFA enforcement) — every endpoint except `/api/auth/status`, `/api/auth/logout`, and `/api/auth/mfa/*` will 403 until you enroll. If you're genuinely locked out (lost authenticator), an operator with filesystem access can unset `mfa_enabled` directly in `data/securaiq.db` for that user as a break-glass step, then re-enroll.

**Workspace reset isn't working / asks for a code I don't have.**
It's a two-step confirmation now (`app/approvals.py`) — call `POST /api/workspace/reset/request-code` first, check `GET /api/notifications` for the 6-digit code (expires in 5 minutes), then resubmit the reset with `confirm_code`.

**How do I get my data out if I stop using SecuraIQ?**
`GET /api/engagements/{id}/export`, `GET /api/reports/*`, and the CSV/PDF/DOCX/XLSX exports throughout the compliance and vuln modules. There's no single "export everything" button yet — see `docs/commercial-roadmap.md` for what's still planned.

**Something looks like a security bug, not just a support question.**
See `/legal/` for the (draft, pending counsel review) vulnerability disclosure policy. Do not file it as a normal GitHub issue if it involves a live exploit path.

## Support process (for whoever is triaging requests)

Since there's no ticketing system wired up yet, triage happens through whatever channel the team already uses (issue tracker, shared inbox, Slack — see `docs/enterprise-integrations.md` for the Slack connector shipped in this pass). Suggested severity handling until a real support portal exists:

| Severity | Example | Target response |
|---|---|---|
| P1 — data loss / security | Reset wiped wrong data, auth bypass found | Same day |
| P2 — broken workflow | Import fails, gap analysis errors | 1–2 business days |
| P3 — cosmetic / question | UI polish, "how do I..." | Best effort |

## What's still genuinely missing

A real support portal (ticket queue, SLA tracking, customer-facing status page, changelog) is **not** built — that's product/ops tooling, not something that makes sense to fake with placeholder code. When you're ready to stand one up, the Slack/Teams/ServiceNow connectors shipped in this pass (see `docs/launch-readiness.md`) are the natural place to route alerts into whatever ticketing tool you pick.
