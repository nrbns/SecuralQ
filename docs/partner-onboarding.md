# SecuraIQ — Partner onboarding runbook

For closed-beta design partners (5–10). Keep scope tight.

## 1. Host prep

1. Follow [beta-deploy.md](./beta-deploy.md) + [production-hardening.md](./production-hardening.md)
2. TLS via [tls-deploy.md](./tls-deploy.md) (`deploy/Caddyfile` or nginx)
3. `AUTH_ENABLED=true`, `MFA_REQUIRED_FOR_ADMIN=true`, strong `BOOTSTRAP_ADMIN_PASSWORD`
4. Run backup drill once: [backup-dr.md](./backup-dr.md)

## 2. Create their workspace

1. Admin creates **Organization** for the partner
2. Create partner user (or invite) and add as org admin/member
3. Partner enrolls **MFA** before any tooling
4. Create an **Engagement** with structured `scope_json` (hosts/CIDRs they own)
5. Confirm tools refuse out-of-scope targets

## 3. First-week workflow (teach this, not every menu)

```text
Mission Control
 → Investigate top risks (Assistant)
 → Findings (triage / Ask AI)
 → Risk register
 → Report export (exec or technical)
```

Optional: one import (scanner JSON) or one Live scan on an owned lab target.

## 4. Support during beta

- Channel: email or shared Slack (fill in your address here)
- Severity: critical outage vs how-to vs feature ask
- Status notes: update [status.md](./status.md) when the beta host is degraded

## 5. Feedback questions (end of week 1)

1. What did you open every day?
2. What felt broken or slow?
3. Did Investigate → finding → fix feel complete?
4. Which integrations do you need next (only if unused weekly workflows are solid)?

Capture answers in the partner tracker — drive product from **usage**, not feature requests alone.
