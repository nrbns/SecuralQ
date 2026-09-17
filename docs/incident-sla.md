# Incident response SLA (#244)

Public status: `/status.html` · API: `/api/status/public` · PSIRT: `/.well-known/security.txt`

| Severity | Ack target | Update cadence | Resolve target |
|----------|------------|----------------|----------------|
| SEV-1 (service down / data risk) | 15 min | 30 min | 4 hours |
| SEV-2 (major feature degraded) | 1 hour | 2 hours | 1 business day |
| SEV-3 (minor / workaround exists) | 1 business day | daily | 5 business days |
| SEV-4 (cosmetic / docs) | 3 business days | as needed | next release |

## Channels

1. Status page flips to `degraded` via `/api/status/public` checks failing
2. PSIRT: `SECURITY_CONTACT_EMAIL` (see security.txt)
3. Internal: audit_log + SIEM forwarders

Authorized / owned systems only — no third-party scanning during IR without written scope.
