# SecuraIQ commercial gap (honest)

The loop is right: **endpoint → event → control → evidence → risk/compliance → SSE → remediation → independent verification**.

Lab engineering is complete (`GET /api/launch/complete`). That is **not** a commercial enterprise/government product.

## 12 areas

| Area | In-repo now | Still ops / frozen |
|------|-------------|--------------------|
| Endpoint agent | Enroll, check-in, commands, Windows/Linux/macOS collectors, lab packages | Production mTLS/EV, signed store updates, M1/M2 live, canary rollout |
| Realtime | Redis Streams, XACK, XAUTOCLAIM, DLQ, SSE + Last-Event-ID | Multi-AZ, measured p95 SLA advertised as product |
| Evidence | Hash, freshness policies, STALE tick, legal hold, export package | Cloud Object Lock, 7-year WORM tenant |
| Controls | Live tests, deterministic last-results, **never PASS when agent offline** | Universal marketplace across cloud/K8s |
| Compliance | Framework catalog + mappings + CMMC readiness (not C3PAO) | C3PAO, live SPRS submit |
| Remediation | Approve → command → independent verify ≠ done | Kill@5k recovery |
| Identity | MFA + SCIM/OIDC/SAML facades + RBAC | Live IdP handshake |
| Multi-tenancy | Isolation tests + tenant stream dual-write | Exclusive Redis ACLs |
| UI | Exec/SOC/Compliance/IT/Auditor modes + truth chip + Current vs Target | Role-complete GRC workspaces |
| Scale | HTTP 1000 measured | 5k / 10k / 100k unpublished |
| Deployment | Slim cloud Docker + Helm scaffold + air-gap notes | Commercial installer stores |
| Security assurance | Lab signing scaffolds, SBOM in CI docs | External pentest, EV Authenticode |

## Shipped in this pass (lab)

- `GET /api/truth/indicators` — LIVE / STALE / UNKNOWN
- `GET /api/controls/catalog/{fw}/{id}/detail` — requirement, why, evidence, action, verify
- `GET|POST /api/compliance/profile` — Current vs Target % + **declared** NIST tiers (not a score)
- Offline agent: last PASS is shown as **UNKNOWN**, never PASS
- Live % applies the same overlay when agents are enrolled but offline (no-agent labs still roll last-results)
- Control Center / Compliance Center **Why / evidence** loads `GET /api/controls/why` (path `/detail` still works)
- Framework JSON is cached in-process so Why/evidence and catalog reads stay fast
- Control Center shows the LIVE/STALE/UNKNOWN chip from the same truth overlay
- Pulse + `GET /api/ops/measured` + launch-complete expose process-local `stage_latency` (null p95 when unmeasured — not an SLA)
- Agent availability for truth is a check-in count — not `list_agents` + latest-command N+1
- Why card splits **document** (catalog/policy, never PASS) vs **observation** (last test + freshness)

## Do not market as done

EV / notarize · cloud Object Lock · live IdP · C3PAO · 5k–100k HTTP · macOS M1/M2 live · digital twin · third-party pentest.

## Next (same loop, no new domain)

Keep P0-01 golden loop green. Measured HA/load (Postgres restore, Sentinel multi-AZ, HTTP 5k) stay ops. Do not invent EV / IdP / C3PAO / 100k.
