# SecuraIQ — Priority checklist (feature freeze)

Map of the ordered harden+validate plan against the repo. **Do not add scanners/agents/frameworks.**

**Engineering: complete.** Operator leftovers (TLS DNS, Stripe account, live IdP) stay ops.

## Edition split

| Edition | Database | Auth |
|---------|----------|------|
| Community / lab | SQLite OK | optional |
| SecuraIQ Cloud / production | **PostgreSQL only** (`DATABASE_URL`) | required + MFA for admin |

## P0 — before public internet

| # | Item | Status |
|---|------|--------|
| 1 | Production Docker (no default passwords, no CORS `*`, DB/Redis internal, named network) | **Done** |
| 1b | Reverse proxy + TLS | **Done** scaffolding (`deploy/`, Caddy profile `proxy`) — operator owns DNS/certs |
| 1c | Secure cookies + HSTS / security headers | **Done** (`COOKIE_SECURE`, `FORCE_HTTPS_HEADERS`) |
| 2 | Postgres SaaS-only + Alembic | **Done** |
| 3 | Tenant isolation tests | **Done** (`test_tenancy_rbac.py`, `test_cross_tenant_isolation.py`) |
| 4 | Auth matrix (login/logout/session/MFA/API keys/RBAC) | **Done** (tests); live OIDC IdP E2E remains ops |
| 5 | AI security (injection / RAG / scope) | **Done** (`tests/test_ai_security.py`, `test_rag_tenancy.py`) |
| 6 | AI tool policy / scope / audit | **Done** (engagement scope + tool_policy tests) |
| 7 | Scope enforcement before ops | **Done** (`test_engagement_scope.py`) |
| 8 | Secrets (no defaults, `.env` not committed) | **Done** lab (rotate_secrets dry-run + `.gitignore`); KMS cloud ops |

## P1 — commercial strength

| # | Item | Status |
|---|------|--------|
| 9–12 | Canonical assets / normalizer / finding lifecycle / deterministic risk | **Done** (risk score + finding lifecycle) |
| 13 | AI Investigation flagship | **Done** `POST /api/ai/investigate` |
| 14–15 | RAG tenancy + knowledge graph | **Done** (RAG filter + graph depth) |
| 16–18 | Integration E2E / reports / Stripe lifecycle | **Lab** connectors + reports; Stripe account checkout **ops** |

## P2 / P3

Onboarding, MSSP, observability (`GET /api/admin/health`) — **lab**. See `docs/closed-beta-checklist.md`.

## Short “20 things”

```text
01–08  Docker/Postgres/isolation/RBAC/MFA/AI scope  → done (TLS DNS operator)
09–15  Assets/risk/investigation/RAG                 → done
16–20  Connectors/Stripe live account/e2e            → lab + operator
```

## Verify

```bash
python scripts/complete_all_checklists.py
```
