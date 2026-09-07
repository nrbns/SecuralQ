# SecuraIQ — Production readiness gate

Do **not** market this product as enterprise-ready or production SaaS until
every item below is **done**. Partial work is tracked honestly. Scores and
checkboxes here are based on the current codebase, not a wishlist.

Related: [priority-checklist.md](./priority-checklist.md) ·
[launch-readiness.md](./launch-readiness.md) ·
[security-baseline.md](./security-baseline.md) ·
[backup-dr.md](./backup-dr.md)

**Agent Platform v1 scope:** multi-tenant native agents + persistent Agent
Gateway (WebSocket) + HTTP check-in fallback. Dashboard SSE stays. Do not
claim 5,000+ agents until a measured load run says so.

Status key: **done** · **partial** · **missing**

---

## Gate checklist

| Item | Status | Evidence / gap |
|------|--------|----------------|
| Tenant isolation | **partial** | `org_id` + `tenant_visibility_sql` on assets/vulns/risks/chats/engagements/RAG; **agents, commands, patch campaigns** now stamped and scoped (`app/agents.py`). Reports/incidents/evidence still mostly user-scoped. |
| RBAC enforcement | **partial** | `require_perm` on enterprise/scans; **agent APIs** now use `agent.read` / `agent.write` / `agent.command` / `agent.approve`. Lab mode (`AUTH_ENABLED=false`) is still global admin. |
| Agent authentication | **done** | Bearer `agent_id.agent_key`; only SHA-256 of the key is used for compare; optional encrypted key copy enables HMAC on new enrollments. Revoke invalidates immediately. |
| Certificate rotation | **missing** | Next: per-agent mTLS or short-lived client certs. Token revoke + re-enroll is the current rotation path. |
| Signed commands | **partial** | HMAC seal (`event_id` + `nonce` + `signature`) on delivery via `app/agent_security.py`. Not Ed25519 / agent-side mandatory verify yet. |
| Replay protection | **partial** | Optional `X-SecuraIQ-Ts` + `X-SecuraIQ-Nonce` (+ HMAC when `key_enc` exists). Enforced when `AGENT_REQUIRE_REPLAY_PROTECTION=true`. Command `expires_at` rejects stale queued work. |
| Event IDs + deduplication | **partial** | `realtime_bus.publish` stamps `event_id` and drops in-process duplicates (LRU). Not a durable exactly-once log. Agent threat fingerprints already dedupe detections. |
| Event ordering | **partial** | Publish `seq` (millis) is best-effort. No per-tenant ordered log or vector clock. |
| Persistent event queue | **missing** | Redis pub/sub (optional) is fan-out, not a durable queue. Jobs remain in-process SQLite. |
| Agent reconnect | **done** | Gateway replaces an existing socket for the same agent id; agent client retries with backoff and falls back to HTTP check-in. |
| Dashboard reconnect | **partial** | SSE `EventSource` reconnects in `static/app.js`. Not a WebSocket dashboard gateway. |
| Offline agent buffering | **missing** | Queued commands wait on the server; the agent does not spool telemetry while disconnected. |
| Command acknowledgement | **done** | HTTP `POST /api/agents/commands/{id}/ack` and WebSocket `{type: ack}`. Status `sent` → `acked`. |
| Command timeout | **done** | `expires_at` on queue; un-acked `sent`/`acked` commands flip to `timeout` after `AGENT_COMMAND_ACK_TIMEOUT_SEC`. |
| Patch verification | **done** | Execution `done` ≠ verified; `verification_status` + advisory refresh job. |
| Evidence generation | **partial** | `app/services/evidence.py` records threat/command paths; not automatically org-scoped for all entity types. |
| Immutable audit trail | **partial** | Append-only `audit_log` + SIEM forward option. SQLite rows are not WORM/object-lock immutable. |
| PostgreSQL backup/restore | **partial** | SQLite scripts in `scripts/backup.*`. Postgres path documented (`pg_dump`) in `docs/backup-dr.md` — operator-owned, not a product HA test. |
| Redis HA/recovery | **missing** | `REDIS_URL` is optional SSE fan-out. No Sentinel/Cluster runbook or failover test. |
| TLS | **partial** | Caddy/nginx scaffolding in `deploy/`; DNS and certs are operator steps. Agent `--insecure` is lab-only. |
| Rate limiting | **done** | `RateLimitMiddleware` on the API (`RATE_LIMIT_*`). |
| Secret management | **partial** | `.env` envelope encryption (`app/secrets_crypto.py`); agent raw key shown once. No KMS/HSM. |
| Signed agent updates | **partial** | `agent_upgrade` carries `expected_sha256` of the server script. Not a code-signing cert / Authenticode / notarization. |
| Windows installer | **partial** | Packaged `SecuraIQ-Agent-*-windows-x64.exe` + Scheduled Task installer. No signed MSI / Authenticode yet. |
| Linux packages | **partial** | `*-linux-x64.tar.gz` (native binary on Linux/CI) + systemd `install.sh`. No `.deb` / `.rpm`. |
| macOS package | **partial** | Portable `.tar.gz`; real `.dmg` via `scripts/packaging/build_macos_dmg.sh` on macOS/CI. Ad-hoc/unsigned Gatekeeper notes in QUICKSTART. |
| Load test | **partial** | Synth harness: `scripts/agent_gateway_load.py` (default 100 HTTP check-ins). **Not** a 5k-agent proof. |
| Failure/recovery test | **partial** | Harness `--kill-reconnect` exercises reconnect/fallback. No chaos suite for Redis/API kill. |
| Security test | **partial** | Auth/tenancy/AI suites exist; new agent isolation + replay tests. No full pentest report. |

---

## P0 modules (platform, not UI)

| Module | v1 target | Now |
|--------|-----------|-----|
| Multi-tenant architecture | Org-isolated agents + APIs | **partial** — agents/commands/campaigns scoped; other tables still catching up |
| Real Agent Gateway | Persistent WS + heartbeat + push commands | **done** (v1) — `WS /api/agents/ws`; HTTP check-in remains fallback |
| Event pipeline | Agent → detection → risk → dashboard | **partial** — threat ingest + realtime bus + SSE; no durable queue |
| Agent installers | MSI / deb / rpm / pkg | **partial** — scripts only |
| Agent security | Device identity, certs, signed commands | **partial** — bearer + replay/HMAC; certs/signed commands next |
| Real-time dashboard | No polling-dependent UX | **partial** — SSE on publish; some panels still poll |
| Load testing | 100 → 1,000 → 5,000+ | **partial** — 100-agent synth only; **do not claim 5k** |

## P1 (after Agent Gateway + tenancy are green)

- Malware analysis (hash → static → behavioral → sandbox)
- SIEM/XDR correlation into unified incidents (connectors exist, live-tenant proof does not)
- AI orchestration that proposes **controlled** actions (approvals already exist)
- Compliance evidence from agent telemetry
- HA/DR (Postgres + Redis + workers)

## P2

- EDR-level process/file/network telemetry (beyond check-in snapshots + Sentinel heuristics)

---

## Architecture (keep dashboard SSE)

```
                 ┌──────────────────────┐
                 │   SecuraIQ Server    │
                 │ FastAPI · Auth/RBAC  │
                 │ Risk · Evidence      │
                 └──────────┬───────────┘
                            │
                     realtime_bus
                     (in-process; Redis optional fan-out)
                            │
             ┌──────────────┴──────────────┐
             │                             │
       Agent Gateway                 Dashboard SSE
       WebSocket /api/agents/ws      GET /api/realtime
             │                             │
        HTTP check-in fallback        SOC / admin browsers
```

---

## How to run the 100-agent synth (not 5k)

```bash
# server already running (python run.py)
python scripts/agent_gateway_load.py --server http://127.0.0.1:8080 --agents 100
# optional: WebSocket connects
python scripts/agent_gateway_load.py --server http://127.0.0.1:8080 --agents 100 --ws
```

Requires `AUTH_ENABLED` matching the server. With auth on, pass `--token` for a
user bearer (admin) used only to enroll synth agents.

---

## Windows lab: enroll + Agent Gateway

1. Start the server (`SecuraIQ.exe` or `python run.py`). Prefer `AUTH_ENABLED=true` for a realistic tenant.
2. UI: **Agents → Enroll**, or `POST /api/agents/enroll` with `X-SecuraIQ-Org`.
3. On the **lab Windows host you own**, prefer a built package from `dist/agent-packages/` (or Agents page download):

```powershell
# Preferred — packaged agent (no separate install_agent_*.ps1 download)
.\SecuraIQ-Agent-*-windows-x64.exe --server http://<server>:8080 --token <agent_id>.<agent_key>
# Or unzip *.zip and: .\install.ps1 -Server http://<server>:8080 -Token <agent_id>.<agent_key>

# Developer fallback only:
curl.exe -fsSL http://<server>:8080/api/agents/install-script -o securaiq_agent.py
python securaiq_agent.py --server http://<server>:8080 --token <agent_id>.<agent_key>
```

Authorized labs / owned systems only.

---

## Slice remaining (deferred — not blocking this build)

Honest leftovers after the Command Center / Compliance Sprint B / agent-package slice.
Do **not** treat these as shipped.

| Item | Why deferred |
|------|----------------|
| Task #144 Live test column | **Frozen** — do not change Frameworks control-table live-test UI |
| First-class Requirement entities | Sprint C+ (`docs/compliance-platform.md`) |
| Human attestation / verification workflow | Still thin; evidence queue + audit ZIP shipped |
| Signed MSI / `.deb` / `.rpm` / notarized `.dmg` | Windows exe + zip, Linux tar.gz, macOS tar.gz + CI dmg script only |
| Native Linux/macOS binaries from a Windows host | PyInstaller does not cross-compile; use CI matrix |
| 5k-agent capacity, durable event queue, mTLS certs | See gate checklist above — **do not claim** |
| Org-scoped evidence/incidents/reports | Agents/commands/campaigns scoped; other tables catching up |

