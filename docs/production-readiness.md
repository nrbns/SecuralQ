# SecuraIQ — Production readiness gate

Do **not** market this product as enterprise-ready or production SaaS until
every item below is **done**. Partial work is tracked honestly. Scores and
checkboxes here are based on the current codebase, not a wishlist.

Related: [master-build-plan.md](./master-build-plan.md) ·
[control-plane-roadmap.md](./control-plane-roadmap.md) ·
[priority-checklist.md](./priority-checklist.md) ·
[launch-readiness.md](./launch-readiness.md) ·
[security-baseline.md](./security-baseline.md) ·
[backup-dr.md](./backup-dr.md) ·
[realtime-v1.md](./realtime-v1.md)

**Agent Platform v1 scope:** multi-tenant native agents + persistent Agent
Gateway (WebSocket) + HTTP check-in fallback. Dashboard SSE stays. Do not
claim 5,000+ agents until a measured load run says so.

Status key: **done** · **partial** · **missing**

---

## Gate checklist

| Item | Status | Evidence / gap |
|------|--------|----------------|
| Tenant isolation | **partial→near-done** | Core product rows use `org_id` + `tenant_visibility_sql` / fail-closed get: assets/vulns/risks/chats/engagements/RAG, agents/commands/campaigns, **scans, incidents, evidence, archives, gap remediations, intel watch, XDR events, compliance attestations/CMMC affirmations**. **Intentional leftovers:** notifications stay recipient-scoped (personal inbox; `org_id` stamped only); lab `local` / `AUTH_ENABLED=false` still sees own/lab rows. |
| RBAC enforcement | **partial** | `require_perm` on enterprise/scans; **agent APIs** now use `agent.read` / `agent.write` / `agent.command` / `agent.approve`. Lab mode (`AUTH_ENABLED=false`) is still global admin. |
| Agent authentication | **done** | Bearer `agent_id.agent_key`; only SHA-256 of the key is used for compare; optional encrypted key copy enables HMAC on new enrollments. Revoke invalidates immediately. |
| Certificate rotation | **missing** | Next: per-agent mTLS or short-lived client certs. Token revoke + re-enroll is the current rotation path. |
| Signed commands | **partial→improved** | HMAC seal (`event_id` + `nonce` + `signature`) on delivery via `app/agent_security.py`. Optional Ed25519 via `AGENT_COMMAND_SIGNING_ALG`. **RT-17** mandatory seals when `AGENT_REQUIRE_COMMAND_SIGNATURE=true` (lab default off; production profile documents enabling it). Not mTLS. |
| Replay protection | **partial** | Optional `X-SecuraIQ-Ts` + `X-SecuraIQ-Nonce` (+ HMAC when `key_enc` exists). Enforced when `AGENT_REQUIRE_REPLAY_PROTECTION=true`. Command `expires_at` rejects stale queued work. |
| Event IDs + deduplication | **partial→improved** | REALTIME v1 contract (`app/event_schema.py`) + `normalize_event` on every `publish` stamps `event_id` / `event_type` / envelope; in-process ring buffer / LRU drops duplicates. RT-06 `securaiq_processed_events` skips processor side-effect retries. Streams `XADD` when `REDIS_URL` set — still not durable exactly-once across HA. Agent threat fingerprints already dedupe detections. |
| Event ordering | **partial→improved** | Normalized `sequence`/`seq` (millis) best-effort dual-write. Agent check-in contiguous ACK + gap fields / `sequence_gap` publish (RT-05). Redis Streams append order when `REDIS_URL` set; **still** no per-tenant sequence authority. |
| Persistent event queue | **partial→improved** | When `REDIS_URL` set: durable Streams (`REDIS_STREAM_KEY`) + **default** Streams SSE fan-out (`REALTIME_STREAMS_FANOUT=true`, per-process `securaiq-realtime-*`). Transitional pub/sub via `REALTIME_STREAMS_FANOUT=false`. Lab without Redis: in-process ring buffer only. Not HA / Sentinel. Jobs remain in-process SQLite. |
| Agent reconnect | **done** | Gateway replaces an existing socket for the same agent id; agent client retries with backoff and falls back to HTTP check-in. |
| Dashboard reconnect | **partial→improved** | SSE `EventSource` reconnects in `static/app.js` with Last-Event-ID catch-up. AUTH-on push events tenant-filtered (`sse_push_allowed_for_client`). Not a WebSocket dashboard gateway. |
| Offline agent buffering | **partial→improved** | `app/agent_offline_buffer.py` + check-in `sequence` / `buffered_events` ACK (`last_telemetry_seq`). Packaged agent **wired** (v1.1.1+): enqueue on failure, flush on check-in, `apply_server_ack`. Remaining gaps: contiguous ACK only (no ACK across holes); host telemetry re-apply from newest ACKed buffer (RT-05) — not HA durable. |
| Command acknowledgement | **done** | HTTP `POST /api/agents/commands/{id}/ack` and WebSocket `{type: ack}`. Status `sent` → `acked`; realtime also publishes `lifecycle` (`ACKNOWLEDGED` / `EXECUTING`). |
| Command timeout | **done** | `expires_at` on queue; un-acked `sent`/`acked` commands flip to `timeout` after `AGENT_COMMAND_ACK_TIMEOUT_SEC` (`lifecycle=TIMEOUT` / `EXPIRED`). |
| Patch verification | **done** | Execution `done` ≠ verified; `verification_status` + advisory refresh job; bus publishes `VERIFICATION` / `VERIFIED`. |
| Evidence generation | **partial** | Evidence store stamps `org_id` and filters with `tenant_visibility_sql`; confirm/list/get fail closed. Not every product claim auto-records evidence yet. |
| Immutable audit trail | **partial** | Append-only `audit_log` + SIEM forward option. SQLite rows are not WORM/object-lock immutable. |
| PostgreSQL backup/restore | **partial** | SQLite scripts in `scripts/backup.*`. Postgres path documented (`pg_dump`) in `docs/backup-dr.md` — operator-owned, not a product HA test. |
| Redis HA/recovery | **missing** | `REDIS_URL` enables Streams + default Streams fan-out (or transitional pub/sub via `REALTIME_STREAMS_FANOUT=false`). Soft chaos docs in `scripts/realtime_chaos_test.py --document-redis`. No Sentinel/Cluster failover test. |
| TLS | **partial** | Caddy/nginx scaffolding in `deploy/`; DNS and certs are operator steps. Agent `--insecure` is lab-only. |
| Rate limiting | **done** | `RateLimitMiddleware` on the API (`RATE_LIMIT_*`). |
| Secret management | **partial** | `.env` envelope encryption (`app/secrets_crypto.py`); agent raw key shown once. Optional Ed25519 key env vars (unused for live seal). No KMS/HSM. |
| Signed agent updates | **partial** | `agent_upgrade` carries `expected_sha256` of the server script. Not a code-signing cert / Authenticode / notarization. |
| Windows installer | **partial** | Packaged `SecuraIQ-Agent-*-windows-x64.exe` + Scheduled Task installer. No signed MSI / Authenticode yet. |
| Linux packages | **partial** | `*-linux-x64.tar.gz` (native binary on Linux/CI) + systemd `install.sh`. No `.deb` / `.rpm`. |
| macOS package | **partial** | Portable `.tar.gz`; real `.dmg` via `scripts/packaging/build_macos_dmg.sh` on macOS/CI. Ad-hoc/unsigned Gatekeeper notes in QUICKSTART. |
| Load test | **partial** | `scripts/realtime_load_test.py` ladder ≤1k + `scripts/load_test_agents.py` / `agent_gateway_load.py`. **Not** production proof; **do not claim 5k**. |
| Failure/recovery test | **partial** | Soft chaos: `scripts/realtime_chaos_test.py` (buffer replay). Redis kill is manual/documented only. |
| Security test | **partial** | Auth/tenancy/AI suites exist; agent isolation + replay + Ed25519 roundtrip tests. No full pentest report. |

---

## P0 modules (platform, not UI)

| Module | v1 target | Now |
|--------|-----------|-----|
| Multi-tenant architecture | Org-isolated agents + APIs | **partial→near-done** — high-value tables scoped; notifications remain per-recipient; lab `local` bypass intentional |
| Real Agent Gateway | Persistent WS + heartbeat + push commands | **done** (v1) — `WS /api/agents/ws`; HTTP check-in remains fallback |
| Event pipeline | Agent → detection → risk → dashboard | **partial→improved** — threat ingest + realtime bus + SSE; Streams + scoped processor hooks (notify/evidence/risk when `user_id` known) + RT-06 idempotency; RT-07 threat→incident when burst/keyword threshold met; RT-08 inventory/vuln→org risk (`risk.changed`) + high/crit derived evidence; RT-09 critical/incident → `compute_attack_paths` + `attack_path` summary; SSE tenant filter when AUTH on; **Streams fan-out default** when Redis set; rich twin/XDR correlation still incomplete |
| Agent installers | MSI / deb / rpm / pkg | **partial** — scripts only |
| Agent security | Device identity, certs, signed commands | **partial→improved** — bearer + replay/HMAC live; Ed25519 helpers optional (Task J); RT-17 opt-in mandatory seals (`AGENT_REQUIRE_COMMAND_SIGNATURE`, lab default off); certs/mTLS (RT-16) still next |
| Real-time dashboard | No polling-dependent UX | **partial** — SSE on publish; some panels still poll |
| Load testing | 100 → 1,000 → 5,000+ | **partial** — ladder harness ≤1k (`realtime_load_test.py`); **do not claim 5k** |

## P1 (after Agent Gateway + tenancy are green)

- Malware analysis (hash → static → behavioral → sandbox)
- SIEM/XDR correlation into unified incidents (connectors exist, live-tenant proof does not)
- AI orchestration that proposes **controlled** actions (approvals already exist)
- Compliance evidence from agent telemetry — **partial→improved** (RT-10/11): host firewall / Defender / SSH root live tests from agent `last_payload_json`, observed evidence + compliance SSE on check-in; firewall FAIL→remediation stub→re-check PASS. Not a compliance certification.
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
                     realtime_bus (+ v1 event contract)
                     (in-process + ring buffer; Redis pub/sub fan-out +
                      Streams XADD when REDIS_URL; event_processor scoped hooks)
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

