# SecuraIQ — REALTIME v1

Unified realtime event pipeline for agents, product writes, and the dashboard
SSE feed (`GET /api/realtime`). **Do not rebuild** the Agent WebSocket gateway
or replace dashboard SSE in this track.

Related: [production-readiness.md](./production-readiness.md) ·
[agent-platform-v1.md](./agent-platform-v1.md)

---

## Architecture (current)

```
  Product writers / agents / jobs
              │
              ▼
     realtime_bus.publish()
              │
     normalize_event()  ← Task A
     app/event_schema.py + app/realtime_events.py
              │
       ┌──────┼──────────────┐
       ▼      ▼              ▼
  in-process  Redis pub/sub  Redis Streams XADD
  SSE queues  (multi-worker  (durable log when
  + ring      SSE fan-out)   REDIS_URL set)
  buffer                     │
       │                     ▼
       │              event_processor
       │              group securaiq-workers
       ▼
  GET /api/realtime  →  browser EventSource
```

- **In-process bus** is the lab default and always works with `AUTH_ENABLED=false`.
  Ring buffer (`REALTIME_REPLAY_BUFFER`, default 2000) powers `replay_since` for
  Last-Event-ID catch-up without Redis (SSE wiring = Task E).
- **Redis pub/sub** (`REDIS_URL`) fans live events across uvicorn workers for SSE.
- **Redis Streams** (`REDIS_STREAM_KEY`, default `securaiq:events`) durable `XADD`
  with approximate `REDIS_STREAM_MAXLEN` trim — Task B.
- **Event processor** (`app/event_processor.py`) — Task C: Streams consumer group
  `securaiq-workers` when Redis is set; lab path runs the same sync hooks from
  `publish` when Redis is absent. Handlers perform scoped notify / evidence / thin
  risk republish when `user_id` is known — no fake detections.

---

## Task A — Unified event contract (done)

| Piece | Role |
|-------|------|
| `app/event_schema.py` | Field definitions, `EVENT_TYPE_REGISTRY`, `validate_event` |
| `app/realtime_events.py` | `normalize_event` / `build_event` + existing job→SSE mapping |
| `app/realtime_bus.publish` | Normalizes every publish before local/Redis fan-out |

### Canonical envelope

| Field | Notes |
|-------|--------|
| `event_id` | Stable id; in-process LRU dedupe |
| `organization_id` / `org_id` | Dual-written for tenancy naming |
| `agent_id`, `asset_id` | Optional scope |
| `event_type` / `type` | Dual-written — **UI still reads `type`** |
| `event_version` | `1` |
| `sequence` / `seq` | Best-effort millis; dual-written |
| `generated_at`, `received_at` | ISO-8601 UTC |
| `severity`, `source`, `environment` | Optional; `environment` defaults to deployment mode |
| `data` | Domain payload mirror |
| `evidence_ids` | List (default `[]`) |

Domain fields (`job_id`, `status`, `id`, …) **remain at the top level** so existing
SSE consumers in `static/app.js` keep working; they are also copied into `data`.

### Example after normalize

```json
{
  "type": "vuln",
  "event_type": "vuln",
  "event_version": 1,
  "event_id": "a1b2c3…",
  "sequence": 1725000000123,
  "seq": 1725000000123,
  "ts": 1725000000.123,
  "generated_at": "2026-09-09T07:30:00.123Z",
  "received_at": "2026-09-09T07:30:00.123Z",
  "severity": "critical",
  "environment": "lab",
  "org_id": "org_x",
  "organization_id": "org_x",
  "id": "v1",
  "data": { "id": "v1" },
  "evidence_ids": []
}
```

---

## Task B — Durable Event Bus / Redis Streams (done)

| Piece | Role |
|-------|------|
| `realtime_bus.publish` | `XADD` to Streams when `REDIS_URL` set (+ keep pub/sub) |
| In-process ring buffer | Last N events by `event_id` for lab `replay_since` |
| `replay_since(last_event_id, limit=200)` | Catch-up helper (buffer only) |
| `stream_status()` / `backend_status()` | Honest mode: `in_process` vs `redis_streams+pubsub` |
| Config | `REDIS_STREAM_KEY`, `REDIS_STREAM_MAXLEN`, `REALTIME_REPLAY_BUFFER` |

**Still partial for HA:** no Sentinel/Cluster, no cross-node replay API on SSE yet.

---

## Task C — Event processor (partial → improved)

| Piece | Role |
|-------|------|
| `app/event_processor.py` | Streams consumer + lab `on_local_publish` |
| Consumer group | `securaiq-workers` (one of many uvicorn workers) |
| Handlers | Real side-effects when `user_id` is known (or recoverable from `agent_id`): notify + evidence + thin `evidence`/`risk` republish with `_from_processor=True` for `agent_threat`, `vuln`, `software.vulnerability.changed`, `remediation`, `agent_command`; light evidence for `incident` / `gap` |

Scope-gated only — no invented detections. Writers never fail if Redis/processor
errors. Per-tenant sequence authority and full detection→risk pipeline remain later.

---

## Task E — SSE Last-Event-ID + reconnect UX (done)

| Piece | Role |
|-------|------|
| `GET /api/realtime` | Reads `Last-Event-ID` / `?last_event_id=`; replays via `replay_since`; SSE frames include `id:` when push has `event_id` |
| `static/app.js` `RealtimeManager` | Connection states: connected / reconnecting / reconnected / failed / offline |
| Live badge | "Live", "Reconnecting…", "Offline — last known state" via `setLiveState` |
| Auth query token | Kept on reconnect URL; native EventSource Last-Event-ID preferred; query param for force-reopen / polyfill |

## Task F / G (dashboard) — Broader dashboard coverage (done)

| Piece | Role |
|-------|------|
| `REALTIME_LIVE_TYPES` | + evidence, compliance, threat, verification (plus existing agent/gap/hardening/…) |
| `syncLiveWorkspace` / workspace runners | Compliance Center + Agents / Evidence / Risk / Remediation / Campaigns / SOC |
| Soft polling | Skip 15s view poll + 60s Command Center poll while `__securaiqEsConnected` |

> **Lettering note:** Earlier drafts used G for dashboard coverage. The Agent Platform
> scaffolding track below reuses **G** for command lifecycle. Dashboard work stays
> documented here; the task table at the bottom is authoritative for A→J status.

---

## Task D — Offline agent telemetry buffer (wired)

Packaged agent embeds a stdlib copy of the buffer and wires it into the check-in
loop (`scripts/securaiq_agent.py` ≥ 1.1.1). Server recovery path unchanged.

| Piece | Role |
|-------|------|
| `app/agent_offline_buffer.py` | Server helper + shared schema; bounded JSON queue |
| Agent embed | Same schema in `scripts/securaiq_agent.py` (no `app.*` import when frozen) |
| Bounds | Default max **5000** events + soft **8 MiB** disk cap (oldest dropped) |
| Check-in fields | Optional `sequence`, `buffered_events`, `request_missing_from` on `POST /api/agents/checkin` |
| Response | `last_acked_seq`, `acked_sequences`, optional `missing_from` |
| Agent row | `last_telemetry_seq` watermark (DB); not a full durable telemetry log |
| Disable | Agent CLI `--no-offline-buffer` |

**Agent wiring:**

- On check-in **failure**: enqueue compact snapshot (full if under ~100KB)
- On check-in **attempt**: merge `build_checkin_extension()` into payload
- On **success** (HTTP or WS `checkin_ok`): `apply_server_ack`; log if events drained

**Honest status:** lab scaffolding — contiguous ACK only; not a durable HA log.

---

## Task G — Command lifecycle (partial)

DB `status` enum unchanged:
`pending_approval | queued | sent | acked | done | error | rejected | timeout`.

Richer **`lifecycle`** is dual-written on realtime `agent_command` publishes:

| DB `status` (+ notes) | `lifecycle` |
|------------------------|-------------|
| `pending_approval` | `PENDING` |
| `queued` | `APPROVED` |
| hand-off publish | `DISPATCHED` (transient) |
| `sent` | `DELIVERED` |
| `acked` | `ACKNOWLEDGED` → then `EXECUTING` |
| `done` | `COMPLETED` → `VERIFICATION` when verify pending |
| verify success | `VERIFIED` |
| `error` / verify fail | `FAILED` |
| `rejected` | `REJECTED` |
| ack/result timeout | `TIMEOUT` |
| expired before delivery | `EXPIRED` |

Helpers: `command_lifecycle()`, `_publish_agent_command()` in `app/agents.py`.
Verification loop still publishes (`record_command_verification`).

---

## Task H / I — Load + chaos scaffolding (partial)

| Script | Role |
|--------|------|
| `scripts/realtime_load_test.py` | Ladder 100→500→1k (`--ladder`); check-in p50/p95; optional `--sse-sample` |
| `scripts/realtime_chaos_test.py` | Soft disconnect → buffer → flush/ACK; `--document-redis` for manual Redis kill |

**Honest output on both:** `not production proof`. **Do not claim 5k support.**

```bash
python scripts/realtime_load_test.py --server http://127.0.0.1:8080 --ladder --max-agents 500
python scripts/realtime_chaos_test.py --local-only
python scripts/realtime_chaos_test.py --document-redis
```

---

## Task J — Crypto foundations (opt-in Ed25519 seal)

| Piece | Role |
|-------|------|
| `generate_ed25519_keypair` / `ed25519_sign` / `ed25519_verify` | Helpers in `app/agent_security.py` (`cryptography`) |
| Config / `.env.example` | `AGENT_COMMAND_SIGNING_ALG` = `hmac` (default) \| `ed25519` \| `both`; Ed25519 key env vars |
| `seal_command_for_delivery` | Always event_id + nonce; HMAC and/or `signature_ed25519` + `signing_public_key` |
| `verify_sealed_command` | Server helper verifies per `signature_alg` |
| Agent | Verifies Ed25519 when present (`cryptography` if installed); HMAC when `SECURAIQ_AGENT_SIGNING_KEY` set |
| Fallback | `alg=ed25519` without private key → HMAC + warning |

Production direction: **Ed25519 + mTLS**. Default remains **HMAC** so labs without keys keep working.

---

## Task order (A → J)

| Task | Scope | Status |
|------|--------|--------|
| **A** | Unified versioned event contract + normalize on publish | **Done** |
| **B** | Durable queue via **Redis Streams** (XADD, trim, in-process replay buffer) | **Done** (needs `REDIS_URL` for durability) |
| **C** | Event processor (consumer group + lab hooks; scoped notify/evidence/risk) | **Partial→improved** |
| **D** | Offline agent telemetry buffering | **Partial** (module + agent wired; not HA durable) |
| **E** | Dashboard reconnect + missed-event catch-up (Last-Event-ID → `replay_since`) | **Done** |
| **F** | Full dashboard realtime (LIVE_TYPES + soft-poll when SSE connected) | **Done** |
| **G** | Command lifecycle dual-write (`lifecycle` on bus) | **Partial** |
| **H** | Load ladder scaffolding (≤1k measured; not 5k) | **Partial** (harness only) |
| **I** | Soft chaos scaffolding (buffer replay; Redis kill manual) | **Partial** |
| **J** | Ed25519 opt-in seal (HMAC default) | **Partial** |

**Later / not this slice:** per-tenant sequence authority, Redis Sentinel/Cluster HA,
exactly-once consumers beyond LRU, ops SLOs, forced Ed25519-only cutover.

**Out of scope for this track:** Task #144 Live Test UI (frozen).

---

## Honest production gate

- Event IDs + schema: **improved** (contract + normalize), still not durable exactly-once.
- Event ordering: **still partial** (millis `sequence`; Streams exist but no per-tenant log).
- Persistent event queue: **partial** — Streams when `REDIS_URL` set; lab remains in-process buffer only.
- Event processor: **partial→improved** — consumer group + scoped notify/evidence/risk hooks; not full detection→risk pipeline.
- Offline agent buffer: **partial** — packaged agent wired; contiguous ACK only; not HA durable.
- Command lifecycle: **partial** — bus dual-write; DB enums unchanged.
- Scale / chaos: **partial** — lab harnesses only; **not production proof**.
- Agent crypto: **partial** — HMAC default; Ed25519 opt-in via `AGENT_COMMAND_SIGNING_ALG`.
