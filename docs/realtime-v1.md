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
       ┌──────┼──────────────────────────┐
       ▼      ▼                          ▼
  in-process  Redis pub/sub              Redis Streams XADD
  SSE queues  (transitional multi-       (durable SoT when
  + ring      worker SSE notify;         REDIS_URL set)
  buffer      default when Redis on)              │
       │      Skip when REALTIME_                 │
       │      STREAMS_FANOUT=true                 ▼
       │                              event_processor
       │                              group securaiq-workers
       │                              (+ RT-06 idempotency ledger)
       │                              │
       │         ┌────────────────────┘
       │         ▼  (default Streams fanout)
       │   securaiq-realtime-{pid}
       │   XREADGROUP → _fanout_local
       ▼
  GET /api/realtime  →  browser EventSource
  (AUTH on: tenant-filter push by user_id / org membership)
```

### Fan-out roles (RT-02)

| Mechanism | Role |
|-----------|------|
| **In-process** `_fanout_local` | Always — same worker / lab (no Redis) |
| **Pub/Sub** `securaiq:realtime` | **Transitional** multi-worker SSE notify when `REDIS_URL` set and `REALTIME_STREAMS_FANOUT=false` |
| **Streams** `XADD` | **Durable source of truth** when `REDIS_URL` set (always XADD; independent of fan-out mode) |
| **Streams fan-out** | **Default** when `REDIS_URL` set (`REALTIME_STREAMS_FANOUT=true`): skip pub/sub; each process runs group `securaiq-realtime-{pid}` and fans to local SSE after `XREADGROUP` |

Lab without Redis is unchanged. Redis HA/Sentinel remains a separate production gate item.
- **In-process bus** is the lab default and always works with `AUTH_ENABLED=false`.
  Ring buffer (`REALTIME_REPLAY_BUFFER`, default 2000) powers `replay_since` for
  Last-Event-ID catch-up without Redis. With Redis, `replay_since` also
  best-effort scans a limited recent Stream window (merged + deduped).
- **SSE tenant filter:** when `AUTH_ENABLED=true`, live + replay **push** events
  must match the client's `user_id` or org membership (`org_id` /
  `organization_id`). Unscoped pushes are delivered only when auth is off.
  Heartbeat snapshots without `push` are never filtered.
- **Event processor** (`app/event_processor.py`) — Task C: Streams consumer group
  `securaiq-workers` when Redis is set; lab path runs the same sync hooks from
  `publish` when Redis is absent. Handlers perform scoped notify / evidence / thin
  risk republish when `user_id` is known — no fake detections.
- **RT-06 idempotency:** `app/event_idempotency.py` table `securaiq_processed_events`
  skips processor side-effects for already-handled `event_id` (writers never gated).

---

## Task A — Unified event contract (done)

| Piece | Role |
|-------|------|
| `app/event_schema.py` | Field definitions, `EVENT_TYPE_REGISTRY` (incl. dotted advisory aliases), `validate_event` |
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

## Task B — Durable Event Bus / Redis Streams (done → RT-02 partial)

| Piece | Role |
|-------|------|
| `realtime_bus.publish` | `XADD` to Streams when `REDIS_URL` set; pub/sub only when `REALTIME_STREAMS_FANOUT=false` |
| In-process ring buffer | Last N events by `event_id` for lab `replay_since` |
| `replay_since(last_event_id, limit=200)` | Ring buffer + best-effort limited Stream scan when Redis available |
| `stream_status()` / `backend_status()` | Modes: `in_process` \| `redis_streams+pubsub` \| `redis_streams_fanout`; best-effort `stream_length` / `dlq_length` / `pending_count` / lag |
| Config | `REDIS_STREAM_KEY`, `REDIS_STREAM_MAXLEN`, `REDIS_STREAM_DLQ_KEY`, `REDIS_STREAM_MAX_DELIVERIES`, `REDIS_STREAM_CLAIM_IDLE_MS`, `REALTIME_REPLAY_BUFFER`, `REALTIME_STREAMS_FANOUT` (default **true** when Redis used; set `false` for transitional pub/sub) |

### Phase 1 durability (DLQ + reclaim)

When `REDIS_URL` is set, the `securaiq-workers` consumer:

| Behavior | Detail |
|----------|--------|
| Retry | On handler failure, message is **not** ACKed until `REDIS_STREAM_MAX_DELIVERIES` (default **5**) |
| DLQ | After max deliveries: `XADD` to `REDIS_STREAM_DLQ_KEY` (default `securaiq:events:dlq`) with original payload + error + `delivery_count` + `stream_id`, then `XACK` |
| Reclaim | Periodic `XAUTOCLAIM` for idle pending older than `REDIS_STREAM_CLAIM_IDLE_MS` (default **60000**); claimed messages re-run `process_event` |
| Lab | Without Redis, DLQ/reclaim are no-ops — `on_local_publish` path unchanged |

Monitoring keys on `stream_status()` / `processor_status()` / health `realtime_bus` are best-effort and **never raise**.

**Still partial for HA:** Streams fan-out is now the default multi-worker SSE path when `REDIS_URL` is set (`REALTIME_STREAMS_FANOUT=true`). Pub/sub remains available via `REALTIME_STREAMS_FANOUT=false`. No Sentinel/Cluster. Full HA catch-up API not claimed.

---

## Task C — Event processor (partial → improved)

| Piece | Role |
|-------|------|
| `app/event_processor.py` | Streams consumer + lab `on_local_publish` |
| Consumer group | `securaiq-workers` (one of many uvicorn workers) for **side-effects** |
| Phase 1 durability | DLQ (`REDIS_STREAM_DLQ_KEY`) after max deliveries; `XAUTOCLAIM` reclaim; status metrics |
| RT-06 idempotency | `app/event_idempotency.py` — `securaiq_processed_events`; skip duplicate handler runs |
| Handlers | Real side-effects when `user_id` is known (or recoverable from `agent_id`): notify + evidence + thin `evidence`/`risk` republish with `_from_processor=True` for `agent_threat`, `vuln`, `software.vulnerability.changed`, `remediation`, `agent_command`; inventory hooks (`inventory`, `software_inventory`, `software.inventory.updated`) recompute org risk; light evidence for `incident` / `gap`; RT-07 threat→incident on burst/keyword; RT-09 attack-path refresh on critical / incident |

Scope-gated only — no invented detections. Writers never fail if Redis/processor
errors. Per-tenant sequence authority and full detection→risk pipeline remain later.

---

## Task E — SSE Last-Event-ID + reconnect UX (done)

| Piece | Role |
|-------|------|
| `GET /api/realtime` | Reads `Last-Event-ID` / `?last_event_id=`; replays via `replay_since`; SSE frames include `id:` when push has `event_id` |
| Tenant filter | `sse_push_allowed_for_client` — AUTH on: require `user_id` or org match; unscoped only when AUTH off; heartbeats unfiltered |
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

## Task D — Offline agent telemetry buffer (wired → RT-04/05)

Packaged agent embeds a stdlib copy of the buffer and wires it into the check-in
loop (`scripts/securaiq_agent.py` ≥ 1.1.1). Server recovery path strengthened in RT-05.

| Piece | Role |
|-------|------|
| `app/agent_offline_buffer.py` | Server helper + shared schema; bounded JSON queue |
| Agent embed | Same schema in `scripts/securaiq_agent.py` (no `app.*` import when frozen) |
| Bounds | Default max **5000** events + soft **8 MiB** disk cap (oldest dropped) |
| Check-in fields | Optional `sequence`, `buffered_events`, `request_missing_from` on `POST /api/agents/checkin` |
| Response | `last_acked_seq`, `acked_sequences`, optional `missing_from` + `gap` |
| Agent row | `last_telemetry_seq` watermark (DB); not a full durable telemetry log |
| Compact buffer | Truncated snapshots still keep `firewall_status` / `defender_status` / `ssh_config` / `packages` when present |
| Disable | Agent CLI `--no-offline-buffer` |

**Agent wiring:**

- On check-in **failure**: enqueue compact snapshot (full if under ~100KB)
- On check-in **attempt**: merge `build_checkin_extension()` into payload
- On **success** (HTTP or WS `checkin_ok`): `apply_server_ack`; log if events drained

**Honest status:** lab scaffolding — contiguous ACK only (never across holes); packaged agent wired; not a durable HA log.

---

## RT-05 — Event ordering + gap recovery (partial → improved)

| Piece | Role |
|-------|------|
| Contiguous ACK | `process_buffered_events_on_server` ACKs only `last+1, last+2, …`; stops at first hole |
| Gap fields | Response `missing_from` + `gap.detected` / `expected_next` / `first_unacked_in_batch` |
| Dashboard | Check-in publishes `type=agent` `status=sequence_gap` with `user_id` / `org_id` when gap set |
| Re-apply | Newest ACKed buffered payload with host telemetry keys merged into effective check-in telemetry → `evaluate_agent_host_controls` (+ packages ingest) |
| Watermark | `last_telemetry_seq` stays honest — never advances across missing sequences |

**Still partial:** no per-tenant global sequence authority; not a durable HA telemetry log.

---

## RT-07 — Detection → Risk → Incident → Evidence → Dashboard (foundations)

**Ingest paths into `agent_threat`:**
- `POST /api/agents/threat` (Python Sentinel watcher)
- Check-in `file_integrity` modify/delete → `record_threat_detections` (Rust + any check-in-only agent; same titles/fingerprints as Sentinel FIM). `added` / truncated empty → no alert.
- Check-in `security_logs` → allowlisted Windows Event IDs (1102/4697/7045/4720/4732) and Linux auth substrings only — never open-ended heuristics.

When `agent_threat` is processed and `user_id` is known:

| Step | Behavior |
|------|----------|
| Notify + evidence | Unchanged for high/critical (inbox + observed evidence + thin `evidence` / `risk` republish) |
| Incident threshold | ≥2 high/critical for same `agent_id` in ~5 min **or** single **critical** with title keywords (`powershell`, `ransomware`, …) |
| Incident API | `app.ops.create_incident` / `update_incident` (source `event_processor:agent_threat`); no invented IOCs |
| Bus | `type=incident` with `_from_processor=True` |
| Idempotency | RT-06 `securaiq_processed_events` skips duplicate handler runs |

**Honest status:** foundations only — not full XDR correlation (see RT-09 for attack-path stub) or full inventory→vuln correlation depth (see RT-08).

---

## RT-08 — Inventory → Vulnerability → Risk → Dashboard (foundations)

When inventory / vuln events are processed and `user_id` is known:

| Step | Behavior |
|------|----------|
| Hook types | `inventory`, `software_inventory`, `software.inventory.updated`, `vuln`, `software.vulnerability.changed` |
| Org risk | Best-effort `compute_org_risk_score` → bus `type=risk` / `event_type=risk.changed` with `previous_score` when the in-process last score is known |
| Evidence | Derived vulnerability evidence **only** for severity critical/high (or `critical_installations` / high-sev change rows) — avoids spam; **never invents CVEs** |
| Inventory-only | Risk republish only — no fabricated findings |

**Honest status:** foundations — risk hint + gated evidence; not a full CMDB→CVE→dashboard pipeline.

---

## RT-09 — Threat → Attack Path → Risk → Incident (foundations)

| Step | Behavior |
|------|----------|
| Trigger | `agent_threat` **critical**, or RT-07 creates/updates an incident |
| Refresh | `app/services/attack_path_realtime.py` → real `compute_attack_paths` for the user's graph (resolves `asset_id` from event or agent row when present) |
| Bus | `type=attack_path` summarizing `path_count` / status (`recalculated` \| `compute_failed`) + thin `type=risk` hint; `_from_processor=True` |
| Honesty | Recalculates from existing graph data only — does **not** invent path edges or CVEs |

**Honest status:** foundations — best-effort refresh + summary event; not full twin/XDR path correlation.

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
| `scripts/realtime_acceptance_demo.py` | RT-10/11 lab acceptance: mock firewall disabled→evidence→enabled PASS (`--local` or `--server`) |

**Honest output on both:** `not production proof`. **Do not claim 5k support.**
Acceptance demo prints: **lab acceptance harness — not a 5k/HA proof**.

```bash
python scripts/realtime_load_test.py --server http://127.0.0.1:8080 --ladder --max-agents 500
python scripts/realtime_chaos_test.py --local-only
python scripts/realtime_chaos_test.py --document-redis
python scripts/realtime_acceptance_demo.py --local
python scripts/realtime_acceptance_demo.py --server http://127.0.0.1:8080 --token <admin_jwt>
```

---

## Task J — Crypto foundations (opt-in Ed25519 seal)

| Piece | Role |
|-------|------|
| `generate_ed25519_keypair` / `ed25519_sign` / `ed25519_verify` | Helpers in `app/agent_security.py` (`cryptography`) |
| Config / `.env.example` | `AGENT_COMMAND_SIGNING_ALG` = `hmac` (default) \| `ed25519` \| `both`; Ed25519 key env vars |
| `seal_command_for_delivery` | Always event_id + nonce + **issued_at/expires_at** (TTL from `AGENT_COMMAND_TTL_SEC`); HMAC and/or `signature_ed25519` + `signing_public_key` |
| `verify_sealed_command` | Server helper verifies per `signature_alg` **and rejects expired seals** |
| Agent | Verifies Ed25519 when present (`cryptography` if installed); HMAC when `SECURAIQ_AGENT_SIGNING_KEY` set; prefers pinned `SECURAIQ_AGENT_ED25519_PUBLIC_KEY` over TOFU embed; refuses expired seals |
| Request path | Agent sends `X-SecuraIQ-Ts` + `Nonce` + **`X-SecuraIQ-Sig`** (HMAC over `ts.nonce.sha256(body)`); check-in/ack/result verify against **raw** body |
| Fallback | `alg=ed25519` without private key → HMAC + warning (unless RT-17 require is on) |

Production direction: **Ed25519 + mTLS**. Default remains **HMAC** so labs without keys keep working.

**Production flag combo (lab hosts you own):**
```text
AGENT_REQUIRE_REPLAY_PROTECTION=true
AGENT_REQUIRE_COMMAND_SIGNATURE=true
AGENT_COMMAND_SIGNING_ALG=hmac   # or both + Ed25519 keys
SECURAIQ_AGENT_SIGNING_KEY=<long random>
# agent.env:
SECURAIQ_REQUIRE_COMMAND_VERIFY=1
SECURAIQ_AGENT_SIGNING_KEY=<same>
```

Still **not** mTLS / device certs (Phase 3 remaining).

---

## RT-17 — Mandatory signed commands (opt-in)

Lab-safe default: **`AGENT_REQUIRE_COMMAND_SIGNATURE=false`** /
``agent_require_command_signature: bool = False``.

| Piece | Role |
|-------|------|
| Config | `AGENT_REQUIRE_COMMAND_SIGNATURE` — production opt-in |
| `seal_command_for_delivery` | When require=True: valid seal mandatory (no silent unsigned); stamps `require_verify: true`; self-checks via `verify_sealed_command` |
| Gateway / check-in dispatch | Refuses to mark `sent` / deliver when require=True and seal missing/invalid; holds row `queued` |
| Self-check | `verify_sealed_command` before `sent` (blocks when require; debug-log only in lab) |
| Agent | Refuses execute if `SECURAIQ_REQUIRE_COMMAND_VERIFY=1` **or** command carries `require_verify: true` |

**Not mTLS (RT-16).** HMAC/Ed25519 seals only.

---

## RT-10 — ControlTestEngine from agent host telemetry (foundations)

Agent check-in payloads already include `firewall_status`, `defender_status`, and
`ssh_config`. RT-10 turns those into live control tests (not certification).

| Piece | Role |
|-------|------|
| `app/services/control_testing.py` | `host_firewall`, `host_defender`, `host_ssh_root` tests + `_CONTROL_TEST_MAP` bindings (CIS-12/10/4, NIST CSF PR.IR-01 / PR.PS-01, ISO A.8.20 / A.8.7 / A.8.9, 800-53 SC-7 / SI-3 / CM-6) |
| Provenance | `test_id`, `source=securaiq_agent`, `agent_id` / `asset_id`, observed snippet, `collected_at`, `confidence` |
| Evidence | `source=observed` on FAIL (idempotent fingerprint) and PASS transitions via `agent_host_control` entities |
| Check-in hook | `evaluate_agent_host_controls` after successful store in `app/agents.py` `checkin` — publishes `type=compliance` (+ thin `type=risk` on FAIL); never breaks check-in |
| Continuous Compliance | `list_live_control_failures` includes host fails when online agents report them |

**Honest status:** foundations — operating-effectiveness signals from enrolled agents only.

---

## RT-11 — FAIL → remediate → verify (minimal)

| Piece | Role |
|-------|------|
| Host control FAIL | `host_firewall` / `host_defender` / `host_ssh_root` open a POA&M / rem row; operator may request approved `enable_firewall` / `enable_defender` / `disable_ssh_root` (never auto-executed). |
| Re-check PASS | Next check-in with healthy telemetry → PASS evidence + compliance pass + risk-reduction hint; matching rem marked `done`; pending host commands flip `verification_status=verified`. |
| Approve path | Remediations / Agents → approve → agent result → wait for check-in verify |
| Lab bar | `python scripts/realtime_acceptance_demo.py --local` covers all three loops (synthetic payloads only) |

**Honest status:** lab closed-loop parity for firewall + Defender + SSH. Not owned-host proof; disk encryption remains observe→POA&M recommend-only (no auto rem command).

---

## Task order (A → J + RT-01…RT-20)

| Task | Scope | Status |
|------|--------|--------|
| **A** / **RT-01** | Unified versioned event contract + normalize on publish | **Done** |
| **B** / **RT-02** | Durable queue via **Redis Streams** (XADD, trim; default Streams fan-out; Phase 1 DLQ + reclaim) | **Partial→improved** (needs `REDIS_URL`; fan-out default; pub/sub opt-out; no Redis HA) |
| **C** / **RT-03** | Event processor (consumer group + lab hooks; scoped notify/evidence/risk) | **Partial→improved** |
| **D** / **RT-04** | Agent offline spool fully wired into packaged agents | **Partial→improved** (v1.1.1 wired; not HA durable) |
| **RT-05** | Event ordering + gap recovery (contiguous ACK, re-apply host telemetry, `sequence_gap`) | **Partial→improved** (foundations) |
| **RT-06** | Processor idempotency ledger (`securaiq_processed_events`) | **Partial→improved** (foundations) |
| **RT-07** | Detection → Risk → Incident → Evidence → Dashboard | **Partial→improved** (threat burst/keyword → incident) |
| **RT-08** | Inventory → Vulnerability → Risk → Dashboard | **Partial→improved** (inventory/vuln hooks → org risk + high/crit evidence) |
| **RT-09** | Threat → Attack Path → Risk → Incident | **Partial→improved** (critical/incident → `compute_attack_paths` + `attack_path` event) |
| **RT-10** | Agent telemetry → control test → compliance → evidence → risk → dashboard | **Partial→improved** (foundations) |
| **RT-11** | Control FAIL → rem → approve → agent → verify → PASS → evidence | **Partial→improved** (firewall + Defender + SSH lab loops; verify on host PASS) |
| **E** / **RT-12** | Central dashboard realtime (`RealtimeManager` + Last-Event-ID) | **Done→partial** (manager exists; not every panel) |
| **F** / **RT-13** | Remove polling from major dashboards | **Partial** (soft-poll skip while SSE connected) |
| **RT-14** | Connection state + stale-data indicators | **Partial→improved** (live badge states) |
| **RT-15** | Realtime timeline for every incident/remediation/control | **Planned** |
| **G** | Command lifecycle dual-write (`lifecycle` on bus) | **Partial** |
| **J** / **RT-16** | mTLS / certificate rotation | **Planned** (missing) |
| **J** / **RT-17** | Mandatory signed commands | **Partial→improved** (opt-in `AGENT_REQUIRE_COMMAND_SIGNATURE`; still not mTLS) |
| **RT-18** | Redis HA | **Planned** (missing) |
| **I** / **RT-19** | Automated chaos testing | **Partial** (soft harness; Redis kill manual) |
| **H** / **RT-20** | 5K measured load test | **Partial** (ladder ≤1k; **do not claim 5k**) |

**Later / not this slice:** per-tenant sequence authority, Redis Sentinel/Cluster HA,
exactly-once beyond SQLite ledger + LRU, ops SLOs, forced Ed25519-only cutover,
approved agent commands that enable firewall automatically.

**Out of scope for this track:** Task #144 Live Test UI (frozen).

---

## Honest production gate

- Event IDs + schema: **improved** (contract + normalize), still not durable exactly-once across HA.
- Event ordering: **partial→improved** — agent contiguous ACK + gap publish + host telemetry re-apply (RT-05); millis `sequence` still best-effort; no per-tenant log.
- Persistent event queue: **partial→improved** — Streams when `REDIS_URL` set; Phase 1 DLQ + pending reclaim; **Streams fan-out default** for multi-worker SSE (`REALTIME_STREAMS_FANOUT=true`); pub/sub via `=false`; lab remains in-process buffer only. Redis HA still missing.
- Event processor: **partial→improved** — consumer group + scoped hooks + RT-06 ledger + RT-07 threat→incident + RT-08 inventory/vuln→risk + RT-09 attack-path refresh; not full detection→risk / XDR correlation.
- SSE tenancy: **improved** — push filtered when AUTH on; heartbeats unfiltered.
- Offline agent buffer: **partial→improved** — packaged agent wired (v1.1.1); contiguous ACK + re-apply host keys from newest ACKed buffer; not HA durable.
- Command lifecycle: **partial** — bus dual-write; DB enums unchanged.
- Scale / chaos: **partial** — lab harnesses only; **not production proof**.
- Agent crypto: **partial→improved** — HMAC default; Ed25519 opt-in; RT-17 mandatory seals via `AGENT_REQUIRE_COMMAND_SIGNATURE` (lab default off; not mTLS).
- Compliance evidence from agent telemetry: **partial→improved** — RT-10/11 host firewall/defender/ssh live tests + observed evidence + SSE; **not a certification**.
