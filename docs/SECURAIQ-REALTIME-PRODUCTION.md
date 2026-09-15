# SecuraIQ Realtime Production — Implementation Map

**Purpose.** Make the **existing** product flow genuinely realtime end-to-end. Do **not** add a second WebSocket/SSE/event architecture.

**Rule:** Extend Redis Streams → processors → evidence/controls/risk → `/api/realtime` SSE → dashboard. Map work to files that already exist.

**Related:** [realtime-v1.md](./realtime-v1.md) · [realtime-controls-evidence-spec.md](./realtime-controls-evidence-spec.md) · [control-config-engine.md](./control-config-engine.md) · [master-build-plan.md](./master-build-plan.md) · [SECURAIQ-PRODUCTION-BUILD.md](./SECURAIQ-PRODUCTION-BUILD.md) · [tls-deploy.md](./tls-deploy.md)

**Honesty:** Phase 1 bus is near-done in lab. Control/compliance/evidence UI and commercial agent security are **partial**. Signed MSI/deb commercial release waits on the security chain below—not on more scanners.

---

## 0. Architectural decision (non-negotiable)

```text
Windows/Linux/macOS Agent
          │  HTTPS + WebSocket (existing gateway)
          ▼
     Agent Gateway          app/agent_gateway.py
          │                 POST /api/agents/checkin
          ▼                 WS /api/agents/ws · POST /api/agents/gateway/wait
    Redis Streams           app/realtime_bus.py  (or in-process bus without REDIS_URL)
          │
    ┌─────┼──────────────┐
    ▼     ▼              ▼
 Events Controls       Risk     app/event_processor.py
    │     │              │      app/services/control_testing.py
    └─────┼──────────────┘
          ▼
       Evidence             app/services/evidence.py
          ▼
      Compliance / Risk     gap + risk snapshots (thin realtime today)
          ▼
      Remediation           enterprise rem + agent commands (approval-gated)
          ▼
     Verification           next check-in / control re-eval
          ▼
     Redis Stream fan-out
          ▼
       SSE                  GET /api/realtime  (app/main.py)
          ▼
      Dashboard             static/app.js RealtimeManager + REALTIME_LIVE_TYPES
```

**Forbidden:** parallel “Realtime 2.0” bus, duplicate SSE endpoints, or dashboard clients that ignore `Last-Event-ID` / Streams replay.

---

## 1. What is already realtime (do not rebuild)

| Capability | Where it lives |
|------------|----------------|
| Unified event envelope + registry | `app/event_schema.py`, `app/realtime_events.py` |
| Publish / local SSE wake | `app/realtime_bus.publish` |
| Redis Streams XADD, consumer group, ACK/retry | `app/realtime_bus.py`, `app/event_processor.py` |
| DLQ + admin list/replay/purge | `GET/POST /api/admin/realtime/dlq*` in `app/main.py` |
| XAUTOCLAIM / reclaim | Streams consumer loop in `app/event_processor.py` |
| Stream metrics + health | `stream_monitor_snapshot`, `/api/health` → `realtime_bus` |
| Default Streams fan-out to SSE | `REALTIME_STREAMS_FANOUT` (`app/config.py`) |
| Per-agent ordering + offline buffer | agent offline queue in `scripts/securaiq_agent.py`; gateway wait |
| Dedup by `event_id` | bus + processor |
| SSE feed + Last-Event-ID replay | `GET /api/realtime` in `app/main.py` |
| Frontend connection manager (partial) | `window.RealtimeManager` in `static/app.js` |
| Soft-poll skip when SSE live | Mission Control / workspace timers in `static/app.js`, `static/workspace.js` |
| Lab HA stub | `docker compose --profile redis-ha`, `deploy/redis/sentinel.conf` |
| Acceptance harness | `scripts/realtime_acceptance_demo.py` (`--local` / `--server`) |

**Still Phase 1 claim blockers (ops proof, not new design):** measured Redis Sentinel failover + multi-worker production proof (`scripts/realtime_multiworker_smoke.py`).

---

## 2. Closed-loop product contract (acceptance)

One endpoint / one agent identity drives **one timeline**—no manual “Run Scan” for host-control truth.

### 2.1 Enroll → inventory → dashboard (MSI path)

```text
MSI / package installed
  → enroll (POST /api/agents/enroll or enroll-by-token)
  → agent.connected / agent check-in
  → inventory / software.inventory.updated
  → software.* / software.vulnerability.changed (advisory match)
  → control.evaluated (host_* tests on check-in)
  → evidence.created
  → compliance / risk.changed
  → SSE → dashboard panels update
```

**Primary producers today**

| Step | Code |
|------|------|
| Check-in + telemetry | `app/agents.checkin`, `POST /api/agents/checkin` |
| Host controls | `evaluate_agent_host_controls` in `app/services/control_testing.py` |
| Package ingest + diffs | `app/software/sources/securaiq_agent.py` (`publish_package_change_events`) |
| Vuln bridge | advisory refresh on check-in (Phase 4 partial) |
| Bus publish | `app.realtime_bus.publish` from agents / control_testing / software |

### 2.2 Firewall closed loop (immediate priority)

Build plan priority: *prove firewall closed loop (`realtime_acceptance_demo.py`) before Phase 22+.*

```text
firewall_status.enabled=false on check-in
  → host_firewall FAIL
  → evidence + control.failed
  → remediation.recommended (auto_execute=false)
  → risk.changed (thin)
  → operator: POST /api/agents/{id}/commands/enable-firewall
  → approve (pending_approval → queued)
  → gateway delivers enable_firewall
  → agent executes (scripts/securaiq_agent.py / Rust parity)
  → next check-in → host_firewall PASS
  → new evidence + control.passed
  → rem closed + risk/compliance update
  → SSE dashboard
```

| Piece | Status | File / API |
|-------|--------|------------|
| Detect FAIL/PASS | **Live** | `evaluate_host_firewall_payload` |
| Evidence + SSE | **Live** | `record_evidence` + `control.failed`/`passed` publishes |
| Rem recommend | **Live** | `_ensure_host_firewall_remediation` |
| Request command | **Live** | `request_enable_firewall_command`, `POST .../commands/enable-firewall` |
| Approval gate | **Live** | `app/agents` command lifecycle |
| Agent action | **Live** | allowlisted `enable_firewall` |
| Verify on check-in | **Live** | PASS closes rem |
| UI panel refresh | **Partial** | types in `REALTIME_LIVE_TYPES`; not every panel is subscriber-driven |
| Affected-controls-only recompute | **Gap** | still curated / check-in scoped |
| Append-only `control_results` history | **Gap** | called out in production build doc |

**Harness (must stay green):**

```bash
python scripts/realtime_acceptance_demo.py --local
# optional against running server:
python scripts/realtime_acceptance_demo.py --server http://127.0.0.1:8080
```

Same pattern for Defender / SSH root (lab parity); disk encryption remains observe→test→POA&M heavier.

---

## 3. Event types — registry vs dashboard wiring

Canonical registry: `app/event_schema.py` → `EVENT_TYPE_REGISTRY`.

Frontend live set: `REALTIME_LIVE_TYPES` in `static/app.js` (partial overlap).

### Target product events (map or dual-write; do not invent a second bus)

| Desired product event | Existing / nearest today | Action |
|-----------------------|--------------------------|--------|
| `agent.online` / `agent.offline` | `agent`, `agent.connected`, `agent.disconnected`, `agent.health_changed` | Normalize aliases in publish + UI |
| `asset.updated` | `asset`, inventory handlers | Ensure asset upsert publishes |
| `software.updated` | `software.updated` / installed / removed | Already on package diffs |
| `vulnerability.created` | `vuln`, `software.vulnerability.changed`, `threat.created` | Dual-write dotted where missing |
| `control.pass` / `control.fail` | `control.passed` / `control.failed` | Keep dotted names; UI already lists them |
| `evidence.created` | `evidence`, `evidence.created` | Prefer dotted on write |
| `compliance.updated` | `compliance`, `compliance.control_*` | Emit on host-control + gap score changes |
| `risk.updated` | `risk`, `risk.changed` | Processor already emits `risk.changed` |
| `finding.created` | `incident.created`, `agent_threat`, gap | Alias carefully—no duplicate incidents |
| `remediation.created` | `remediation`, `remediation.recommended` | Already |
| `command.pending` … `command.completed` | `agent_command` + lifecycle field | Expand lifecycle → dotted types or `also[]` |
| `verification.pass` / `fail` | `verification`, `verification.completed` | Emit from check-in verify path |
| `license.updated` | license APIs (weak bus today) | Publish on validate/issue/revoke |
| `agent.update.available` | agent_updates publish | Publish when release row created |

**Processor handlers today** (`app/event_processor.py` `HANDLERS`): threats, vuln, inventory, remediation/command, incident/gap light evidence, config drift, `control.failed`. Extend handlers rather than new consumers.

---

## 4. Frontend: finish `RealtimeManager` (extend, don’t replace)

Already present (light): `connect` state, `lastEventId`, reconnect, `route()` → `securaiq:realtime:routed`.

### DoD for RealtimeManager v1

| Method | Behavior | Notes |
|--------|----------|-------|
| `connect()` | Open `/api/realtime` EventSource (cookie auth) | Exists via `ensureRealtimeFeed` |
| `subscribe(type\|panel, fn)` | Register panel invalidators | **Add** — replace ad-hoc `addEventListener` sprawl over time |
| `lastEventId()` | Return buffered id | Exists (`noteEventId`) |
| `reconnect()` | Close + reopen with `last_event_id` | Partial |
| `replay()` | Rely on server `replay_since` | Server-side already |
| `deduplicate(event_id)` | Drop duplicate UI applies | **Add** client Set (bounded) |
| `invalidate(panel)` | Refresh one workspace view | **Add** — Agents, Controls, Evidence, Risk, Compliance, Remediations |

**Remove polling** only where SSE already delivers the same signal (Command Center soft poll already skips when `__securaiqEsConnected`). Keep poll as **fallback** when EventSource failed—not as primary path.

Wire panels:

- Agents fleet / online
- Host controls / Control Center
- Evidence freshness
- Compliance score strip
- Risk
- Findings / threats
- Remediation queue + command approval
- License / activation (commercial)

---

## 5. ONE endpoint → ONE realtime timeline (acceptance UI)

Product acceptance view (lab): pick one agent/asset and show chronological bus events for that `agent_id` / `asset_id`:

```text
Agent → Inventory → Software → Vuln → Control → Evidence
  → Compliance → Risk → Remediation → Verification
```

**Implementation sketch (reuse bus, no new store required for lab):**

1. SSE already carries pushes; add optional `GET /api/realtime/timeline?agent_id=` that reads recent Streams entries / replay buffer filtered by agent (admin/lab).
2. Or: client-side timeline fed by `RealtimeManager.subscribe('*')` filtered by agent while viewing that asset.

Do **not** make PDF/DOCX the timeline SoT ([realtime-controls-evidence-spec.md](./realtime-controls-evidence-spec.md)).

---

## 6. Control / compliance / evidence gaps (biggest product hole)

| Gap | Why it matters | Direction |
|-----|----------------|-----------|
| Curated test registry only | Not full CIS/NIST auto-map | Keep curated; freeze Framework Live Test UI (#144) |
| Event-scoped control recompute | Check-in re-runs host set; package change may not re-touch only affected controls | On `software.*` / `configuration.*`, schedule affected-control ids only |
| `control_results` append-only history | Audit / certification trail | New table + write from `evaluate_agent_host_controls` |
| Compliance score as first-class SSE | Often thin / derived | Publish `compliance.updated` when control PASS/FAIL changes score |
| Completeness of UI | Types registered ≠ panels update | RealtimeManager invalidate map |

Host live tests already implemented: firewall, Defender, SSH root, disk encryption — `app/controls/test_registry.py` + `app/services/control_testing.py`.

---

## 7. Commercial gate (before marketing signed installers)

Do **not** commercially promise `.msi` / `.deb` / `.rpm` / `.dmg` until this chain is real:

```text
MFA → organization → license → agent enrollment
  → device identity → mTLS (proxy + certs)
  → signed command → approval → execution
  → verification → evidence
```

| Link | Repo status (honest) |
|------|----------------------|
| MFA + recovery + mandatory | Shipped (`app/mfa.py`, auth) |
| Org / tenancy / RBAC | Shipped |
| Signed license + validate | Shipped (`app/license_service.py`, `/api/licenses/*`, agent validate) |
| Enroll tokens | Shipped |
| Device identity | Partial (agent id + fingerprint fields; cert columns when `AGENT_MTLS_ENABLED`) |
| mTLS | Stub + proxy examples (`deploy/*mtls*`, `AGENT_MTLS_PROXY_VERIFY`); not fleet-complete rotation |
| Signed commands | HMAC default; Ed25519 + `AGENT_REQUIRE_COMMAND_SIGNATURE` opt-in |
| Approval → execute → verify → evidence | Firewall loop lab-proven; not full action catalog |
| Authenticode / notarization | CI secrets-gated scaffolds only |

Packaging scaffolds may ship for **lab/owned hosts**; commercial “signed enterprise agent” claims wait on the table above.

---

## 8. Implementation backlog (ordered)

### P0 — Prove and harden the existing loop

1. [x] Keep `scripts/realtime_acceptance_demo.py --local` green in CI (`phase1-realtime-gate`).
2. [x] Document runbook: Redis URL vs in-process; Sentinel compose profile; DLQ admin (`deploy/redis/README.md`, `scripts/realtime_phase1_proof.py --document`).
3. [x] Emit missing dotted aliases on existing publish sites (`control.passed`, `evidence.created`, command lifecycle, `agent.online`) without breaking flat `type` — `publish_aliased` in `app/realtime_events.py`.
4. [x] RealtimeManager: `subscribe` / `deduplicate` / `invalidate` for Agents + Controls + Evidence + Risk (`static/app.js`).
5. [x] Publish `license.updated` on issue/validate/revoke; `agent.update.available` on update publish.
6. [x] Live security stream shows human labels + event type badges for the full closed-loop vocabulary.
7. [x] CI once-only / XAUTOCLAIM / SSE replay proofs (`tests/test_realtime_phase1_proof.py`, `app/realtime/`).
8. [ ] Ops: record a **measured** Sentinel failover timing note after `docker compose stop redis-primary` (lab stub only — not Cluster cert).

### P1 — Make the chain complete product-wise (Sprint 2–4; do not expand scanners first)

9. Affected-controls-only recompute on package/config events.
10. `control_results` history table + API read for timeline.
11. Timeline UI for one agent (SSE-fed).
12. Production profile: `AGENT_REQUIRE_COMMAND_SIGNATURE=true`, replay protection on, mTLS device certs/rotation (Sprint 2).
13. Automatic evidence on every control/remediation state change (Sprint 3).

### P2 — After acceptance greens

11. Broader OS config trees / Phase 22+ domain expansion (explicitly frozen until then).
12. Full cert rotation / short-lived creds (RT-16 completion).
13. Commercial Authenticode/notarization with org secrets.

---

## 9. File index (quick map)

| Concern | Path |
|---------|------|
| SSE endpoint | `app/main.py` → `GET /api/realtime` |
| Bus | `app/realtime_bus.py` |
| Schema | `app/event_schema.py`, `app/realtime_events.py` |
| Processor / DLQ consumer | `app/event_processor.py` |
| Agent gateway | `app/agent_gateway.py` |
| Check-in / commands | `app/agents.py`, `app/agents_api.py` |
| Host controls | `app/services/control_testing.py`, `app/controls/test_registry.py` |
| Evidence | `app/services/evidence.py` |
| Package diffs | `app/software/sources/securaiq_agent.py` |
| Config baselines | `app/configuration/*` |
| Lab agent | `scripts/securaiq_agent.py` |
| Rust agent | `securaiq-agent/` |
| UI realtime | `static/app.js` (`RealtimeManager`, `REALTIME_LIVE_TYPES`) |
| Acceptance | `scripts/realtime_acceptance_demo.py` |
| Chaos / load / multiworker | `scripts/realtime_*.py` |

---

## 10. What “done” means for realtime production (this doc)

**Lab done:** firewall (and Defender/SSH) closed loop green on owned endpoints; SSE updates Controls/Evidence/Risk without refresh; Streams+DLQ healthy when `REDIS_URL` set.

**Production claim done:** above + Sentinel/multi-worker proof + command signature enforcement + mTLS proxy verify for agents + no commercial installer claims without signing secrets.

**Explicitly not done by this doc alone:** full framework certification, XDR/Sigma engine, or a new realtime stack.

---

*This document consolidates product direction onto the current `main` tree. Prefer updating this file and [realtime-controls-evidence-spec.md](./realtime-controls-evidence-spec.md) when status changes—do not fork architecture docs.*
