# SecuraIQ Agent Platform

**Product stance:** SecuraIQ Agent is **not** an EDR product and **not** a Wazuh clone.  
It extends the existing gateway + agent check-in path already in this repo: inventory and host-control telemetry → control/risk/evidence → optional **approved** remediation commands.

Related: [securaiq-architecture.md](./securaiq-architecture.md) (Phase 0 freeze) ·
[agent-protocol-v1.md](./agent-protocol-v1.md) ·
[agent-platform-v1.md](./agent-platform-v1.md) (lab slices) ·
[master-build-plan.md](./master-build-plan.md) ·
[control-plane-roadmap.md](./control-plane-roadmap.md) ·
[control-config-engine.md](./control-config-engine.md) ·
[realtime-v1.md](./realtime-v1.md)

---

## Architecture

```text
  SecuraIQ Agent (lab / owned host)
           │
           │  HTTP check-in  +  WS / long-poll gateway
           ▼
     Agent Gateway (app/agents_api.py, app/agents.py)
           │
           ▼
     Realtime event bus (Redis Streams when configured)
           │
     ┌─────┼──────────────┐
     ▼     ▼              ▼
  Control  Risk        Evidence
  tests    scoring     / audit proof
     │
     ▼
  Remediation recommend (auto_execute=false)
     │
     ▼
  Operator: request command → approve → agent fixed-argv action → next check-in verify
```

**Rules**

- Command `kind` is an allowlist (`SUPPORTED_COMMAND_KINDS`) — never arbitrary shell from the server.
- Every remediation command lands in `pending_approval` first; approval is required before delivery.
- Host FAIL opens POA&M / remediation stubs and publishes `remediation.recommended`; it does **not** auto-execute enable/firewall/defender/SSH changes.

---

## Module map

**Production direction:** one **Rust** core + OS adapters in [`securaiq-agent/`](../securaiq-agent/README.md)
(see architecture freeze). **Lab bridge:** keep `scripts/securaiq_agent.py` until Rust v0.1
protocol parity (enroll → heartbeat → inventory → allowlisted command → verify).

| Module | Role today | Code |
|--------|------------|------|
| **core** | Version, config, check-in loop, gateway wait/WS, command ack/result | `scripts/securaiq_agent.py`; Rust `securaiq-agent/` v0.2 |
| **inventory** | Host/OS/software/services/processes + **hardware / local_groups / network** | Python collectors; Rust `platform/deep/{windows,linux,macos}` |
| **security** | Firewall / Defender / SSH / BitLocker / sentinel heuristics | Python + Rust host-status on check-in; remediations Python-only for now |
| **response** | Allowlisted commands: `patch_package`, `agent_upgrade`, `enable_firewall`, `enable_defender` | agent executors + `app/agents.py` / `app/agents_api.py` |

Server-side control plane pieces that consume agent telemetry: `app/services/control_testing.py`, `app/controls/`, `app/configuration/`, event processor + realtime bus.

**Do not start server-side AI missions** until inventory → control → evidence → approve loop is solid on the agent path.

---

## Phase 1–7 build order (from product plan)

Aligned with [master-build-plan.md](./master-build-plan.md) Phases 1–7. Finish foundations before claiming EDR/XDR depth.

| Phase | Focus | Agent-platform implication |
|-------|--------|----------------------------|
| **1** | Realtime foundation (durable bus, DLQ, reclaim, acceptance) | Agent events and command lifecycle ride a trustworthy bus |
| **2** | Real agent platform | Deepen Win/Lin/Mac inventory + host telemetry (not full EDR) |
| **3** | Agent security | Enrollment, identity, signed commands, rotation (mTLS later) |

**Phase 3 progress (this slice):** sealed commands include `issued_at`/`expires_at` in the signature; agents refuse expired seals; check-in/ack/result send `X-SecuraIQ-Sig` over the raw body; prefer pinned Ed25519 public key. **Still missing:** mTLS / device certs / short-lived cred rotation.
| **4** | Realtime command system | Richer lifecycle + more **allowlisted** actions under approval |
| **5** | Security event engine | Normalize agent signals → detection → risk → evidence |
| **6** | EDR depth | Process/file/network/persistence behavior — **after** 1–5 are solid |
| **7** | Vulnerability management | CVE → asset → fix → verify using agent inventory + patch commands |

**This doc’s “Phase 1” agent slice:** document the platform, keep the monolith packagable, add safe allowlisted host fixes (`enable_firewall`, `enable_defender`), Agents detail + Control Center remediations, and scaffold `scripts/agent_lib/` without a big-bang split.

**Firewall acceptance bar:** `python scripts/realtime_acceptance_demo.py --local` must green (FAIL → evidence → POA&M → risk → approve `enable_firewall` → PASS).

---

## Explicit NOT now

Do **not** build these under the agent platform banner yet:

- Full EDR / XDR product surface (kernel callbacks, behavioral blocking engine)
- Kernel drivers / eBPF “always-on” sensor stack
- In-house antivirus engine or signature cloud
- Continuous packet capture / NIDS on the endpoint
- Arbitrary remote shell or free-form PowerShell from the server
- Auto-execute of dangerous remediations on control FAIL (Task **#144** frozen)

Commercial EDR **connectors** may exist elsewhere in the repo; they are not a substitute for claiming native EDR depth.

---

## Approved host remediation commands (current)

| Kind | API | Agent behavior |
|------|-----|----------------|
| `enable_firewall` | `POST /api/agents/{id}/commands/enable-firewall` | Fixed argv firewall enable (Windows / Linux; macOS honest unsupported) |
| `enable_defender` | `POST /api/agents/{id}/commands/enable-defender` | Windows: fixed argv `Set-MpPreference -DisableRealtimeMonitoring $false`; non-Windows: honest not supported |

Both always require approval. Failures must be reported honestly (elevation, third-party AV takeover, missing modules).
