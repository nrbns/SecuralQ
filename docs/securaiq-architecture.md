# SecuraIQ — Architecture Freeze (Phase 0)

**Status:** Frozen product direction (2026-09-10).  
**Rule:** Extend this repository’s control plane. Do **not** start a second SecuraIQ.

Related: [agent-platform.md](./agent-platform.md) · [agent-protocol-v1.md](./agent-protocol-v1.md) ·
[realtime-v1.md](./realtime-v1.md) · [master-build-plan.md](./master-build-plan.md)

---

## Three layers (one product)

```text
1. Cross-platform SecuraIQ Agent     — one Rust core + OS adapters
2. SecuraIQ Security Server          — existing FastAPI control plane
3. Agentic Security Engine + UI      — server-side AI tools (not on endpoint)
```

```text
  Dashboard (today: static/; target: React+TS)
           │  HTTPS + SSE
           ▼
  SecuraIQ Server (app/* FastAPI, Redis Streams, Postgres when configured)
           │  Agent Gateway WS + HTTPS
           ▼
  ┌────────────┬────────────┬────────────┐
  │  Windows   │   Linux    │   macOS    │
  │  adapter   │  adapter   │  adapter   │
  └─────┬──────┴─────┬──────┴─────┬──────┘
        └────────────┼────────────┘
                     ▼
              Rust agent core
```

---

## Locked decisions

| Decision | Choice | Non-choice |
|----------|--------|------------|
| Endpoint agent language | **Rust** (`securaiq-agent/`) | Three separate Win/Lin/Mac codebases; Electron/Node on endpoint |
| Lab / bridge agent | Keep `scripts/securaiq_agent.py` until Rust remediations land | Delete Python agent overnight |
| Control plane | Existing `app/agents*`, gateway, controls, evidence, realtime | New SIEM / second gateway |
| Commands | Allowlisted + approval + signature + verify | AI → arbitrary shell |
| AI location | **Server-side** orchestrator + tool calls | Heavy LLM inside the endpoint agent |
| EDR / kernel | Later (after inventory → control → risk → approve loop) | Kernel driver / full EDR in v0.1 |
| Dashboard rewrite | Evolve toward React+TS; keep shipping on current UI | Big-bang rewrite before agent v0.1 |

**Phase 1–4 progress:** Rust agent speaks check-in + gateway + offline queue, deep inventory,
FIM + security log samples, HMAC seal verify, and allowlisted `enable_firewall` /
`enable_defender`. Server: agent packages → debounced advisory CVE match → enterprise vuln
bridge (`app/software/vuln_bridge.py`). Patch/upgrade and Ed25519 seals still lean on later work.

---

## Product loop (everything maps here)

```text
DISCOVER → OBSERVE → DETECT → UNDERSTAND → PRIORITIZE → APPROVE
        → REMEDIATE → VERIFY → PROVE → RISK / COMPLIANCE → continuous
```

Never claim “fixed” without independent verification + evidence.

---

## Agent shape

- **One binary** per OS: `SecuraIQAgent.exe` / `securaiq-agent`
- **Adapters:** `platform/{windows,linux,macos}` implementing shared traits
- **Transport:** WebSocket (heartbeat, commands, ACK) + HTTPS (enroll, check-in, inventory, fallback)
- **Local store:** config, identity, offline queue (extends current offline-buffer semantics)
- **Security modes:** Monitor → Assist → Controlled Response → Campaign (canary rollouts)

Code lives in repo root: [`securaiq-agent/`](../securaiq-agent/README.md).

---

## Server mapping (already in this repo)

| Layer | Today |
|-------|--------|
| Enrollment / check-in / commands | `app/agents.py`, `app/agents_api.py` |
| Gateway WS / long-poll | `app/agent_gateway.py` |
| Auth / seals / replay | `app/agent_auth.py`, `app/agent_security.py` |
| Offline buffer | `app/agent_offline_buffer.py` |
| Controls / config | `app/controls/`, `app/configuration/` |
| Evidence | `app/services/evidence.py` |
| Realtime | `app/realtime_bus.py`, `app/event_processor.py` |
| Lab Python agent | `scripts/securaiq_agent.py` |

Rust agent **must speak the same protocol** as [agent-protocol-v1.md](./agent-protocol-v1.md).

---

## AI agents (server only — after Phase 5+)

Specialized agents with **validated tools** only:

`get_asset`, `get_agent`, `get_inventory`, `get_events`, `get_vulnerabilities`,
`get_controls`, `get_evidence`, `get_attack_paths`, `calculate_risk`,
`run_control_test`, `create_finding`, `create_remediation`, `request_approval`,
`create_campaign`, `verify_remediation`

No direct DB or OS shell from the model.

---

## Roadmap (build order)

| Phase | Milestone | Notes |
|-------|-----------|--------|
| **0** | Architecture freeze | This doc + protocol |
| **1** | Rust agent core | enroll, heartbeat, WS/HTTPS, queue, health — Win+Linux first, then macOS |
| **2** | Inventory | OS/hardware/software/users/processes/services/network |
| **3** | Security telemetry | logs, FIM, firewall/AV/encryption config |
| **4** | Vulnerability | package → CVE → exposure → risk |
| **5** | Config & compliance | observe → control test → evidence — **host_disk_encryption** live test wired (v0.3 telemetry) |
| **6–7** | Detection + risk | correlation, attack path, business risk — **host PASS/FAIL → compensating_controls / priority reasons** (Phase 6 wedge) |
| **8** | AI SecOps | investigation / risk / compliance / remediation / verification agents |
| **9–10** | Response + campaigns | signed commands, canary, rollback |
| **11** | Advanced | graph twin, cloud/K8s, SBOM, deeper EDR |

**Do not start Phase 8 (AI missions) before Phases 1–5 are solid.**

---

## Honesty

- Resource targets (≤1–2% CPU, ~50–150 MB RAM) are **goals**, not SLAs, until measured.
- CMMC / certification claims stay out of product copy (operating-effectiveness only).
- Task **#144** (Frameworks Live Test UI column) remains frozen.
