# SecuraIQ Agent Protocol v1

**Status:** Phase 0 contract — Rust and Python agents must stay compatible.  
**Authority:** Existing FastAPI routes under `/api/agents/*` and `/api/agent-gateway/*`.

Parent: [securaiq-architecture.md](./securaiq-architecture.md)

---

## Transport

| Channel | Use |
|---------|-----|
| **HTTPS** | Enrollment, check-in (inventory), command ACK/result, config pull, offline flush |
| **WebSocket** (Agent Gateway) | Heartbeat, push commands, realtime status; HTTPS long-poll fallback |

Base URL is the SecuraIQ server (e.g. `http://127.0.0.1:8080`). Agent never talks to the LLM.

---

## Identity & enrollment

1. Admin creates enrollment (token + org).
2. Agent generates keypair (lab: HMAC shared secret / Ed25519 as configured).
3. Agent calls enroll → receives `agent_id`, policy hints, signing material.
4. Private key **stays on endpoint**.

Headers (check-in / ACK / result / gateway wait) include request authenticity
(`X-SecuraIQ-Sig` over **raw body** where applicable). Command seals carry
`issued_at` / `expires_at`; expired seals are refused.

Production target (later): device certificate + mTLS. Not required for v0.1.

---

## HTTPS surfaces (stable shapes)

Align with current server; field names may grow but must not break without version bump.

| Operation | Method / path (canonical) | Payload focus |
|-----------|---------------------------|---------------|
| Enroll | `POST /api/agents/enroll` | token, hostname, OS, agent version, public key |
| Check-in | `POST /api/agents/{id}/check-in` | inventory slices, health, policy version |
| Heartbeat | via gateway or check-in interval | status, queue depth |
| Poll / wait commands | gateway WS or HTTPS wait | pending commands |
| ACK command | `POST .../commands/{cid}/ack` | command id, status |
| Result | `POST .../commands/{cid}/result` | exit, stdout summary, verification |
| Offline flush | buffered events → check-in / event ingest | ordered, ACK then drop |

Exact paths: follow `app/agents_api.py` / `app/agent_gateway.py` as source of truth;
this doc freezes **semantics**, not every query param.

---

## Check-in inventory slices (v0.1)

Agent may send partial inventory; server stores and marks `collected` / `reason`.

```text
system | hardware | software | users | groups | processes | services | network
```

Deferred for later protocol revisions: certificates, scheduled tasks, rich port→PID.

---

## Command model (security-critical)

Commands are **allowlisted kinds** only (e.g. `enable_firewall`, `enable_defender`,
agent upgrade). Flow:

```text
Recommendation → policy → human approval → signed seal → agent verify
  → allowlisted execute → ACK → independent verification → evidence
```

Forbidden: free-form shell from AI or dashboard.

Seal fields (minimum):

```text
command_id, kind, agent_id, args (fixed schema), issued_at, expires_at, signature
```

---

## Event / telemetry

Normalize at server (`Event Normalizer` → Redis Streams / bus → workers).

Agent emits typed events (auth, config drift, FIM, control observation, etc.)
with `agent_id`, `observed_at`, `schema_version`.

Dashboard consumes via SSE (`realtime` bus), not by polling agents.

---

## Policy schema (push)

YAML/JSON equivalent of:

```yaml
agent:
  heartbeat: 30
inventory:
  interval: 300
process:
  enabled: true
  interval: 60
network:
  enabled: true
fim:
  enabled: false   # v0.2+
logs:
  enabled: false
configuration:
  enabled: true
vulnerability:
  enabled: false
```

Server is source of truth; agent applies on next check-in / push.

---

## Versioning

- Protocol: `protocol_version: 1` in enroll/check-in.
- Agent binary: semver (`1.x` Python bridge / `0.1.x` Rust until parity).
- Breaking schema changes require `protocol_version` bump + dual-read window.

---

## Security modes (policy)

| Mode | Behavior |
|------|----------|
| Monitor | Collect, detect, report |
| Assist | + recommend, request approval |
| Controlled Response | + execute allowlisted after approve + verify |
| Campaign | staged % rollout + canary + rollback |

---

## Compatibility

| Client | Role |
|--------|------|
| `scripts/securaiq_agent.py` | Lab / Windows bridge until Rust remediations |
| `securaiq-agent/` (Rust) | Phase 1: token auth, check-in, WS/HTTP gateway, offline queue |

Both must pass enroll → heartbeat → inventory → approve firewall → verify loop
against a local server before declaring full remediations parity.
