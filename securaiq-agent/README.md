# securaiq-agent (Rust)

Cross-platform **SecuraIQ endpoint agent**: one core, OS-specific adapters.

- Architecture: [`docs/securaiq-architecture.md`](../docs/securaiq-architecture.md)
- Protocol: [`docs/agent-protocol-v1.md`](../docs/agent-protocol-v1.md)
- Lab bridge (Python): [`scripts/securaiq_agent.py`](../scripts/securaiq_agent.py)

## Status

**Phase 1 (wired):** enroll token auth, HTTPS check-in (HMAC replay headers), offline
queue, health probe, Agent Gateway long-poll, WebSocket session, reconnect backoff.
Inventory is a minimal honest snapshot (hostname/OS/ip + deferred deep slices).
Allowlisted remediations are **ACK’d** but not executed yet — use the Python bridge
for `enable_firewall` / `enable_defender` until Phase 9 in Rust.

Requires [Rust](https://rustup.rs/) (`rustc` / `cargo`).

```bash
cd securaiq-agent
cargo build --release
```

```powershell
.\target\release\securaiq-agent.exe --server http://127.0.0.1:8080 --token "<agent_id>.<agent_key>" --once
```

Env: `SECURAIQ_SERVER`, `SECURAIQ_TOKEN`, `SECURAIQ_AGENT_DATA_DIR`.

Admin enrolls via dashboard / `POST /api/agents/enroll` (token shown once). The agent
does **not** call enroll itself — same model as the Python bridge.

## Layout

```text
src/
  core/ transport/ crypto/ inventory/ platform/ storage/ response/ ...
```

## Principles

1. Speak **existing** Agent Gateway / HTTPS APIs — no second protocol.
2. No arbitrary shell; allowlisted remediation only.
3. Offline queue + reconnect; bounded resources.
4. AI stays on the **server**, not in this binary.
