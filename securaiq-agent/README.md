# securaiq-agent (Rust)

Cross-platform **SecuraIQ endpoint agent**: one core, OS-specific adapters.

- Architecture: [`docs/securaiq-architecture.md`](../docs/securaiq-architecture.md)
- Protocol: [`docs/agent-protocol-v1.md`](../docs/agent-protocol-v1.md)
- Lab bridge (Python): [`scripts/securaiq_agent.py`](../scripts/securaiq_agent.py)

## Status

**v0.2.0 — Phase 2 inventory + host security status**

- Token auth, HTTPS check-in (HMAC), offline queue, gateway WS/HTTP
- Deep inventory: OS, hardware, software/packages, users, groups, processes,
  services, network, listening ports, startup apps
- Host status: firewall, disk encryption, Defender (Windows), SSH config (Lin/mac)
- Allowlisted remediations still ACK-only in Rust — use Python bridge to execute

```powershell
cd securaiq-agent
$env:CARGO_TARGET_DIR = "$PWD\target"
cargo build --release
.\target\release\securaiq-agent.exe --server http://127.0.0.1:8080 --token "<id>.<key>" --once
```

Env: `SECURAIQ_SERVER`, `SECURAIQ_TOKEN`, `SECURAIQ_AGENT_DATA_DIR`.

Admin enrolls via dashboard / `POST /api/agents/enroll` (token shown once).

## Principles

1. Speak **existing** Agent Gateway / HTTPS APIs.
2. No arbitrary shell; allowlisted remediation only.
3. Honest `collected` / `reason` when a signal cannot be gathered.
4. AI stays on the **server**.
