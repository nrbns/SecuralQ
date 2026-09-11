# securaiq-agent (Rust)

Cross-platform **SecuraIQ endpoint agent**: one core, OS-specific adapters.

- Architecture: [`docs/securaiq-architecture.md`](../docs/securaiq-architecture.md)
- Protocol: [`docs/agent-protocol-v1.md`](../docs/agent-protocol-v1.md)
- Lab bridge (Python): [`scripts/securaiq_agent.py`](../scripts/securaiq_agent.py)

## Status

**v0.3.0 — Phase 3 security telemetry + allowlisted remediations**

- Deep inventory + host status (v0.2)
- FIM baseline + `file_integrity` events on check-in
- Bounded `security_logs` sample (Windows Security / journalctl / macOS log)
- Seal verify (HMAC + **Ed25519**) + **`enable_firewall` / `enable_defender`** fixed-argv execution
- `patch_package` / `agent_upgrade` still Python bridge

```powershell
cd securaiq-agent
$env:CARGO_TARGET_DIR = "$PWD\target"
cargo build --release
.\target\release\securaiq-agent.exe --server http://127.0.0.1:8080 --token "<id>.<key>" --once
```

Optional: `SECURAIQ_AGENT_SIGNING_KEY` (HMAC, must match server), `SECURAIQ_AGENT_ED25519_PUBLIC_KEY` (or trust `signing_public_key` on sealed commands), `SECURAIQ_REQUIRE_COMMAND_VERIFY=1`.

## Principles

1. Speak existing Agent Gateway / HTTPS APIs.
2. No arbitrary shell — allowlisted remediations only.
3. Honest `collected` / `reason` when signals cannot be gathered.
4. AI stays on the **server**.
