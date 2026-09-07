# SecuraIQ — Agent Platform v1

Product loop: **SEE → THINK → ACT → VERIFY → PROVE**

## Slice 0 — Prove the existing Windows lab loop

Prereqs: `AUTH_ENABLED=true`, one Windows lab VM you own.

1. **SEE** — `POST /api/agents/enroll` → run packaged `SecuraIQ-Agent-*-windows-x64.exe` (or zip `install.ps1`) → confirm `status=online` after check-in.
2. **THINK** — Inventory/advisories show a real outdated package on that host (or install a known lab package).
3. **ACT** — `POST /api/agents/{id}/commands` with `patch_package` → approve → command delivered (check-in or gateway wait).
4. **VERIFY** — Agent reports result; patch verification / inventory refresh updates status.
5. **PROVE** — `audit_log` + evidence / findings update; Mission Control SSE shows `agent` / `agent_command` events.

Do not require WebSockets, Redis, or Postgres for Slice 0.

## Slice 1 — Multi-tenant agents

- `org_id` on `securaiq_agents`, commands, threats, campaigns.
- Enroll accepts active org (`X-SecuraIQ-Org` or primary membership).
- List/get/command APIs use tenant visibility + `require_perm`.
- Cross-org access returns 404/403.

## Slice 2 — Agent Gateway

- **Long-poll** `POST /api/agents/gateway/wait` — works with stdlib agent (no extra deps).
- **WebSocket** `WS /api/agents/ws` — for future native clients.
- On command approve → gateway notifies connected waiter (near-instant vs 60s check-in).
- HTTP check-in remains the telemetry + fallback command channel.

## Slice 3 — Security floor

- Commands carry `event_id`, `nonce`, HMAC `signature` (server signing key).
- Agent (and gateway) can verify signature; server rejects replayed nonces.
- Cloud-metadata SSRF stays blocked on web scanners; agent token still hashed at rest.

## Slice 4 — Load / failure

```bash
python scripts/load_test_agents.py --server http://127.0.0.1:8080 --admin-token <JWT> --agents 100 --duration 60 --gateway
```

Record measured `success_rate_pct` / latency from the script JSON output. Do **not** claim 5k-agent capacity without that measurement.

## Installers (honest current state)

| OS | Today (primary) | Developer fallback | Later |
|----|-----------------|--------------------|-------|
| Windows | **packaged** `SecuraIQ-Agent-*-windows-x64.exe` / `.zip` (embeds `install.ps1`) | `install_agent_windows.ps1` | signed MSI |
| Linux | **packaged** `*-linux-x64.tar.gz` (embeds `install.sh`) | `install_agent_linux.sh` | `.deb` / `.rpm` |
| macOS | **packaged** `*.tar.gz` (+ `.dmg` via macOS/CI) | `install_agent_macos.sh` | notarized `.pkg` / `.dmg` |

Build packages from the repo root:

```bash
python scripts/build_agent_packages.py
# artifacts → dist/agent-packages/
```

See README **Host agents** and `scripts/packaging/QUICKSTART.md`. CI: `.github/workflows/agent-packages.yml`.