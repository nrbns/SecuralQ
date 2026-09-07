# SecuraIQ Agent — Quick start

Authorized labs / owned hosts / blue-team endpoints only. This is **not** malware C2.

## What this package does

1. **Enroll** — you create an agent identity on the SecuraIQ server (token shown once).
2. **Check-in** — the agent posts real host telemetry to `POST /api/agents/checkin`.
3. **Realtime** — WebSocket Agent Gateway (`WS /api/agents/ws`) when available; otherwise HTTP long-poll (`POST /api/agents/gateway/wait`) plus periodic check-in.
4. **Commands** — approved `patch_package` / `agent_upgrade` jobs are executed and reported back (inventory refresh → verify → evidence on the server).

## First run (all platforms)

1. Open SecuraIQ → **Agents** (Security Operations → Agents) → **Enroll new agent**. Copy the token (`<agent_id>.<agent_key>`).
2. Download the OS package from the same page (`GET /api/agents/packages`), or copy `agent.env.example` → `agent.env` next to the agent binary (or script).
3. Set:

   ```
   SECURAIQ_SERVER=https://your-securaiq-host:8080
   SECURAIQ_TOKEN=<agent_id>.<agent_key>
   ```

4. Start the agent (see platform sections). Within ~60s it should show **online** in the Agents UI.

CLI equivalent (no env file):

```text
SecuraIQ-Agent --server https://your-host:8080 --token <agent_id>.<agent_key>
```

Useful flags: `--once` (single check-in), `--help`, `--version`, `--insecure` (lab self-signed TLS only), `--no-websocket`, `--no-gateway`.

---

## Windows

**Portable exe**

1. Unzip the package (or use the standalone `.exe`).
2. Create `agent.env` beside `SecuraIQ-Agent.exe`.
3. Double-click the exe, or run from PowerShell:

   ```powershell
   .\SecuraIQ-Agent.exe
   ```

**Install as startup task (elevated PowerShell)**

```powershell
.\install.ps1 -Server "https://your-host:8080" -Token "<agent_id>.<agent_key>"
```

This copies the exe under `%ProgramData%\SecuraIQ\agent` and registers a SYSTEM Scheduled Task (`SecuraIQAgent`).

Optional service-style registration with `sc.exe` is not required; Task Scheduler is the supported unattended mode (no NSSM/WinSW dependency).

---

## Linux

```bash
tar -xzf SecuraIQ-Agent-*-linux-*.tar.gz
cd SecuraIQ-Agent-*-linux-*
sudo ./install.sh --server https://your-host:8080 --token '<agent_id>.<agent_key>'
```

Installs to `/opt/securaiq-agent`, writes `/etc/securaiq/agent.env` (mode 600), and enables `securaiq-agent.service` when systemd is present.

Without root (foreground):

```bash
cp agent.env.example agent.env   # edit SERVER + TOKEN
./SecuraIQ-Agent                 # or: python3 securaiq_agent.py
```

---

## macOS

**From `.dmg` (built on macOS / CI)**

1. Open the DMG → drag **SecuraIQ Agent** to Applications (or run from the volume).
2. If Gatekeeper blocks an ad-hoc/unsigned build: **System Settings → Privacy & Security → Open Anyway**, or:

   ```bash
   xattr -dr com.apple.quarantine "/Applications/SecuraIQ Agent.app"
   ```

3. Create `agent.env` inside the app support dir, or run:

   ```bash
   "/Applications/SecuraIQ Agent.app/Contents/MacOS/SecuraIQ-Agent" \
     --server https://your-host:8080 --token '<agent_id>.<agent_key>'
   ```

**From `.tar.gz` (portable)**

```bash
tar -xzf SecuraIQ-Agent-*-macos-*.tar.gz
cd SecuraIQ-Agent-*-macos-*
sudo ./install.sh --server https://your-host:8080 --token '<agent_id>.<agent_key>'
```

That registers a LaunchDaemon (`com.securaiq.agent`).

---

## Confirm realtime

- Agents UI: status **online**, last check-in updates.
- Server logs / Mission Control SSE: `agent` / `agent_command` events when commands are approved.
- Agent console: `check-in ok` and optionally `websocket connected`.
