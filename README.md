# SecuraIQ

**Local security AI workspace** for authorized pentesting, blue-team / SOC workflows, CTFs, GRC, and sandboxed malware analysis.

On-prem friendly. Not a ChatGPT clone — Mission Control, engagements, scanners, RAG, and local or cloud model backends.

> Use only on labs, VMs, CTFs (HTB / THM / PortSwigger), or systems you own and are authorized to test.

---

## Quick start (no `.env` editing)

You never need to create or edit a `.env` by hand. Start scripts create the venv, copy `.env.example` → `.env`, and boot the server. Optional API keys go in **Settings** in the UI later.

**From a clean clone, scans/tools/reports work without Ollama.** Chat needs Ollama, LM Studio, or an API token in Settings.

### Requirements

- [Python 3.11+](https://www.python.org/downloads/) on PATH (Windows: tick **Add python.exe to PATH**)
- Internet once for `pip` (and optional model download)

### Any OS (from scratch)

```bash
git clone https://github.com/nrbns/Hackgpt-ai.git
cd Hackgpt-ai
python3 -m venv .venv
# Windows:  .\.venv\Scripts\python -m pip install -r requirements.txt
# Unix:     .venv/bin/python -m pip install -r requirements.txt
.venv/bin/python run.py          # Unix
.\.venv\Scripts\python run.py    # Windows
```

Open **http://127.0.0.1:8080** — then **New scan** on a host you own.

### Windows (one command)

```powershell
git clone https://github.com/nrbns/Hackgpt-ai.git
cd Hackgpt-ai
.\run_proper.cmd
```

After the first setup, double-click or run:

```powershell
.\start.cmd
```

Open **http://127.0.0.1:8080**

### Windows EXE (no Python on PATH)

From a machine that already has the venv (after `.\run_proper.cmd` once):

```powershell
.\build_exe.cmd
```

That writes **`dist\SecuraIQ\SecuraIQ.exe`**. Copy the whole `dist\SecuraIQ` folder (not just the EXE). Double-click `SecuraIQ.exe` — it opens the browser at http://127.0.0.1:8080 and stores `data\` and `.env` next to the EXE.

### Works everywhere

Same repo on **Windows, macOS, Linux, and Docker**. Paths and `.env` always resolve from the project root — you can start from any working directory:

```bash
# after venv exists
.venv/bin/python /path/to/Hackgpt-ai/run.py          # Linux/macOS
.\.venv\Scripts\python.exe E:\Hackgpt\Hackgpt-ai\run.py   # Windows
```

Or use Docker (any host with Docker):

```bash
export BOOTSTRAP_ADMIN_PASSWORD='your-strong-password'
docker compose up --build
```

| Command | Purpose |
|---------|---------|
| `.\run_proper.cmd` | First-time setup + start |
| `.\start.cmd` | Start only (localhost) |
| `.\start_lan.cmd` | Start reachable on Wi‑Fi (phones / other PCs) |
| `.\scripts\enable_secure_mode.cmd` | Turn on login + lock register |

### Other devices (phone / tablet / another PC on Wi‑Fi)

1. On this machine run **`.\start_lan.cmd`** (Windows) or **`bash start_lan.sh`** (Linux/macOS).
2. The console prints URLs like `http://192.168.x.x:8080`.
3. On the other device (same Wi‑Fi), open that URL in a browser.
4. If it does not load on Windows: allow **TCP 8080** in Windows Defender Firewall (Private networks). LAN start tries to add this rule automatically.

LAN mode binds `0.0.0.0`, allows trusted-lab open access (`ALLOW_OPEN_LAN=true`), relaxes CORS, and **keeps workspace data** across restarts (`WORKSPACE_ZERO_START=false`). It also **auto-scans this host** (not the rest of the Wi‑Fi) so Assets, findings, and Mission Control populate on every phone/PC in realtime. Open the printed `http://192.168.x.x:8080` URL on the other device — scans started on one screen appear on the others without refresh.

### Linux / macOS

```bash
git clone https://github.com/nrbns/Hackgpt-ai.git
cd Hackgpt-ai
bash scripts/run_proper.sh
# later:
bash scripts/start.sh
# phones / other PCs on Wi‑Fi:
bash start_lan.sh
```

### Docker

```bash
export BOOTSTRAP_ADMIN_PASSWORD='your-strong-password'
docker compose up --build
```

Auth is on by default in Compose. Sign in as `admin`.

The image installs **Nmap**, **Nuclei** (templates), and optionally **ZAP** for daemon boost. **SecuraIQ Web Scanner** is built-in (no ZAP required). Smaller image without ZAP:

```bash
docker compose build --build-arg INSTALL_ZAP=false
```

Override versions with `--build-arg NUCLEI_VERSION=…` / `ZAP_VERSION=…` if needed.

Optional profiles:

```bash
docker compose --profile vectors up -d    # Qdrant
docker compose --profile prefect up -d    # Prefect UI
```

---

## How to use

1. Open **Mission Control** (starts at score **0** / empty workspace).
2. **New scan** → set an owned target → choose **Discovery** (Nmap) → authorize → **Start scan**.
3. Review assets/services and findings (evidence under `data/evidence/scans/`).
4. Optionally **Import** third-party reports (ZAP, Burp, Trivy, …) under Vulnerabilities.
5. Triage findings → remediations → optional Jira / AI Investigation.
6. Connect Wazuh / Slack / webhooks under **Integrations** when ready.

**Primary workflow:** Create Engagement → Define Scope → Run Scan → Review Findings → AI Investigation → Remediate → Report

**In-app manual:** http://127.0.0.1:8080/manual/ · source: [`docs/user-manual.md`](docs/user-manual.md)

### Secured mode (password login)

Default lab mode is open on **localhost only**. For a gated install:

```powershell
.\scripts\enable_secure_mode.cmd
.\start.cmd
```

This enables auth, disables public registration, binds `127.0.0.1`, and prints an `admin` password once.

### Zero-start vs keep data

| Setting | Default | Meaning |
|---------|---------|---------|
| `HOST` | `127.0.0.1` | Localhost only (use `-Lan` for Wi‑Fi) |
| `AUTH_ENABLED` | `false` | Open lab on localhost |
| `WORKSPACE_ZERO_START` | `true` (lab) | Empty Mission Control on each localhost start; prior scans go to **Reports → archive** |
| `ALLOW_OPEN_LAN` | `false` | Required for phones when auth is off (`start_lan` sets `true`) |
| `LAN_AUTO_SCAN` | `false` | Discovery scan of **this host** on LAN start so assets load on every device |
| `AUTH_ALLOW_REGISTER` | `false` | No public signup when auth is on |

Set `WORKSPACE_ZERO_START=false` (or use **start_lan** / secured mode) to keep live assets and findings across restarts.

---

## Features

- **Scan engine** — **New scan** queues a worker: built-in SecuraIQ, **SecuraIQ Web Scanner**, **Nmap**, **Nuclei**, or **Combo workflow** → evidence → assets/findings. Docker image includes Nmap+Nuclei (+ optional ZAP daemon). Import remains optional for third-party reports.
- **Mission Control** — security score, KPIs, first-run checklist, morning brief
- **18 agent modes** — CTF, red/blue/purple, XDR, IR, cloud, AppSec, CISO, awareness, …
- **Gap analysis** — ISO / NIST / CIS controls + remediations
- **Vuln import** — CSV / JSON / XML (optional alongside live scans)
- **SOC / XDR** — incidents, detections, optional **Wazuh** sync
- **Inventory** — scan discovery + optional network sync into Assets
- **Threat intel** — KEV, NVD, free intel APIs, password exposure check (k-anonymity)
- **Automation** — background jobs + optional Prefect
- **RAG** — local knowledge base (Re-index in UI)
- **PWA** — installable on phone/tablet browsers

### Model backends (optional)

First start prefers **Ollama** if installed, otherwise the configured Hugging Face path. Switch anytime in **Settings** or with scripts:

| Backend | Windows | Linux / macOS |
|---------|---------|---------------|
| Ollama | `.\scripts\use_ollama.cmd` | `bash scripts/use_ollama.sh` |
| LM Studio | `.\scripts\use_lmstudio.ps1` | `bash scripts/use_lmstudio.sh` |
| Hermes Agent | `.\scripts\use_hermes.ps1` | `bash scripts/use_hermes.sh` |
| Unsloth | `.\scripts\use_unsloth.ps1` | `bash scripts/use_unsloth.sh` |
| Hugging Face | `.\scripts\use_huggingface.ps1` | `bash scripts/use_huggingface.sh` |
| Wazuh SIEM | `.\scripts\use_wazuh.cmd` | — (prompted SecureString password) |
| Network inventory | LAN Refresh (built-in Open-AudIT-style) or `.\scripts\use_openaudit.cmd` | Optional appliance password |
| HardeningKitty | `.\scripts\use_hardeningkitty.cmd -Download` | — |

---

## Scan pipeline (definition of done)

SecuraIQ’s assessment path is **worker-driven**, not AI-invented:

```text
New scan (authorized + scope) → job queue → scanner worker → raw evidence →
parse → normalize → assets + findings → risk score → report → Ask AI (from evidence)
```

- **Default live scanner:** SecuraIQ builtin (always available). Discovery/web without structured scope is allowed for builtin only.
- **Nmap / Nuclei / ZAP:** require structured scope (CIDR/IP/hostname) and the authorization checkbox. Empty scope is blocked.
- **SecuraIQ Web Scanner (built-in DAST):** runs out of the box — security headers, cookies, sensitive paths, CORS, TLS, reflection probes. No ZAP install required. Optional: set `ZAP_PREFER_API=true` and start a ZAP daemon on **8090** for deeper spider/active scan on top of the built-in engine.
- **Nmap:** install [Nmap](https://nmap.org/download.html) (Windows: winget `Insecure.Nmap`) **and [Npcap](https://npcap.com)**. Without Npcap, Windows reports the binary present but scans fail to start. Adapter also finds the default install under `Program Files`. Evidence lands in `data/evidence/scans/<scan_id>/` (`config.json`, `nmap.xml` or `securaiq_scan.json`, logs, `report.md`).
- **Finding lifecycle:** `open → triaged → in_progress → remediated → verified → resolved` (plus `accepted` / `false_positive`). Triage creates risk + remediation.
- **Assets:** scans correlate by IP/hostname in notes so IP-first and hostname-first results merge.
- **Ask AI (from evidence):** post-scan CTA calls `POST /api/ai/investigate-scan` and loads `report.md` + artifact paths into the chat prompt (no invented results).
- **Combo assessment:** one tool `combo_assessment` (**Integrated VA**) in Tools hub / chat — runs authorize → SecuraIQ + Nmap + Nuclei + SecuraIQ Web Scanner → evidence → investigate → auto-triage. Also: `POST /api/scans/combo`, New Scan **Combo workflow**, Mission Control button.
- **Imports:** Greenbone/OpenVAS report XML via `POST /api/vulnerabilities/import` (alongside Burp/ZAP/Trivy/…).
- Do not claim “automated pentest” for customers until you can demo this path on a lab you own.

---

## Modes

| Mode | Focus |
|------|-------|
| Default | Pentest + defense |
| CTF / Lab | Flags, DVWA, Juice Shop |
| Red / Blue / Purple | Attack, detect, fix loops |
| Threat hunt / XDR | Hypothesis hunts, alert correlation |
| IR | Containment playbooks |
| Malware lab | Sandbox, YARA, IOC (authorized samples) |
| Cloud / AppSec | Posture + ASVS |
| CISO / Awareness / Tabletop | GRC, phishing sims, exercises |

---

## Verify install

With the server running:

```powershell
.\.venv\Scripts\python scripts\smoke_test.py
.\.venv\Scripts\python scripts\check_openapi_gets.py
.\.venv\Scripts\python scripts\commercial_integration_check.py
```

```bash
.venv/bin/python scripts/smoke_test.py
.venv/bin/python scripts/check_openapi_gets.py
.venv/bin/python scripts/commercial_integration_check.py
```

Or offline: `.venv/Scripts/python -m pytest tests/ -q`

---

## API (high level)

| Endpoint | Purpose |
|----------|---------|
| `GET /api/health` | Backend + RAG status |
| `GET /api/dashboard` | Mission Control data |
| `GET /api/settings` | Masked settings (secrets never cleartext) |
| `POST /api/chat` | Streaming chat |
| `GET /api/platform` | OS + LAN URLs |
| `GET /api/wazuh/status` | Wazuh connector |
| `GET /api/openaudit/status` | Network inventory connector |
| `POST /api/openaudit/sync` | Queue inventory device sync |
| `POST /api/lan/refresh` | Sweep local `/24`, queue VA scans, stream Open-AudIT-style inventory |
| `GET /api/hardeningkitty/status` | HardeningKitty / CIS workflow |
| `POST /api/hardeningkitty/audit` | Local Windows Audit (not HailMary) |
| `POST /api/intel/password/check` | HIBP k-anonymity (body only) |

Full OpenAPI: http://127.0.0.1:8080/docs

---

## Docs

| Doc | Topic |
|-----|--------|
| [`docs/user-manual.md`](docs/user-manual.md) | End-user guide |
| [`docs/enterprise-integrations.md`](docs/enterprise-integrations.md) | Connectors |
| [`docs/security-baseline.md`](docs/security-baseline.md) | Hardening checklist |
| [`docs/commercial-roadmap.md`](docs/commercial-roadmap.md) | Product roadmap |
| [`docs/launch-readiness.md`](docs/launch-readiness.md) | Ship checklist |
| [`docs/cursor-local-models.md`](docs/cursor-local-models.md) | Local models in Cursor |

---

## Project layout

```
app/           FastAPI backend
static/        Web UI (primary)
scripts/       Start helpers, backend switches, smoke checks
data/knowledge RAG corpus
docs/          Manuals and runbooks
```

Cursor rule for authorized-only security work: [`.cursor/rules/authorized-security-assistant.mdc`](.cursor/rules/authorized-security-assistant.mdc)

---

## License / use

Authorized security work only. Do not use this project for unauthorized access, malware deployment, or credential theft.
