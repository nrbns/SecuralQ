# SecuraIQ

**Local security workspace** for authorized pentesting, blue-team / SOC work, CTFs, compliance evidence, and sandboxed malware analysis.

Runs on your machine (or Docker). Scans, assets, findings, reports, host agents, and optional local AI — without sending lab data to a SaaS by default.

> **Authorized use only** — labs, VMs, CTFs (HTB / THM / PortSwigger), or systems you own and are allowed to test. Not for unauthorized access, malware deployment, or credential theft.

---

## What you get

| Area | What it does |
|------|----------------|
| **Scans** | New scan → Nmap / Nuclei / built-in web DAST / combo → evidence under `data/evidence/` |
| **Operations** | Assets, vulnerabilities, incidents, remediations, playbooks |
| **Compliance** | Frameworks, gap analysis, continuous control checks → remediations + evidence |
| **Reports** | PDF / DOCX / Excel exports; archived scan Markdown + PDF (delete per row) |
| **Agents** | Packaged `.exe` / `.zip` / `.tar.gz` (+ `.dmg` on Mac/CI), enroll, realtime check-in |
| **AI Analyst** | Optional chat (Ollama, LM Studio, or API keys in Settings) grounded on your evidence |

**Scans and reports work with no AI installed.** Chat needs Ollama, LM Studio, or an API token.

---

## Install

### End users (Windows package — recommended)

No Python required on the target PC. On a build machine with `.venv` already set up:

```powershell
.\build_exe.cmd
```

Copy `dist\SecuraIQ.exe` anywhere and double-click. Browser opens at **http://127.0.0.1:8080**. Data and `.env` live next to the EXE. First launch unpacks a large bundle (slower); later starts are faster.

Host agents are separate packages under `dist\agent-packages\` (see [Host agents](#host-agents-windows--linux--macos) below).

### Developers (source / scripts)

#### Requirements

- [Python 3.11+](https://www.python.org/downloads/) on PATH  
  Windows installer: tick **Add python.exe to PATH**
- Internet once for `pip`
- Optional later: [Nmap](https://nmap.org/download.html) (+ [Npcap](https://npcap.com) on Windows), [Ollama](https://ollama.com)

You do **not** need to hand-edit `.env`. Start scripts copy `.env.example` → `.env`. Tune keys later in **Settings**.

#### Windows (dev)

```powershell
git clone https://github.com/nrbns/Hackgpt-ai.git
cd Hackgpt-ai
.\run_proper.cmd
```

Next times:

```powershell
.\start.cmd
```

Open **http://127.0.0.1:8080**

| Script | Use (developers only) |
|--------|------------------------|
| `.\run_proper.cmd` | First-time venv + deps + start |
| `.\start.cmd` | Start on localhost |
| `.\start_lan.cmd` | Reachable on Wi‑Fi (phones / other PCs) |
| `.\scripts\enable_secure_mode.cmd` | Login required + lock public register |
| `.\build_exe.cmd` | Build installable `dist\SecuraIQ.exe` |

#### Linux / macOS (dev)

```bash
git clone https://github.com/nrbns/Hackgpt-ai.git
cd Hackgpt-ai
bash scripts/run_proper.sh
# later:
bash scripts/start.sh
# Wi‑Fi access:
bash start_lan.sh
```

Open **http://127.0.0.1:8080**

#### Any OS (manual)

```bash
git clone https://github.com/nrbns/Hackgpt-ai.git
cd Hackgpt-ai
python3 -m venv .venv

# Windows
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python run.py

# Linux / macOS
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python run.py
```

#### Docker

```bash
export BOOTSTRAP_ADMIN_PASSWORD='your-strong-password'
docker compose up --build
```

Sign in as `admin`. Image includes Nmap + Nuclei; optional ZAP at build time.

```bash
docker compose build --build-arg INSTALL_ZAP=false   # smaller image
docker compose --profile vectors up -d                 # optional Qdrant
```

---

## Use (first 10 minutes)

1. Open **http://127.0.0.1:8080**
2. Click **New scan** (header).
3. Enter a target you own (lab IP / hostname / URL).
4. Pick an engine (e.g. **Discovery / Nmap** or **Web**).
5. Check **authorize** (and seed scope when the UI asks).
6. **Start scan** → watch **Overview** / **Assets** / **Vulnerabilities** update live.
7. Open **Scans** (Reports) for Markdown + PDF; use **Archive & clear live scans** when you want a fresh workspace (archives stay listed; each row has **Delete**).

**Primary loop**

```text
Scope → New scan → Findings → Remediate → Verify → Report / evidence
```

In-app guide: http://127.0.0.1:8080/manual/  
Source: [`docs/user-manual.md`](docs/user-manual.md)

### Everyday pages

| Nav | Purpose |
|-----|---------|
| **Overview** | KPIs, what to fix first, live charts |
| **Assets / Vulnerabilities** | Inventory and findings |
| **Agents** | Enroll hosts, download packaged `.exe` / `.zip` / `.tar.gz`, fleet online status |
| **Compliance Center** | Framework posture + continuous control failures → Fix |
| **Scans** | Workspace exports + live/archived reports |
| **AI Analyst** | Chat (needs a model backend) |
| **Settings** | API keys, backends, integrations |

### Phone / another PC on the same Wi‑Fi

1. Run `.\start_lan.cmd` (Windows) or `bash start_lan.sh` (Linux/macOS).
2. Open the printed `http://192.168.x.x:8080` URL on the other device.
3. If it fails on Windows, allow **TCP 8080** on Private networks.

LAN mode binds `0.0.0.0`, keeps workspace data across restarts, and is for **trusted private networks only**.

### Password login (secured lab)

```powershell
.\scripts\enable_secure_mode.cmd
.\start.cmd
```

Enables auth, disables public registration, binds localhost, prints an `admin` password once.

---

## Host agents (Windows / Linux / macOS)

Separate from the server EXE. Agents check in with real host telemetry over the Agent Gateway (WebSocket, with HTTP fallback).

**Primary path: download a package** (`.exe` / `.zip` / `.tar.gz` — installers are *inside* the archive). Do not download three raw `install_agent_*` scripts as the normal UX.

**Build packages** (from repo root, developers/CI):

```powershell
python scripts/build_agent_packages.py
```

Output: `dist/agent-packages/`

| Artifact | Notes |
|----------|--------|
| `*-windows-x64.exe` / `.zip` | Built on Windows or CI; zip embeds `install.ps1` |
| `*-linux-x64.tar.gz` | Native on Linux/CI; portable layout from Windows (embeds `install.sh`) |
| `*-macos-*.tar.gz` | Portable anywhere; native binary on macOS/CI |
| `*-macos-*.dmg` | **macOS or CI `macos-latest` only** |

**Enroll and run**

1. Start SecuraIQ (`SecuraIQ.exe` or `.\start.cmd`).
2. **Agents** → **Enroll** → copy the one-time token.
3. Download the package for that OS from the Agents page (`GET /api/agents/packages`).
4. Windows: run the `.exe` with `--server` / `--token`, or unzip and `.\install.ps1 -Server … -Token …`.
5. Linux/macOS: extract the tarball and `sudo ./install.sh --server … --token …`.
6. Within ~60s the agent should show **online**.

`scripts/install_agent_*.ps1|sh` and `GET /api/agents/install-script/*` remain as **developer fallback** only (labs without a built package).

Full steps: [`scripts/packaging/QUICKSTART.md`](scripts/packaging/QUICKSTART.md)  
CI: [`.github/workflows/agent-packages.yml`](.github/workflows/agent-packages.yml)

---

## Optional: AI chat

Without a model, scanning still works. For chat:

| Backend | How |
|---------|-----|
| **Ollama** (recommended local) | Install Ollama → `ollama pull mistral` → `.\scripts\use_ollama.cmd` or Settings |
| **LM Studio** | Start local server → `.\scripts\use_lmstudio.ps1` |
| **Cloud keys** | Settings → OpenAI / OpenRouter / Groq / … |

More: [`docs/ai-router.md`](docs/ai-router.md), [`docs/cursor-local-models.md`](docs/cursor-local-models.md)

---

## Scan pipeline (what “done” means)

```text
Authorize + scope → job queue → scanner → evidence files →
assets + findings → risk → report → Ask AI (from evidence only)
```

- **Built-in web scanner** works without ZAP. Optional ZAP daemon on port **8090** for deeper spider/active scan (`ZAP_PREFER_API=true`).
- **Nmap on Windows** needs Nmap **and** Npcap.
- Evidence: `data/evidence/scans/<scan_id>/`
- Do not claim full “automated pentest” for customers until you can demo this path on a lab you own.

---

## Lab defaults vs keep data

| Setting | Typical lab | Meaning |
|---------|-------------|---------|
| `HOST` | `127.0.0.1` | Localhost only (`start_lan` uses `0.0.0.0`) |
| `AUTH_ENABLED` | `false` | Open on localhost |
| `WORKSPACE_ZERO_START` | often `true` on localhost | Empty live workspace each start; scans archived first |
| `ALLOW_OPEN_LAN` | `false` | Must be `true` for phone access when auth is off |

Set `WORKSPACE_ZERO_START=false` (or use LAN / secured scripts) to keep live assets and findings across restarts.

---

## Verify install

With the server running:

```powershell
.\.venv\Scripts\python scripts\smoke_test.py
.\.venv\Scripts\python scripts\check_openapi_gets.py
```

```bash
.venv/bin/python scripts/smoke_test.py
.venv/bin/python scripts/check_openapi_gets.py
```

Offline tests: `.venv/bin/python -m pytest tests/ -q`  
API docs: http://127.0.0.1:8080/docs

---

## Project layout

```text
app/           FastAPI backend
static/        Web UI
scripts/       Start helpers, packaging, smoke checks
data/          Runtime DB, evidence, archive, RAG
docs/          Manuals and runbooks
```

---

## More docs

| Doc | Topic |
|-----|--------|
| [`docs/user-manual.md`](docs/user-manual.md) | End-user guide |
| [`docs/scan-engine.md`](docs/scan-engine.md) | Scanners |
| [`docs/compliance-platform.md`](docs/compliance-platform.md) | Compliance / continuous tests |
| [`docs/enterprise-integrations.md`](docs/enterprise-integrations.md) | Connectors |
| [`docs/security-baseline.md`](docs/security-baseline.md) | Hardening |
| [`docs/production-readiness.md`](docs/production-readiness.md) | Production gate |
| [`docs/backup-dr.md`](docs/backup-dr.md) | Backup / restore |
| [`scripts/packaging/QUICKSTART.md`](scripts/packaging/QUICKSTART.md) | Agent install |

Cursor rule for authorized-only work: [`.cursor/rules/authorized-security-assistant.mdc`](.cursor/rules/authorized-security-assistant.mdc)

---

## License / use

Authorized security work only. Do not use this project for unauthorized access, malware deployment, or credential theft.
