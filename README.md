# SecuraIQ

**Continuous Security, Risk & Compliance Control Plane**

Authorized labs, owned systems, and enterprise blue-team / GRC workflows. Scans, agents, risk, continuous control testing, evidence, and optional local AI — without inventing “certified compliant” from a score.

> **Authorized use only** — labs, VMs, CTFs (HTB / THM / PortSwigger), or systems you own and are allowed to test.

**Public repo:** https://github.com/nrbns/SecuralQ  

**Product gate:** [`docs/production-readiness.md`](docs/production-readiness.md) · **Architecture:** [`docs/securaiq-architecture.md`](docs/securaiq-architecture.md) · **Roadmap:** [`docs/control-plane-roadmap.md`](docs/control-plane-roadmap.md)

---

## Operating loop

```text
DISCOVER → OBSERVE → DETECT → UNDERSTAND → PRIORITIZE
        → SIMULATE → REMEDIATE → VERIFY → PROVE
        → COMPLIANCE / RISK UPDATED
```

Day-one path on a lab you own:

```text
Scope → New scan → Findings → Remediate → Verify → Report / evidence
```

AI may recommend. It must not claim a fix succeeded unless the platform executed and verified it.

---

## What you get today

| Area | What it does |
|------|----------------|
| **Scans** | Web (public URLs) and Network stay separate · Nmap / Nuclei / built-in DAST · optional ZAP |
| **Operations** | Assets, vulnerabilities, incidents, remediations, playbooks |
| **Compliance** | Frameworks, gap analysis, continuous control checks → remediations + evidence |
| **Reports** | PDF / DOCX / Excel · archived scan Markdown + PDF |
| **Agents** | Lab: `scripts/securaiq_agent.py` · Production direction: Rust core [`securaiq-agent/`](securaiq-agent/README.md) · enroll · realtime gateway |
| **AI Analyst** | Optional chat (Ollama, LM Studio, or API keys) grounded on evidence |

**Scans and reports work with no AI installed.** Chat needs a model backend.

Do **not** rebuild these from scratch — close P0 platform gaps (tenancy, agent security, event pipeline, evidence→verify, load honesty). See the [control-plane roadmap](docs/control-plane-roadmap.md).

---

## Install

### End users (Windows package — recommended)

No Python on the target PC. On a build machine with `.venv`:

```powershell
.\build_exe.cmd
```

Copy `dist\SecuraIQ.exe` anywhere and double-click → **http://127.0.0.1:8080**. Data and `.env` live next to the EXE.

Host agents: `dist\agent-packages\` (see [Host agents](#host-agents-windows--linux--macos)).

### Developers (source)

#### Requirements

- [Python 3.11+](https://www.python.org/downloads/) on PATH  
- Internet once for `pip`  
- Optional: [Nmap](https://nmap.org/download.html) (+ [Npcap](https://npcap.com) on Windows), [Ollama](https://ollama.com)

Start scripts copy `.env.example` → `.env`. Tune keys later in **Settings**.

#### Windows

```powershell
git clone https://github.com/nrbns/SecuralQ.git
cd SecuralQ
.\run_proper.cmd
```

Later: `.\start.cmd` · LAN: `.\start_lan.cmd` · secure login: `.\scripts\enable_secure_mode.cmd`

#### Linux / macOS

```bash
git clone https://github.com/nrbns/SecuralQ.git
cd SecuralQ
bash scripts/run_proper.sh
# later: bash scripts/start.sh
# LAN:   bash start_lan.sh
```

#### Manual / Docker

```bash
git clone https://github.com/nrbns/SecuralQ.git
cd SecuralQ
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt   # Windows: .\.venv\Scripts\python ...
.venv/bin/python run.py
```

```bash
export BOOTSTRAP_ADMIN_PASSWORD='your-strong-password'
docker compose up --build
```

Sign in as `admin`. Optional: `INSTALL_ZAP=false`, `--profile vectors` for Qdrant.

Open **http://127.0.0.1:8080**

---

## Use (first 10 minutes)

1. Open **http://127.0.0.1:8080**
2. **New scan** → owned target → **Web** or **Network** (separate) → authorize → Start
3. Review **Overview** / **Assets** / **Vulnerabilities** (live SSE)
4. **Scans** for Markdown + PDF; archive/clear when needed
5. **Compliance Center** / **Frameworks** for posture and continuous failures → Fix
6. **Agents** to enroll packaged hosts

| Nav | Purpose |
|-----|---------|
| **Overview** | KPIs, what to fix first |
| **Assets / Vulnerabilities** | Inventory and findings |
| **Agents** | Packages + fleet online |
| **Compliance / Frameworks** | Posture, gaps, continuous tests |
| **Scans** | Exports + archives |
| **Automation** | Live job queue |
| **AI Analyst** | Evidence-grounded chat |
| **Settings** | Keys, backends, integrations |

Manual: http://127.0.0.1:8080/manual/ · [`docs/user-manual.md`](docs/user-manual.md)

---

## Host agents (Windows / Linux / macOS)

```powershell
python scripts/build_agent_packages.py
```

Artifacts: `dist/agent-packages/`

| Artifact | Notes |
|----------|--------|
| `*-windows-x64.exe` / `.zip` | Windows / CI |
| `*-linux-x64.tar.gz` | Linux native or portable |
| `*-macos-*.tar.gz` / `.dmg` | DMG needs macOS/CI |

Enroll in **Agents** → set `SECURAIQ_SERVER` + `SECURAIQ_TOKEN` → start package. Details: [`scripts/packaging/QUICKSTART.md`](scripts/packaging/QUICKSTART.md)

---

## Optional AI

| Backend | How |
|---------|-----|
| Ollama | `ollama pull mistral` → Settings / `.\scripts\use_ollama.cmd` |
| LM Studio | Local server → Settings |
| Cloud | Settings → API keys |

[`docs/ai-router.md`](docs/ai-router.md)

---

## Honesty rules

- Web scans target **public web** URLs; network discovery is a **separate** engine — no silent internal mix-in.
- Compliance scores **assess**; they do **not** certify.
- Do not claim “N thousand agents” without measured load results ([production-readiness](docs/production-readiness.md)).

---

## Verify

```powershell
.\.venv\Scripts\python scripts\smoke_test.py
.\.venv\Scripts\python scripts\check_openapi_gets.py
```

API docs: http://127.0.0.1:8080/docs

---

## Docs

| Doc | Topic |
|-----|--------|
| [`docs/control-plane-roadmap.md`](docs/control-plane-roadmap.md) | P0 / P1 / P2 product direction |
| [`docs/production-readiness.md`](docs/production-readiness.md) | Ship / don’t-ship gate |
| [`docs/compliance-platform.md`](docs/compliance-platform.md) | Continuous compliance |
| [`docs/scan-engine.md`](docs/scan-engine.md) | Scanners |
| [`docs/security-baseline.md`](docs/security-baseline.md) | Hardening |
| [`docs/backup-dr.md`](docs/backup-dr.md) | Backup / restore |

---

## License / use

Authorized security work only. Do not use for unauthorized access, malware deployment, or credential theft.
