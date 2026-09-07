# SecuraIQ User Manual

Authorized AI Security OS for labs, owned systems, CTFs, blue-team workflows, and GRC — not a general chatbot and not for unauthorized access.

**Open the app:** [http://127.0.0.1:8080](http://127.0.0.1:8080)
**In-app copy:** [/manual/](/manual/) (when the server is running)

---

## 1. What SecuraIQ is for

| Use | Examples |
|-----|----------|
| Posture & decisions | Mission Control score, morning brief, work queue |
| Vuln workflow | Import scan → triage → Jira → verify → close |
| Compliance & risk | Frameworks, gap analysis, evidence, risk register |
| Continuous monitoring | Native agents + SecuraIQ Sentinel — real-time threat detection like Wazuh/EDR, install-free |
| AI assistance | Floating assistant or AI Workspace (agents first) |
| Labs / CTF | Local tools, authorized target probe, playbooks |

**Not for:** malware distribution, credential theft, C2, or attacking systems you do not own or have written permission to test.

---

## 2. Start the application

### Run from source (Windows / Linux / macOS)

No manual `.env` setup is required. The scripts create `.venv`, install deps, and copy `.env.example` → `.env` if needed. Optional keys (models, Jira, Wazuh, network inventory) can be set later in **Settings**.

**Windows:**
```powershell
.\scripts\run_proper.ps1
```
Already installed once? `.\scripts\start.ps1`

**Linux / macOS:**
```bash
bash scripts/run_proper.sh
```
Already installed once? `bash scripts/start.sh`

Then open **http://127.0.0.1:8080**.

### Run as a standalone Windows app (no Python install needed)

`build_exe.cmd` (or `scripts\build_exe.ps1`) packages the whole app — including the bundled RAG knowledge base, compliance frameworks, and native-agent install scripts — into a single **SecuraIQ.exe**. Double-click it; there's nothing else to install alongside it. First launch is slower than later ones (the bundle unpacks to a temp folder before the server starts); `.env` and your data are created next to wherever you put the exe. This has to be built on a Windows machine — PyInstaller doesn't cross-compile.

### Models

Use Settings or the Advanced model routing panel to pick **Ollama**, **LM Studio**, or another configured backend. Pull a small model first (for example `ollama pull tinyllama`) so chat works offline.

---

## 3. Five pillars (sidebar)

1. **Mission Control** — morning brief, KPIs, charts, heat map, MITRE coverage, work queue
2. **AI Workspace** — full chat, canvas, memory, files, tools, automation tab
3. **Security Operations** — assets, vulnerabilities, agents, threat intel, incidents, playbooks, campaigns
4. **Compliance & Risk** — frameworks, gap analysis, controls, evidence, policies, risk register, knowledge graph
5. **Automation** — visual golden-path workflow, jobs, triggers, reports

Collapsed groups: **Cloud & Development**, **Administration** (orgs, integrations, billing, settings, account).

---

## 4. AI Assistant (floating)

On Mission Control and module pages the bottom chat bar is replaced by a bottom-right **AI Assistant** button.

| Action | Result |
|--------|--------|
| Click **Assistant** | Opens the floating panel |
| Use action chips | Executive Summary, Root Cause, Attack Path, Ticket, Report, Fix, Playbook, Investigation |
| **Ask AI** on a finding | Fills the assistant without leaving the page |
| **Workspace** | Opens the full AI Workspace |
| **Close** or `Esc` | Closes the panel |

Choose an **Agent persona** (SOC Analyst, Compliance Officer, …). Model backend/name stay under **Advanced model routing**. (This is a different concept from the *native monitoring agents* in section 6 below — same word, unrelated feature.)

---

## 5. Golden path (recommended daily flow)

```
Import scan  →  AI triage  →  Assign / Jira  →  Evidence  →  Report
```

1. **Vulnerabilities** → **Import scan** (Trivy, Semgrep, Gitleaks, Nessus, etc.) — or let a native agent or built-in scan create findings automatically
2. Select a finding → review the right-hand detail panel
3. **Triage** or **Triage+Jira**
4. Attach **Evidence** and track **Remediations**
5. Export from **Reports** (Markdown / PDF where enabled)
6. Check **Mission Control** workflow counters and morning brief

Findings, remediations, and gap assessments can all be **deleted** from their detail views when they were created in error — each delete is a real destructive action (confirmation required) and updates every connected view immediately.

---

## 6. Native agents & SecuraIQ Sentinel (continuous monitoring)

SecuraIQ can monitor your own servers continuously, the same way a Wazuh or EDR agent does — no external product required.

### Enrolling a server

1. Go to **Security Operations → Agents** and click **Enroll agent**.
2. You'll get a one-time install command and token — save it, it's shown only once.
3. Install it on the target as a **persistent service** (recommended — starts on boot, restarts if it crashes):

   | Platform | Install command |
   |----------|------------------|
   | Linux | `sudo ./install_agent_linux.sh --server <url> --token <token>` (systemd) |
   | macOS | `sudo ./install_agent_macos.sh --server <url> --token <token>` (launchd) |
   | Windows | `.\install_agent_windows.ps1 -Server <url> -Token <token>` (elevated PowerShell — runs as a Scheduled Task at startup under SYSTEM) |

   Or run it in the foreground once for testing: `python securaiq_agent.py --server <url> --token <token>`.

The agent prefers a persistent **WebSocket** to `/api/agents/ws` (instant command push + heartbeat). If the gateway is unavailable it falls back to HTTP check-in and long-poll (`POST /api/agents/gateway/wait`). Use `--no-websocket` to skip WS.

The install scripts and the agent script itself are served directly by the app (`/api/agents/install-script` and `/api/agents/install-script/{linux|macos|windows}`) — nothing to download separately.

### What the agent reports

Every check-in (default: every 60s) sends real host telemetry: hostname, OS, listening ports, installed packages. This keeps the **Assets** inventory and the agent's online/offline status current — an agent that stops checking in genuinely goes "offline" after missing a couple of intervals, not held at a fake "online" state.

### SecuraIQ Sentinel — the real-time threat detection engine

Independently of check-ins, each agent runs a background watcher (default: every 10s) that fuses four detection techniques:

1. **Signature matching** — known-bad file hashes (SHA-256)
2. **Behavioral heuristics** — suspicious process names, command lines, and parent/child relationships (e.g. Office spawning a shell)
3. **Ransomware indicators** — mass file renames to known ransom-note names/extensions
4. **File-integrity monitoring (FIM)** — a persisted baseline of watched directories; new hashes on first run establish the baseline silently (no false alerts), then every scan diffs against it and reports genuine adds/modifications/deletions

A detection immediately: creates a linked finding in **Vulnerabilities** (so it shows up on the asset), opens a **SOC incident** for critical/high severity, and pushes a live toast + realtime update to every connected browser — no page refresh needed. Repeat sightings of the same ongoing issue are deduplicated (re-alerts at most every 30 minutes) so a persistent problem doesn't spam your feed.

The **Agents** panel shows a status badge per agent (based on its most severe recent detection) and a live "SecuraIQ Sentinel — recent detections" feed underneath the agent table.

### Removing an agent

**Revoke** invalidates its token immediately (it can no longer check in) without losing history. **Delete** removes the agent record entirely — a real destructive action with confirmation.

---

## 7. Module guides

### Mission Control

- Greeting + AI morning summary
- Security score, compliance, critical/high, incidents, assets
- Severity / asset / integration charts, risk heat map, MITRE strip
- Work queue with Ask AI / open actions

### Vulnerabilities

- Filters: search, severity, status, scanner, owner
- Table: CVE, severity, CVSS, asset, owner, status, SLA, age, scanner
- Detail panel: AI summary actions, references, triage / Jira / close / **delete**

### Web URL Scan (dedicated page)

A focused page (separate from the general "New scan" modal) for scanning a **public web app**: security headers, TLS, cookie flags, sensitive-path exposure, CORS, reflected-input and open-method checks, depending on the depth you pick. It's install-free — no ZAP daemon required.

This tool is scoped to public-facing web apps only: it rejects loopback, private (RFC1918), link-local, and `.local`/`.internal`-style targets before scanning (this also closes an SSRF path where a "web scan" could otherwise be pointed at internal services). To assess your own internal hosts, use a network/VAPT scan from **New scan** instead — that one is designed for private IP ranges.

### Compliance & frameworks

- KPI strip: implemented / partial / missing / coverage / evidence / maturity
- Framework cards → **Open controls** → evidence, owner, risk, status
- **Run gap** for ISO / NIST / CIS-style assessments
- **Delete assessment** removes it and cascades to its generated remediation tasks — confirmation required

### Assets

- Class tiles (server, endpoint, container, cloud, repo, database, app, domain, API)
- Inventory table (name, IP, type, owner) with Ask AI per asset
- Assets created/updated automatically by native-agent check-ins and by scan results
- Optional **Sync inventory** pulls discovered hosts into the same list (Settings → Network inventory)

### Frameworks / Windows hardening

- Gap analysis against ISO / NIST / CIS Controls catalogs
- **HardeningKitty** panel: install via `.\scripts\use_hardeningkitty.cmd -Download`, then **Run HardeningKitty audit** (Audit mode) or import a report CSV
- Official CIS Benchmarks / CIS-CAT: [CIS Downloads](https://downloads.cisecurity.org/#/) (account required)
- HailMary (apply hardening) is **not** exposed in SecuraIQ — use PowerShell on owned hosts after backup ([HardeningKitty](https://github.com/scipag/HardeningKitty))

### Automation

- Visual pipeline: Trigger → Scan → AI → Risk → Approval → Ticket → Notify → Close
- Jobs and webhook pointers → Integrations

### Knowledge graph

- Correlated assets, vulns, risks, controls, incidents for attack-path questions
- Interactive force-graph viz is still evolving; lists and Ask AI paths work today

### XDR / EDR connectors

Live and near-real-time feeds from CrowdStrike (streaming), Sophos, SentinelOne, and Microsoft Defender surface into the same SOC/incident views as everything else — configure credentials in **Integrations**; each connector is a no-op until you do.

### Integrations

- Connect scanners (Trivy, Semgrep, …), Jira, Slack webhooks, XDR/EDR vendors, cloud stubs
- Inbound webhook receivers accept pushes from external XDR/EDR/SIEM tools too
- Prefer **Connect** paths that open import/settings rather than fake "connected" badges

### Reports

- Executive / technical / risk / vuln exports
- Use AI **Generate Report** for narrative drafts, then export

### Administration

- Organizations & members (when auth is on)
- Settings: API keys, theme, model backends
- Account: login / register when `AUTH_ENABLED=true`
- Billing & audit (admin) as configured

---

## 8. Global search & notifications

- Top search: assets, risks, vulns, controls — or ask AI if nothing matches
- Notifications badge routes toward SOC / tasks
- Nearly everything above updates **live**: scans, findings, agent check-ins, Sentinel detections, incidents, and remediations push to every open browser tab over a realtime connection — you generally don't need to refresh to see new activity.

---

## 9. Tools & authorized probing

In the assistant or AI Workspace:

- Enable **Tools** / open the **Tools** palette
- Set a **lab/owned Target IP** and check **Auth** before probe-style tools
- Built-ins (DNS, ports, HTTP, headers) work without extra installs; PATH tools appear when installed

---

## 10. Auth, projects, theme

| Topic | How |
|-------|-----|
| Auth off | Local open mode (default for solo lab use) |
| Auth on | `AUTH_ENABLED=true` — Account → login/register |
| Project / engagement | Sidebar **Project** selector + **+ New** |
| Theme | Sidebar theme toggle (light/dark) |
| Uploads | Upload evidence / RAG files from sidebar or AI Files tab |

---

## 11. Safety & legal

- Authorized labs, HTB/THM-style ranges, PortSwigger, and systems you own or have written permission to test only
- The Web URL Scan tool refuses internal/private targets by design (see section 7) — it cannot be used to probe infrastructure it wasn't meant to reach
- Draft legal pages: [/legal/](/legal/)
- AI can be wrong — verify remediations and tickets before production change

---

## 12. Troubleshooting

| Symptom | Try |
|---------|-----|
| Page looks old | Hard refresh (`Ctrl+F5`) |
| Chat fails | Check Ollama/LM Studio is running; Settings → backend/model |
| Empty Mission Control | Import a scan, run gap analysis, or enroll an agent |
| Jira fails | Configure Jira in Settings / env; use Triage without Jira first |
| Web scan rejects my target | It only accepts public web targets by design — see section 7; use a network/VAPT scan for internal hosts |
| Agent shows offline | It hasn't checked in for ~3 intervals (default ~3 min); confirm the service is running on the host and the token/server URL are correct |
| Port in use | Change `PORT` in `.env` or stop the other process |

Developer docs: [README](../README.md), [enterprise integrations](enterprise-integrations.md), [AI router](ai-router.md), [launch readiness](launch-readiness.md), [scan engine](scan-engine.md).
