/* Remaining Command Center workspaces: modules tables, intel, reports, SOC, evidence, AI tabs */
(function () {
  const qs = (id) => document.getElementById(id);

  function authHeaders(extra) {
    if (typeof window.authHeaders === "function") return window.authHeaders(extra || {});
    const h = Object.assign({}, extra || {});
    const t = localStorage.getItem("securaiq.auth.token");
    if (t) h.Authorization = `Bearer ${t}`;
    return h;
  }

  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // Maintenance windows are stored and evaluated server-side in UTC (the
  // right call — the server may serve viewers in many timezones, so UTC is
  // the only unambiguous ground truth). This just renders the equivalent
  // local-time range next to it so a viewer isn't stuck doing UTC math in
  // their head. Purely a display convenience — never sent back to the API.
  function _utcHourRangeToLocal(startHour, endHour) {
    try {
      const now = new Date();
      const fmt = (h) => {
        const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), h, 0, 0));
        return d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
      };
      return `${fmt(startHour)}–${fmt(endHour)}`;
    } catch (e) {
      return "";
    }
  }

  async function createServiceNowIncident({ summary, description, remediationId }, btn) {
    if (btn) btn.disabled = true;
    try {
      const res = await fetch("/api/integrations/servicenow/incident", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          short_description: summary,
          description: description || "",
          remediation_id: remediationId || undefined,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      const msg = data.url
        ? `**ServiceNow:** [${data.number || data.sys_id || "incident"}](${data.url})`
        : `**ServiceNow:** ${data.number || data.sys_id || "created"}`;
      if (typeof notifyUser === "function") notifyUser(msg);
      else if (typeof appendMessage === "function") appendMessage("assistant", renderMarkdown(msg), true);
      return data;
    } catch (err) {
      const msg = `**ServiceNow failed:** ${err.message}`;
      if (typeof notifyUser === "function") notifyUser(msg);
      else if (typeof appendMessage === "function") appendMessage("assistant", renderMarkdown(msg), true);
      else alert(err.message);
      return null;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function downloadApiExport(url, filename) {
    const res = await fetch(url, { headers: authHeaders() });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || `HTTP ${res.status}`);
    }
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function hideAllViews() {
    document.querySelectorAll(".workspace-view").forEach((el) => el.classList.add("hidden"));
  }

  function setComposerMode(view) {
    const wrap = qs("composerWrap");
    const fab = qs("aiFab");
    if (!wrap) return;
    const isChat = view === "chat";
    const isCommand = view === "command";
    const isPage = !isChat && !isCommand;
    wrap.classList.toggle("is-command", isCommand);
    wrap.classList.toggle("is-page", isPage);
    wrap.classList.toggle("is-chat", isChat);
    wrap.classList.toggle("is-floating", !isChat);
    if (isChat) {
      wrap.classList.remove("is-open");
      document.getElementById("aiAssistThread")?.classList.add("hidden");
      fab?.classList.add("hidden");
      fab?.setAttribute("aria-expanded", "false");
    } else {
      // Docked footer becomes FAB + floating panel so modules keep full canvas.
      if (!wrap.classList.contains("is-open")) fab?.classList.remove("hidden");
    }
  }

  function openFloatingAssistant() {
    if (typeof window.openAiAssistant === "function") window.openAiAssistant();
  }

  function wireAskAiButtons(rootId) {
    qs(rootId)?.querySelectorAll(".ws-ask-ai").forEach((btn) => {
      btn.addEventListener("click", () => {
        let payload = {};
        try {
          payload = JSON.parse(btn.getAttribute("data-json") || "{}");
        } catch (e) {}
        if (typeof window.askAboutEntity === "function") {
          window.askAboutEntity(btn.getAttribute("data-kind"), payload);
        }
      });
    });
  }

  function setPageComposerHint(view) {
    const input = qs("input");
    const wrap = qs("composerWrap");
    if (!input || !wrap) return;
    const hints = {
      assets: "Ask AI about an asset, or type a hardening question…",
      software: "Ask about outdated software, patch gaps, or EOL services on scanned hosts…",
      risks: "Ask AI to prioritize risks or draft mitigations…",
      vulns: "Ask AI to triage a CVE, or paste scan findings…",
      remediations: "Ask AI for control implementation guidance…",
      soc: "Ask AI for IR steps on an incident…",
      intel: "Ask AI for a threat brief on a CVE or IOC…",
      reports: "Ask AI to draft an executive or technical report…",
      webscan: "Ask AI about a web finding, or paste a URL to scan…",
      evidence: "Ask AI what evidence is missing for an audit…",
      playbooks: "Ask AI to expand or tabletop a playbook…",
      campaigns: "Ask AI to design an awareness campaign…",
      orgs: "Ask about RBAC / tenancy for your engagement…",
    };
    if (view === "chat") {
      input.placeholder = "Issue a control query…";
      wrap.classList.remove("is-page-context");
    } else if (hints[view]) {
      input.placeholder = hints[view];
      wrap.classList.add("is-page-context");
    } else {
      input.placeholder = "Issue a control query…";
      wrap.classList.remove("is-page-context");
    }
  }

  window.showWorkspace = function showWorkspace(view, opts) {
    opts = opts || {};
    hideAllViews();
    const map = {
      command: "viewCommand",
      chat: "viewChat",
      assets: "viewAssets",
      software: "viewSoftware",
      risks: "viewRisks",
      vulns: "viewVulns",
      remediations: "viewRemediations",
      playbooks: "viewPlaybooksPage",
      campaigns: "viewCampaignsPage",
      intel: "viewIntel",
      reports: "viewReports",
      webscan: "viewWebscan",
      soc: "viewSoc",
      evidence: "viewEvidence",
      orgs: "viewOrgs",
      frameworks: "viewFrameworks",
      integrations: "viewIntegrations",
      billing: "viewBilling",
      graph: "viewGraph",
      automation: "viewAutomation",
    };
    const id = map[view] || "viewCommand";
    const panel = qs(id);
    if (panel) panel.classList.remove("hidden");
    if (view === "chat" || view === "command") {
      if (typeof showView === "function") showView(view, opts);
      setPageComposerHint(view);
      return;
    }
    if (typeof window.__setSecuraIQView === "function") window.__setSecuraIQView(view);
    setComposerMode(view);
    setPageComposerHint(view);
    document.querySelectorAll(".nav-item[data-view], .nav-link[data-workspace]").forEach((el) => {
      const v = el.getAttribute("data-view") || el.getAttribute("data-workspace");
      el.classList.toggle("active", v === view);
    });
    const title = qs("topbarChatTitle");
    if (title) {
      const labels = {
        command: "Command Center",
        chat: "AI Assistant",
        assets: "Assets",
        software: "Software inventory",
        risks: "Risk Register",
        vulns: "Vulnerabilities",
        remediations: "Remediations",
        playbooks: "Playbooks",
        campaigns: "Campaigns",
        intel: "Threat Intelligence",
        reports: "Reports",
        webscan: "Web URL Scan",
        soc: "SOC",
        evidence: "Evidence Locker",
        orgs: "Organizations",
        frameworks: "Frameworks",
        integrations: "Integrations",
        billing: "Billing",
        graph: "Knowledge Graph",
        automation: "Automation",
      };
      title.textContent = labels[view] || "SecuraIQ";
    }
    window.__securaiqWorkspaceView = view;
    if (view === "command" && typeof loadCommandCenter === "function") loadCommandCenter();
    if (view === "chat" && typeof syncEmptyState === "function") syncEmptyState();
    if (view === "assets") renderAssetsPage();
    if (view === "software") renderSoftwarePage();
    if (view === "risks") renderRisksPage();
    if (view === "vulns") renderVulnsPage();
    if (view === "remediations") renderRemsPage();
    if (view === "playbooks") renderPlaybooksPage();
    if (view === "campaigns") renderCampaignsPage();
    if (view === "intel") renderIntelPage();
    if (view === "reports") renderReportsPage();
    if (view === "webscan") renderWebScanPage();
    if (view === "soc") renderSocPage();
    if (view === "evidence") renderEvidencePage();
    if (view === "orgs") renderOrgsPage();
    if (view === "frameworks") {
      renderHardeningPanel();
      renderFrameworksPage();
    }
    if (view === "integrations") renderIntegrationsPage();
    if (view === "billing") renderBillingPage();
    if (view === "graph") renderGraphPage();
    if (view === "automation") renderAutomationPage();
    if (typeof closeSidebar === "function") closeSidebar();
  };

  // Do not override showView — app.js owns chat/command; we extend via showWorkspace + nav.
  async function renderTable(targetId, headers, rowsHtml, emptyText) {
    const el = qs(targetId);
    if (!el) return;
    if (!rowsHtml) {
      el.innerHTML = `<div class="page-empty">
        <p class="page-empty-title">${escapeHtml(emptyText || "Nothing here yet")}</p>
        <p class="hint">Starts empty — add data when you’re ready.</p>
      </div>`;
      return;
    }
    el.innerHTML = `
      <div class="data-table-wrap">
        <table class="data-table">
          <thead><tr>${headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>`;
  }

  async function syncInventory() {
    const btn = qs("oaSyncBtn");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Syncing…";
    }
    try {
      await refreshLanAssets({ scans: false, silentBtn: true });
      const stRes = await fetch("/api/openaudit/status", { headers: authHeaders() }).catch(() => null);
      const st = stRes ? await stRes.json().catch(() => ({})) : {};
      if (st.configured) {
        const res = await fetch("/api/openaudit/sync", { method: "POST", headers: authHeaders() });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          if (typeof notifyUser === "function") notifyUser(`**Open-AudIT sync failed:** ${data.detail || res.status}`);
        } else {
          const jobId = data.job && data.job.id;
          if (typeof notifyUser === "function") {
            notifyUser(`**Open-AudIT appliance sync queued** · job \`${jobId || "?"}\``);
          }
          if (jobId && typeof window.waitForJob === "function") {
            const job = await window.waitForJob(jobId, { timeoutMs: 120000 });
            const r = job?.result || {};
            if ((job?.status || "") === "done" && typeof notifyUser === "function") {
              notifyUser(
                `**Open-AudIT sync done** · ${r.devices_total || 0} devices · ${r.devices_new || 0} new`
              );
            }
          }
        }
      }
    } catch (err) {
      if (typeof notifyUser === "function") notifyUser(`**Inventory sync error:** ${err.message || err}`);
    }
    renderAssetsPage();
    if (typeof loadCommandCenter === "function") loadCommandCenter();
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Sync inventory";
    }
  }

  function setAssetsScanLive(text, show) {
    const live = qs("assetsScanLive");
    if (!live) return;
    live.hidden = !show;
    live.textContent = text || "";
  }

  function inventorySourceKind(item) {
    const blob = `${item.source || ""} ${item.notes || ""} ${item.os || ""}`.toLowerCase();
    if (item._oa || /openaudit|open.?audit|securaiq_audit/.test(blob)) return "audit";
    return "scan";
  }

  function displayAssetLabel(item) {
    if (!item) return "—";
    const dn = item.display_name || item.displayName;
    if (dn) return String(dn).split(" · ")[0];
    const name = String(item.name || item.asset_name || "").trim();
    const ip = String(item.ip || "").trim();
    const host = String(item.hostname || "").trim();
    if (host && ip && host !== ip) return `${host} (${ip})`;
    if (name && /^\d+\.\d+\.\d+\.\d+$/.test(name) && host) return `${host} (${name})`;
    if (name && !/^\d+\.\d+\.\d+\.\d+$/.test(name)) return name;
    return ip || host || name || "device";
  }

  window.displayAssetLabel = displayAssetLabel;

  const ASSET_CATEGORY_LABELS = {
    server: "Server",
    computer: "Computer",
    endpoint: "Endpoint",
    mobile: "Mobile",
    network: "Network",
    printer: "Printer",
    iot: "IoT",
    database: "Database",
    web: "Web app",
    cloud: "Cloud",
    container: "Container",
    code: "Code",
    other: "Other",
  };
  window.ASSET_CATEGORY_LABELS = ASSET_CATEGORY_LABELS;
  window.__inventoryCategoryFilter = window.__inventoryCategoryFilter || "";

  function assetCategoryId(item) {
    return String(item?.asset_category || item?.asset_type || item?.type || "other").toLowerCase();
  }

  function displayCategoryLabel(item) {
    const id = assetCategoryId(item);
    return item?.category_label || ASSET_CATEGORY_LABELS[id] || id.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function categoryChipHtml(item, { clickable = false, active = false } = {}) {
    const id = assetCategoryId(item);
    const label = displayCategoryLabel(item);
    const cls = `category-chip category-${escapeHtml(id)}${active ? " is-active" : ""}${clickable ? " category-chip-btn" : ""}`;
    if (clickable) {
      return `<button type="button" class="${cls}" data-category="${escapeHtml(id)}">${escapeHtml(label)}</button>`;
    }
    return `<span class="${cls}">${escapeHtml(label)}</span>`;
  }

  window.displayCategoryLabel = displayCategoryLabel;
  window.categoryChipHtml = categoryChipHtml;

  function inventoryLiveLabel(item) {
    const blob = `${item.source || ""} ${item.notes || ""}`.toLowerCase();
    if (/openaudit/.test(blob) && !/securaiq_audit|lan_arp|live:/.test(blob) && !item._oaOnly) {
      if (item.source && /openaudit/i.test(item.source)) return "Open-AudIT";
    }
    const src = (item.source || "").split(":")[0] || "";
    if (/^zap$/i.test(src)) return "SecuraIQ Web Scanner live";
    if (/^nmap|nuclei|zap$/i.test(src)) return `${src} live`;
    return "securaiq live";
  }

  function fmtInventoryWhen(ts) {
    if (ts == null || ts === "") return "—";
    const d = new Date(typeof ts === "number" && ts < 1e12 ? ts * 1000 : ts);
    return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
  }

  function portChipsHtml(ports) {
    const list = (ports || [])
      .map((p) => String(p == null ? "" : p).trim())
      .filter(Boolean)
      .slice(0, 10);
    if (!list.length) return `<span class="hint">—</span>`;
    return `<span class="port-chips">${list
      .map((p) => `<code class="port-chip">${escapeHtml(p)}</code>`)
      .join("")}</span>`;
  }

  function inventoryRowHtml(a) {
    const ip = a.ip || "";
    const title = displayAssetLabel(a);
    const scanSt = (a.last_scan_status || "").toLowerCase();
    const isBlocked = scanSt === "blocked";
    const scanChip = scanSt
      ? `<span class="auto-job-status ${
          scanSt === "completed" ? "status-done" : isBlocked ? "status-planned" : /fail/.test(scanSt) ? "status-error" : "status-running"
        }"${
          isBlocked
            ? ` title="Scan not run — this host isn't marked authorized. Use Scan and confirm ownership to run a vulnerability scan against it."`
            : ""
        }>${escapeHtml(scanSt)}</span>`
      : `<span class="hint">idle</span>`;
    const scanTarget = ip || a.name;
    const metaBits = [a.os, a.mac].filter(Boolean);
    const extra = metaBits.length
      ? `<div class="hint">${escapeHtml(metaBits.join(" · "))}</div>`
      : "";
    const shareHint = (a.shares || []).length
      ? `<div class="hint">shares ${escapeHtml((a.shares || []).slice(0, 4).join(", "))}</div>`
      : "";
    const patch = a._patch;
    const patchSt = patch ? (patch.patch_status || "unknown").toLowerCase() : "";
    const patchCls = patchSt === "up_to_date" ? "done" : patchSt === "needs_update" ? "error" : "planned";
    const patchCell = patch
      ? `<button type="button" class="sw-status-chip status-${patchCls} ws-asset-patch" data-id="${escapeHtml(
          a.id || ""
        )}" data-name="${escapeHtml(title || a.name || "")}" title="Open software & patch details">${escapeHtml(
          patch.patch_label || patchSt || "?"
        )}</button>${
          patch.issues_count ? `<div class="hint">${Number(patch.issues_count)} issue(s)</div>` : ""
        }`
      : `<span class="hint">—</span>`;
    const canEdit = !!a.id && !a._oaOnly;
    return `<tr>
        <td><strong>${escapeHtml(title || "—")}</strong>${extra}${shareHint}</td>
        <td>${ip && ip !== title ? `<code>${escapeHtml(ip)}</code>` : `<span class="hint">—</span>`}</td>
        <td>${categoryChipHtml(a)}</td>
        <td><span class="inventory-source inventory-source-${inventorySourceKind(a)}">${escapeHtml(
          inventoryLiveLabel(a)
        )}</span></td>
        <td>${portChipsHtml(a.open_ports)}</td>
        <td>${scanChip}<div class="hint">${escapeHtml(fmtInventoryWhen(a.last_scan_at))}</div></td>
        <td>${a.findings != null ? escapeHtml(String(a.findings)) : "—"}</td>
        <td>${patchCell}</td>
        <td class="ws-actions">
          <button type="button" class="btn-primary-cc ws-scan-asset" data-target="${escapeHtml(scanTarget)}">Scan</button>
          <button type="button" class="btn-secondary ws-asset-software" data-id="${escapeHtml(a.id || "")}" data-name="${escapeHtml(
            title || a.name || ""
          )}">Software</button>
          <button type="button" class="btn-secondary ws-ask-ai" data-kind="asset" data-json="${escapeHtml(
            JSON.stringify({ id: a.id, name: a.name, asset_type: a.asset_type, criticality: a.criticality, ip })
          )}">Ask AI</button>
          ${
            canEdit
              ? `<button type="button" class="btn-secondary ws-edit-asset" data-id="${a.id}" data-name="${escapeHtml(
                  a.name || ""
                )}" data-owner="${escapeHtml(a.owner || "")}" data-crit="${escapeHtml(
                  a.criticality || "medium"
                )}" data-type="${escapeHtml(assetCategoryId(a))}">Edit</button>
          <button type="button" class="btn-secondary ws-del-asset" data-id="${a.id}">Delete</button>`
              : ""
          }
        </td>
      </tr>`;
  }

  function inventoryBlockHtml(title, items, emptyHint) {
    const rows = items.map(inventoryRowHtml).join("");
    return `<section class="inventory-block">
      <header class="inventory-block-head">
        <h2>${escapeHtml(title)}</h2>
        <span class="hint">${items.length} live</span>
      </header>
      ${
        rows
          ? `<div class="data-table-wrap"><table class="data-table"><thead><tr>
              <th>Host</th><th>IP</th><th>Category</th><th>Source</th><th>Open ports</th><th>Last scan</th><th>Findings</th><th>Patch</th><th></th>
            </tr></thead><tbody>${rows}</tbody></table></div>`
          : `<div class="page-empty"><p class="page-empty-title">No ${escapeHtml(title)} hosts yet</p><p class="hint">${emptyHint}</p></div>`
      }
    </section>`;
  }

  async function queueAssetScan(target) {
    const t = (target || "").trim();
    if (!t) return;
    window.__securaiqAssetsScanBusy = true;
    setAssetsScanLive(`Scanning ${t}…`, true);
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          target: t,
          scanner: "securaiq",
          profile: "discovery",
          authorized: true,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      if (typeof notifyUser === "function") {
        notifyUser(`**Live scan queued** · \`${t}\` · job \`${data.job_id || "?"}\``);
      }
      setAssetsScanLive(`Scan queued · ${t}`, true);
      if (data.job_id && typeof window.waitForJob === "function") {
        const job = await window.waitForJob(data.job_id, { timeoutMs: 180000 });
        const st = (job?.status || "").toLowerCase();
        if (st === "done" && typeof notifyUser === "function") {
          const r = job.result || {};
          const sum = r.summary || r;
          notifyUser(
            `**Scan done** · ${t} · ${sum.findings_created ?? sum.findings ?? 0} findings`
          );
        } else if (st === "error" && typeof notifyUser === "function") {
          notifyUser(`**Scan failed:** ${job.error || "error"}`);
        }
      }
    } catch (err) {
      if (typeof notifyUser === "function") notifyUser(`**Scan error:** ${err.message || err}`);
      setAssetsScanLive(String(err.message || err), true);
    } finally {
      window.__securaiqAssetsScanBusy = false;
      renderAssetsPage({ quiet: true });
    }
  }
  window.queueAssetScan = queueAssetScan;

  async function refreshLanAssets(opts) {
    const scans = !opts || opts.scans !== false;
    const silentBtn = !!(opts && opts.silentBtn);
    const btn = qs("assetsLanRefresh");
    if (btn && !silentBtn) {
      btn.disabled = true;
      btn.textContent = "Refreshing…";
    }
    window.__securaiqAssetsScanBusy = true;
    setAssetsScanLive(
      scans
        ? "Live inventory + VA scans on local /24…"
        : "Live Open-AudIT inventory on local /24…",
      true
    );
    try {
      const res = await fetch(`/api/assets/lan-refresh?scans=${scans ? "true" : "false"}`, {
        method: "POST",
        headers: authHeaders(),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      const queuedScans = Array.isArray(data.queued_scans) ? data.queued_scans.filter((s) => s && s.ok) : [];
      const invJob = data.inventory_job || {};
      const nHosts = 1 + (data.neighbors || []).length;
      if (typeof notifyUser === "function") {
        notifyUser(
          `**LAN ${scans ? "refresh" : "inventory"}** · subnet \`${data.subnet || "local /24"}\` · host \`${
            data.this_host || "?"
          }\` · ${data.assets_upserted || 0} assets · ${(data.neighbors || []).length} neighbors · ${
            queuedScans.length
          } VA scan(s) · inventory job \`${invJob.id || "—"}\``
        );
      }
      if (invJob.id && typeof window.waitForJob === "function") {
        setAssetsScanLive(`Live inventory · ${nHosts} host(s)…`, true);
        const job = await window.waitForJob(invJob.id, { timeoutMs: 180000 });
        const r = job?.result || {};
        if ((job?.status || "") === "done" && typeof notifyUser === "function") {
          notifyUser(
            `**Inventory done** · ${r.audited || r.hosts || nHosts} host(s) audited`
          );
        }
      }
      if (queuedScans.length) {
        setAssetsScanLive(`Queued ${queuedScans.length} LAN vulnerability scan(s)…`, true);
      }
    } catch (err) {
      if (typeof notifyUser === "function") notifyUser(`**LAN refresh failed:** ${err.message || err}`);
    } finally {
      window.__securaiqAssetsScanBusy = false;
      if (btn && !silentBtn) {
        btn.disabled = false;
        btn.textContent = "Refresh LAN";
      }
      renderAssetsPage({ quiet: true });
      if (typeof loadCommandCenter === "function") loadCommandCenter();
    }
  }

  function attachAssetPatchInfo(assets, servers) {
    const byId = {};
    const byName = {};
    (servers || []).forEach((s) => {
      const entry = {
        patch_status: s.patch_status,
        patch_label: s.patch_label,
        issues_count: s.issues_count,
      };
      if (s.asset_id) byId[s.asset_id] = entry;
      const nm = (s.asset_name || "").trim().toLowerCase();
      if (nm) byName[nm] = entry;
    });
    return assets.map((a) => {
      const label = (a.display_name || a.name || "").trim().toLowerCase();
      const patch = (a.id && byId[a.id]) || (label && byName[label]) || null;
      return patch ? { ...a, _patch: patch } : a;
    });
  }

  async function renderAssetsPage(opts) {
    const el = qs("assetsPageBody");
    if (!el) return;
    const quiet = !!(opts && opts.quiet) || !!window.__securaiqAssetsScanBusy;
    if (!quiet) el.innerHTML = `<p class="hint" aria-live="polite">Loading live inventory…</p>`;
    let data = {};
    let inv = {};
    let st = {};
    let jobsData = { jobs: [] };
    let swPosture = {};
    try {
      const [res, invRes, stRes, jobsRes, swRes] = await Promise.all([
        fetch("/api/assets", { headers: authHeaders() }),
        fetch("/api/openaudit/devices?limit=500", { headers: authHeaders() }).catch(() => null),
        fetch("/api/openaudit/status", { headers: authHeaders() }).catch(() => null),
        fetch("/api/jobs?limit=20", { headers: authHeaders() }).catch(() => null),
        fetch("/api/software/posture", { headers: authHeaders() }).catch(() => null),
      ]);
      data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `Assets failed (${res.status})`);
      inv = invRes ? await invRes.json().catch(() => ({})) : {};
      st = stRes ? await stRes.json().catch(() => ({})) : {};
      jobsData = jobsRes ? await jobsRes.json().catch(() => ({ jobs: [] })) : { jobs: [] };
      swPosture = swRes && swRes.ok ? await swRes.json().catch(() => ({})) : {};
    } catch (err) {
      el.innerHTML = `<p class="hint">Could not load assets: ${escapeHtml(err.message || String(err))}</p>`;
      return;
    }
    const assets = data.assets || [];
    const liveScans = data.live_scans || [];
    if (liveScans.length) {
      const s0 = liveScans[0];
      setAssetsScanLive(
        `Live scan · ${(s0.status || "running").toUpperCase()} · ${s0.target || ""}`,
        true
      );
    } else if (!window.__securaiqAssetsScanBusy) {
      setAssetsScanLive("", false);
    }
    const byAsset = {};
    (inv.devices || []).forEach((d) => {
      if (d.asset_id) byAsset[d.asset_id] = d;
    });
    const merged = assets.map((a) => {
      const d = byAsset[a.id] || {};
      const ip = a.ip || d.ip || "";
      const hostname = a.hostname || d.hostname || "";
      const os = a.os || d.os || "";
      return {
        ...a,
        ip,
        hostname,
        os,
        mac: a.mac || d.mac || "",
        open_ports: (a.open_ports && a.open_ports.length ? a.open_ports : d.open_ports) || [],
        shares: d.shares || a.shares || [],
        display_name:
          a.display_name ||
          displayAssetLabel({ name: a.name, ip, hostname, os, asset_name: a.name }),
        _oa: !!d.asset_id || /openaudit/i.test(a.notes || ""),
      };
    });
    const seenAuditIds = new Set(merged.filter((a) => a._oa).map((a) => a.id));
    const oaOnly = (inv.devices || [])
      .filter((d) => !d.asset_id || !seenAuditIds.has(d.asset_id))
      .map((d) => ({
        id: d.asset_id || d.id,
        name: displayAssetLabel({ name: d.name, ip: d.ip, hostname: d.hostname, os: d.os }),
        display_name: displayAssetLabel({ name: d.name, ip: d.ip, hostname: d.hostname, os: d.os }),
        ip: d.ip || "",
        hostname: d.hostname || "",
        asset_type: d.type || "endpoint",
        os: d.os || "",
        mac: d.mac || "",
        source: "openaudit",
        notes: "openaudit",
        _oa: true,
        _oaOnly: !d.asset_id,
        last_scan_status: "",
        findings: null,
        open_ports: d.open_ports || [],
        shares: d.shares || [],
      }));
    const filterCat = String(window.__inventoryCategoryFilter || "").toLowerCase();
    const filterRow = (a) => !filterCat || assetCategoryId(a) === filterCat;
    const swServers = swPosture.servers || [];
    const openScan = attachAssetPatchInfo(merged.filter(filterRow), swServers);
    const openAudit = attachAssetPatchInfo(
      [
        ...merged.filter((a) => a._oa).filter(filterRow),
        ...oaOnly.filter(filterRow),
      ],
      swServers
    );
    const typeCounts = {};
    [...merged, ...oaOnly].forEach((a) => {
      const t = assetCategoryId(a);
      typeCounts[t] = (typeCounts[t] || 0) + 1;
    });
    const withPorts = [...merged, ...oaOnly].filter((a) => (a.open_ports || []).length).length;
    const withShares = [...merged, ...oaOnly].filter((a) => (a.shares || []).length).length;
    const jobs = jobsData.jobs || [];
    const liveJobs = jobs.filter(
      (j) =>
        /lan_inventory|openaudit_sync|scan_execute/.test(j.kind || "") &&
        /pending|running/.test((j.status || "").toLowerCase())
    );
    const liveChip = liveJobs.length
      ? `<span class="auto-job-status status-running">${liveJobs.length} job(s) live</span>`
      : `<span class="auto-job-status status-done">securaiq live</span>`;
    const ping = st.ping || {};
    const oaChip = st.configured
      ? ping.ok
        ? `<span class="auto-job-status status-done">Open-AudIT connected</span>`
        : `<span class="auto-job-status status-error">Open-AudIT unreachable</span>`
      : "";
    const typeBits = Object.entries(typeCounts)
      .filter(([, n]) => n > 0)
      .sort((a, b) => b[1] - a[1])
      .map(([k, n]) => `<span class="inventory-cat-stat">${categoryChipHtml({ asset_category: k }, { clickable: true, active: filterCat === k })}<em>${n}</em></span>`)
      .join(" ");
    const clearFilterBtn = filterCat
      ? `<button type="button" class="btn-secondary inventory-clear-filter">Clear filter</button>`
      : "";
    const summary = `
      <div class="inventory-summary-bar" aria-live="polite">
        <div class="vuln-summary-metrics">
          <strong>${merged.length + oaOnly.length}</strong> hosts ·
          <strong>${openScan.length}</strong> Open Scan ·
          <strong>${openAudit.length}</strong> Open Audit
          ${withPorts ? ` · <strong>${withPorts}</strong> with ports` : ""}
          ${withShares ? ` · <strong>${withShares}</strong> with shares` : ""}
          ${st.devices_cached ? ` · <strong>${st.devices_cached}</strong> cached` : ""}
        </div>
        <div class="inventory-category-bar">${typeBits || `<span class="hint">No categories yet</span>`}${clearFilterBtn}</div>
        <div class="vuln-summary-actions">${liveChip}${oaChip}</div>
      </div>`;
    el.innerHTML = `
      ${summary}
      ${inventoryBlockHtml("Open Scan", openScan, filterCat ? "No hosts in this category — clear filter or Refresh LAN." : "Refresh LAN or Queue engine scan on a host you own.")}
      ${inventoryBlockHtml("Open Audit", openAudit, filterCat ? "No audit hosts in this category." : "Refresh LAN or Sync inventory — hosts stream here as they are audited.")}`;
    el.querySelectorAll(".category-chip-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const cat = btn.getAttribute("data-category") || "";
        window.__inventoryCategoryFilter = window.__inventoryCategoryFilter === cat ? "" : cat;
        renderAssetsPage({ quiet: true });
      });
    });
    el.querySelector(".inventory-clear-filter")?.addEventListener("click", () => {
      window.__inventoryCategoryFilter = "";
      renderAssetsPage({ quiet: true });
    });
    wireAskAiButtons("assetsPageBody");
    qs("assetsPageBody")?.querySelectorAll(".ws-scan-asset").forEach((btn) => {
      btn.addEventListener("click", () => queueAssetScan(btn.getAttribute("data-target")));
    });
    qs("assetsPageBody")?.querySelectorAll(".ws-asset-software").forEach((btn) => {
      btn.addEventListener("click", () => {
        window.__softwareAssetFilter = {
          id: btn.getAttribute("data-id") || "",
          name: btn.getAttribute("data-name") || "",
        };
        showWorkspace("software");
      });
    });
    qs("assetsPageBody")?.querySelectorAll(".ws-asset-patch").forEach((btn) => {
      btn.addEventListener("click", () => {
        window.__softwareAssetFilter = {
          id: btn.getAttribute("data-id") || "",
          name: btn.getAttribute("data-name") || "",
        };
        _softwareView = "products";
        showWorkspace("software");
      });
    });
    qs("assetsPageBody")?.querySelectorAll(".ws-edit-asset").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const name = prompt("Asset name:", btn.getAttribute("data-name") || "");
        if (!name?.trim()) return;
        const owner = prompt("Owner:", btn.getAttribute("data-owner") || "") ?? "";
        const criticality = prompt("Criticality (low/medium/high/critical):", btn.getAttribute("data-crit") || "medium") ?? "medium";
        const assetType = prompt(
          "Category (server/computer/endpoint/mobile/network/printer/iot/database/web/cloud/container/code/other):",
          btn.getAttribute("data-type") || "server"
        ) ?? (btn.getAttribute("data-type") || "server");
        await fetch(`/api/assets/${btn.getAttribute("data-id")}`, {
          method: "PATCH",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ name: name.trim(), owner, criticality, asset_type: assetType.trim() }),
        });
        renderAssetsPage({ quiet: true });
      });
    });
    qs("assetsPageBody")?.querySelectorAll(".ws-del-asset").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await fetch(`/api/assets/${btn.getAttribute("data-id")}`, { method: "DELETE", headers: authHeaders() });
        renderAssetsPage({ quiet: true });
        if (typeof loadCommandCenter === "function") loadCommandCenter();
      });
    });
  }
  window.renderAssetsPage = renderAssetsPage;

  let _softwareFilters = { q: "", status: "", source: "" };
  let _softwareView = "products";

  async function readApiError(res) {
    const ct = (res.headers && res.headers.get("content-type")) || "";
    if (ct.includes("application/json")) {
      const data = await res.json().catch(() => ({}));
      if (typeof data.detail === "string") return data.detail;
      if (Array.isArray(data.detail)) return data.detail.map((d) => d.msg || JSON.stringify(d)).join("; ");
      return data.message || `HTTP ${res.status}`;
    }
    if (res.status === 405) {
      return "Software API not loaded — restart SecuraIQ (python run.py) so /api/software routes register.";
    }
    if (res.status === 404) {
      return "Software API not found — restart SecuraIQ to pick up the latest server code.";
    }
    return `HTTP ${res.status}`;
  }

  function setSoftwareSyncLive(text, show) {
    const live = qs("softwareScanLive");
    if (!live) return;
    if (show && text) {
      live.hidden = false;
      live.textContent = text;
    } else if (!window.__securaiqSoftwareSyncBusy) {
      live.hidden = true;
      live.textContent = "";
    }
  }
  window.setSoftwareSyncLive = setSoftwareSyncLive;

  function softwareLiveEnabled() {
    try {
      const v = localStorage.getItem("securaiq.software.live");
      if (v === "0" || v === "false") return false;
    } catch {
      /* ignore */
    }
    return true;
  }

  function wireSoftwareLiveToggleOnce() {
    if (window.__swLiveToggleWired) return;
    window.__swLiveToggleWired = true;
    const toggle = qs("softwareLiveToggle");
    if (!toggle) return;
    toggle.checked = softwareLiveEnabled();
    toggle.addEventListener("change", () => {
      try {
        localStorage.setItem("securaiq.software.live", toggle.checked ? "1" : "0");
      } catch {
        /* ignore */
      }
      if (toggle.checked) {
        setSoftwareSyncLive("● LIVE · updates resumed", true);
        refreshSoftwareFromPush({}, { partial: true });
      } else {
        setSoftwareSyncLive("Live updates paused", true);
      }
    });
  }

  function formatActivityAgo(ts) {
    if (!ts) return "now";
    const sec = Math.max(0, Math.round(Date.now() / 1000 - Number(ts)));
    if (sec < 5) return "just now";
    if (sec < 60) return `${sec}s ago`;
    if (sec < 3600) return `${Math.round(sec / 60)}m ago`;
    return `${Math.round(sec / 3600)}h ago`;
  }

  function activityIconForPush(push) {
    const action = String((push && push.action) || "").toLowerCase();
    if (push && (push.kev || push.cve || action === "vuln")) return { cls: "is-crit", glyph: "!" };
    if (push && (push.needs_update || action === "patch")) return { cls: "is-warn", glyph: "↑" };
    return { cls: "", glyph: "✓" };
  }

  function pushSoftwareActivity(push) {
    wireSoftwareLiveToggleOnce();
    if (!softwareLiveEnabled()) return;
    const feed = qs("softwareActivityFeed");
    if (!feed) return;
    push = push || {};
    let text = push.message || "";
    if (!text) {
      const changes = push.changes || [];
      if (changes.length) {
        const c = changes[0];
        text = `${c.product || "Software"}${c.version ? ` ${c.version}` : ""}${c.asset_name ? ` on ${c.asset_name}` : ""}`;
        if (changes.length > 1) text += ` · +${changes.length - 1} more`;
      } else if (push.total_products != null) {
        text = `Inventory updated · ${push.total_products} product(s)`;
      } else if (push.issues != null) {
        text = `${push.issues} patch gap(s) · ${push.health_score != null ? push.health_score + "% health" : "live"}`;
      } else {
        return;
      }
    }
    const icon = activityIconForPush(push);
    const ts = push.ts || Date.now() / 1000;
    const li = document.createElement("li");
    li.innerHTML = `<span class="sw-act-icon ${icon.cls}">${icon.glyph}</span><span class="sw-act-body">${escapeHtml(text)}</span><span class="sw-act-ago">${escapeHtml(formatActivityAgo(ts))}</span>`;
    feed.insertBefore(li, feed.firstChild);
    while (feed.children.length > 8) feed.removeChild(feed.lastChild);
    feed.hidden = false;
  }
  window.pushSoftwareActivity = pushSoftwareActivity;

  function softwareRowKey(r) {
    const id = r && r.id ? String(r.id) : "";
    const asset = r && r.asset_id ? String(r.asset_id) : "";
    const product = r && r.product ? String(r.product).toLowerCase() : "";
    const port = r && r.port != null ? String(r.port) : "0";
    return id || `${asset}|${product}|${port}`;
  }

  function softwareProductRowHtml(r, chipFn) {
    const fn = chipFn || (typeof window.softwareStatusChip === "function" ? window.softwareStatusChip : (it) => escapeHtml(it.status || "?"));
    const iid = escapeHtml(r.id || "");
    const prodKey = escapeHtml(r.canonical_id || r.product || "");
    const aid = escapeHtml(r.asset_id || "");
    const aname = escapeHtml(r.asset_name || "");
    const sourceText = (
      r.source_label ||
      (typeof r.source === "string" ? r.source.split(":")[0] : "") ||
      "unknown"
    )
      .toString()
      .trim() || "unknown";
    return `<tr data-sw-key="${escapeHtml(softwareRowKey(r))}" data-sw-installation="${iid}" class="sw-product-row">
        <td>${fn(r)}</td>
        <td><button type="button" class="sw-row-link sw-open-product" data-key="${prodKey}" data-installation="${iid}">${escapeHtml(r.product || "?")}</button>${r.detail ? `<br><span class="hint">${escapeHtml(r.detail)}</span>` : ""}</td>
        <td><span class="sw-source-pill" title="${escapeHtml(sourceText)}">${escapeHtml(sourceText)}</span></td>
        <td>${escapeHtml(r.version || "—")}</td>
        <td class="hint">${r.latest_version ? escapeHtml(r.latest_version) : "Unknown"}</td>
        <td>${r.kev ? `<span class="sw-status-chip status-error" title="CISA KEV">KEV</span> ` : ""}${escapeHtml(r.cve || "—")}${Number(r.cve_count || 0) > 1 ? `<br><span class="hint">+${Number(r.cve_count) - 1} more</span>` : ""}</td>
        <td>${aid ? `<button type="button" class="sw-row-link sw-open-asset" data-id="${aid}" data-name="${aname}">${aname || "—"}</button>` : escapeHtml(r.asset_name || "—")}</td>
        <td>${r.port ? `:${r.port}` : "—"}</td>
      </tr>`;
  }

  function closeSoftwareDetailDrawer() {
    const drawer = qs("softwareDetailDrawer");
    if (!drawer) return;
    drawer.classList.add("hidden");
    drawer.setAttribute("aria-hidden", "true");
  }

  function openSoftwareDetailDrawer(title, html) {
    const drawer = qs("softwareDetailDrawer");
    const body = qs("softwareDetailBody");
    const head = qs("softwareDetailTitle");
    if (!drawer || !body) return;
    if (head) head.textContent = title || "Software detail";
    body.innerHTML = html;
    drawer.classList.remove("hidden");
    drawer.setAttribute("aria-hidden", "false");
    drawer.querySelectorAll("[data-sw-detail-close]").forEach((el) => {
      el.onclick = closeSoftwareDetailDrawer;
    });
  }

  async function openProductDetail(key, installationId) {
    if (!key && installationId) {
      const d = await fetch(`/api/patches/${encodeURIComponent(installationId)}`, { headers: authHeaders() }).then((r) => r.json()).catch(() => ({}));
      if (d && d.patch) key = d.patch.canonical_id || d.patch.product;
    }
    if (!key) return;
    openSoftwareDetailDrawer("Loading…", `<p class="hint">Loading product detail…</p>`);
    const data = await fetch(`/api/software/product/${encodeURIComponent(key)}`, { headers: authHeaders() }).then((r) => r.json()).catch(() => ({}));
    const p = data.product || {};
    const adv = data.advisory_summary || {};
    const vers = (data.version_counts || []).map((v) => `<li>${escapeHtml(v.version)} — <strong>${Number(v.assets)}</strong> asset(s)</li>`).join("");
    const assets = (data.affected_assets || []).slice(0, 12).map((a) => `<li>${escapeHtml(a)}</li>`).join("");
    const advRows = (data.advisories || []).slice(0, 8).map((a) => `<li>${a.kev ? "KEV " : ""}${escapeHtml(a.cve_id || "?")}${a.cvss != null ? ` · CVSS ${a.cvss}` : ""}${a.fixed_version ? ` · fix ${escapeHtml(a.fixed_version)}` : ""}</li>`).join("");
    openSoftwareDetailDrawer(
      p.name || key,
      `<div class="sw-detail-section"><dl class="sw-detail-kv"><dt>Latest</dt><dd>${p.latest_version ? escapeHtml(p.latest_version) : "Unknown"}</dd><dt>Source</dt><dd>${escapeHtml(p.latest_source || "—")}</dd><dt>Advisories</dt><dd>${Number(adv.total || 0)} (${Number(adv.kev || 0)} KEV)</dd></dl></div>
      <div class="sw-detail-section"><h3>Installed versions</h3><ul class="hint">${vers || "<li>None</li>"}</ul></div>
      <div class="sw-detail-section"><h3>Affected assets</h3><ul class="hint">${assets || "<li>None</li>"}</ul></div>
      <div class="sw-detail-section"><h3>Vulnerabilities</h3><ul class="hint">${advRows || "<li>No CVE data yet</li>"}</ul></div>
      <div class="sw-detail-actions"><button type="button" class="btn-primary-cc sw-detail-remediate" data-installation="${escapeHtml(installationId || "")}">Create remediation</button></div>`
    );
    wireSoftwareDetailActions();
  }

  async function openAssetSoftwareDetail(assetId, assetName) {
    openSoftwareDetailDrawer(assetName || "Asset software", `<p class="hint">Loading…</p>`);
    const data = await fetch(`/api/assets/${encodeURIComponent(assetId)}/software`, { headers: authHeaders() }).then((r) => r.json()).catch(() => ({}));
    const rows = (data.software || []).map((r) => `<tr><td>${escapeHtml(r.patch_label || r.status_label || r.status || "?")}</td><td>${escapeHtml(r.product || "?")}</td><td>${escapeHtml(r.version || "—")}</td><td class="hint">${r.latest_version ? escapeHtml(r.latest_version) : "Unknown"}</td></tr>`).join("");
    const last = data.last_inventory ? new Date(Number(data.last_inventory) * (Number(data.last_inventory) < 1e12 ? 1000 : 1)).toLocaleString() : "Unknown";
    openSoftwareDetailDrawer(
      assetName || assetId,
      `<div class="sw-detail-section"><dl class="sw-detail-kv"><dt>Software</dt><dd>${Number(data.total || 0)}</dd><dt>Issues</dt><dd>${Number(data.issues || 0)}</dd><dt>Last inventory</dt><dd>${escapeHtml(last)}</dd></dl></div>
      <div class="sw-detail-section"><table class="ws-table sw-table"><thead><tr><th>Status</th><th>Product</th><th>Installed</th><th>Latest</th></tr></thead><tbody>${rows || `<tr><td colspan="4" class="hint">No software</td></tr>`}</tbody></table></div>
      <div class="sw-detail-actions"><button type="button" class="btn-primary-cc sw-detail-remediate-asset" data-id="${escapeHtml(assetId)}" data-name="${escapeHtml(assetName || "")}">Create remediation</button><button type="button" class="btn-secondary sw-filter-asset" data-id="${escapeHtml(assetId)}" data-name="${escapeHtml(assetName || "")}">Filter table</button></div>`
    );
    wireSoftwareDetailActions();
  }

  // OS -> package manager guess for the "Patch via Agent" action. This is a
  // best-effort default, not a promise the exact package name resolves —
  // the UI says so (see the hint text below) because the SecuraIQ Agent's
  // installed-software list uses each OS's own display name, which doesn't
  // always match the package manager's own package/ID naming.
  function _guessPackageManager(osName) {
    const os = String(osName || "").toLowerCase();
    if (os.includes("win")) return "winget";
    if (os.includes("darwin") || os.includes("mac")) return "brew";
    if (os.includes("linux")) return "apt";
    return "";
  }

  async function openPatchDetail(installationId) {
    if (!installationId) return;
    openSoftwareDetailDrawer("Patch detail", `<p class="hint">Loading…</p>`);
    const data = await fetch(`/api/patches/${encodeURIComponent(installationId)}`, { headers: authHeaders() }).then((r) => r.json()).catch(() => ({}));
    const p = data.patch || {};
    const adv = (data.advisories || []).slice(0, 6).map((a) => `<li>${a.kev ? "KEV " : ""}${escapeHtml(a.cve_id || "?")}${a.fixed_version ? ` → ${escapeHtml(a.fixed_version)}` : ""}</li>`).join("");
    // Only offer agent-executed patching when this asset actually has a
    // live SecuraIQ Agent enrolled — there's no other channel to run the
    // upgrade command on that host.
    let agent = null;
    if (p.asset_id) {
      try {
        const agentsData = await fetch("/api/agents", { headers: authHeaders() }).then((r) => r.json()).catch(() => ({}));
        agent = (agentsData.agents || []).find((a) => a.asset_id === p.asset_id && a.status !== "revoked") || null;
      } catch {
        agent = null;
      }
    }
    const manager = agent ? _guessPackageManager(agent.os) : "";
    const patchAgentBtn =
      agent && manager
        ? `<button type="button" class="btn-primary-cc sw-detail-patch-agent" data-agent-id="${escapeHtml(
            agent.id
          )}" data-manager="${escapeHtml(manager)}" data-package="${escapeHtml(
            p.product || ""
          )}" data-target="${escapeHtml(p.target_version || "")}">Patch via Agent</button>`
        : "";
    openSoftwareDetailDrawer(
      `${p.product || "Patch"} on ${p.asset_name || "host"}`,
      `<div class="sw-detail-section"><dl class="sw-detail-kv"><dt>Status</dt><dd>${escapeHtml(p.patch_label || p.patch_status || "?")}</dd><dt>Installed</dt><dd>${escapeHtml(p.installed_version || "—")}</dd><dt>Target</dt><dd>${p.target_version ? escapeHtml(p.target_version) : "Unknown"}</dd><dt>CVE</dt><dd>${escapeHtml(p.cve || "—")}</dd></dl><p class="hint">${escapeHtml(p.reason || p.detail || "")}</p></div>
      <div class="sw-detail-section"><h3>Advisories</h3><ul class="hint">${adv || "<li>None on record</li>"}</ul></div>
      ${
        agent
          ? `<p class="hint">${
              manager
                ? `SecuraIQ Agent online on this host — can run <code>${escapeHtml(manager)} upgrade ${escapeHtml(p.product || "")}</code>. Best-effort package-name match, not guaranteed to resolve.`
                : "SecuraIQ Agent enrolled on this host, but its OS isn't recognized for agent-driven patching yet."
            }</p>`
          : `<p class="hint">No SecuraIQ Agent enrolled on this host — enroll one under Assets to enable agent-driven patching.</p>`
      }
      <div class="sw-detail-actions">${patchAgentBtn}<button type="button" class="btn-primary-cc sw-detail-verify" data-installation="${escapeHtml(installationId)}">Verify patch</button><button type="button" class="btn-secondary sw-detail-remediate" data-installation="${escapeHtml(installationId)}">Create remediation</button></div>`
    );
    wireSoftwareDetailActions();
  }

  function wireSoftwareDetailActions() {
    qs("softwareDetailBody")?.querySelector(".sw-detail-patch-agent")?.addEventListener("click", async (ev) => {
      const btn = ev.currentTarget;
      const agentId = btn.getAttribute("data-agent-id");
      const manager = btn.getAttribute("data-manager");
      const pkg = btn.getAttribute("data-package");
      const target = btn.getAttribute("data-target") || "";
      if (
        !confirm(
          `Request a real ${manager} upgrade of "${pkg}" on this host's SecuraIQ Agent?\n\n` +
            `This creates a pending approval request. Once approved (see Agents → Pending Approvals), it runs on the agent's next check-in and actually changes installed software on that machine.`
        )
      ) {
        return;
      }
      btn.disabled = true;
      btn.textContent = "Requesting…";
      try {
        const res = await fetch(`/api/agents/${encodeURIComponent(agentId)}/commands`, {
          method: "POST",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({
            kind: "patch_package",
            payload: { manager, package: pkg, target_version: target },
          }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
        if (typeof notifyUser === "function") {
          notifyUser(`**Patch requested** · \`${manager} upgrade ${pkg}\` — awaiting approval (Agents → Pending Approvals) before it runs.`);
        }
        btn.textContent = "Pending approval";
        if (typeof window.renderAgentsPanel === "function") window.renderAgentsPanel();
      } catch (e) {
        if (typeof notifyUser === "function") notifyUser(`Patch request failed: ${e.message || e}`);
        btn.disabled = false;
        btn.textContent = "Patch via Agent";
      }
    });
    qs("softwareDetailBody")?.querySelector(".sw-detail-verify")?.addEventListener("click", async (ev) => {
      const btn = ev.currentTarget;
      const iid = btn.getAttribute("data-installation");
      btn.disabled = true;
      try {
        const res = await fetch(`/api/patches/${encodeURIComponent(iid)}/verify`, { method: "POST", headers: authHeaders() });
        const body = await res.json().catch(() => ({}));
        if (typeof notifyUser === "function") notifyUser(body.verified ? `**Verified** · ${body.after_version || "?"}` : `**Not verified** · ${body.after_version || "?"}`);
        if (typeof refreshSoftwareFromPush === "function") refreshSoftwareFromPush({}, { partial: true });
        openPatchDetail(iid);
      } catch (e) {
        if (typeof notifyUser === "function") notifyUser(`Verify failed: ${e.message || e}`);
      } finally {
        btn.disabled = false;
      }
    });
    qs("softwareDetailBody")?.querySelector(".sw-detail-remediate")?.addEventListener("click", async (ev) => {
      const btn = ev.currentTarget;
      const iid = btn.getAttribute("data-installation");
      btn.disabled = true;
      try {
        const res = await fetch(`/api/patches/${encodeURIComponent(iid)}/remediation`, { method: "POST", headers: authHeaders() });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.detail || body.message || `HTTP ${res.status}`);
        if (typeof notifyUser === "function") notifyUser(`**Remediation created** · ${body.title || "Patch task"}`);
        if (typeof window.showWorkspace === "function") window.showWorkspace("remediations");
      } catch (e) {
        if (typeof notifyUser === "function") notifyUser(`Remediation failed: ${e.message || e}`);
      } finally {
        btn.disabled = false;
      }
    });
    qs("softwareDetailBody")?.querySelector(".sw-detail-remediate-asset")?.addEventListener("click", async (ev) => {
      const btn = ev.currentTarget;
      btn.disabled = true;
      try {
        const res = await fetch("/api/software/remediations", {
          method: "POST",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ asset_id: btn.getAttribute("data-id") || "", asset_name: btn.getAttribute("data-name") || "" }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
        if (typeof notifyUser === "function") notifyUser(`**Remediation created** · ${body.title || "Patch"}`);
      } catch (e) {
        if (typeof notifyUser === "function") notifyUser(`Remediation failed: ${e.message || e}`);
      } finally {
        btn.disabled = false;
      }
    });
    qs("softwareDetailBody")?.querySelector(".sw-filter-asset")?.addEventListener("click", (ev) => {
      const btn = ev.currentTarget;
      window.__softwareAssetFilter = { id: btn.getAttribute("data-id"), name: btn.getAttribute("data-name") };
      closeSoftwareDetailDrawer();
      _softwareView = "products";
      renderSoftwarePage();
    });
  }

  function wireSoftwareTableInteractions(root) {
    (root || document).querySelectorAll(".sw-open-product").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        openProductDetail(btn.getAttribute("data-key"), btn.getAttribute("data-installation"));
      });
    });
    (root || document).querySelectorAll(".sw-open-asset").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        openAssetSoftwareDetail(btn.getAttribute("data-id"), btn.getAttribute("data-name"));
      });
    });
    (root || document).querySelectorAll(".sw-product-row").forEach((tr) => {
      tr.addEventListener("dblclick", () => {
        const iid = tr.getAttribute("data-sw-installation");
        if (iid) openPatchDetail(iid);
      });
    });
  }
  window.openProductDetail = openProductDetail;
  window.openPatchDetail = openPatchDetail;

  function patchSoftwareKpis(metrics) {
    const kpis = document.querySelector(".sw-server-kpis");
    if (!kpis || !metrics) return;
    const nums = kpis.querySelectorAll("strong");
    if (nums[0] && metrics.totalProducts != null) nums[0].textContent = String(metrics.totalProducts);
    if (nums[1] && metrics.outdatedCount != null) nums[1].textContent = String(metrics.outdatedCount);
    if (nums[2] && metrics.criticalCount != null) nums[2].textContent = String(metrics.criticalCount);
    if (nums[3] && metrics.upToDateCount != null) nums[3].textContent = String(metrics.upToDateCount);
    const gauge = document.querySelector(".sw-health-gauge span");
    if (gauge && metrics.health != null) {
      gauge.textContent = `${metrics.health}%`;
      const wrap = gauge.closest(".sw-health-gauge");
      if (wrap) wrap.style.setProperty("--p", String(metrics.health));
    }
  }

  async function fetchSoftwareSummaryMetrics() {
    const res = await fetch("/api/software/summary", { headers: authHeaders() }).catch(() => null);
    if (!res || !res.ok) return null;
    const data = await res.json().catch(() => ({}));
    const posture = data.posture || {};
    const counts = posture.counts || {};
    const engine = data.engine || {};
    const outdated =
      Number(counts.outdated || 0) + Number(counts.eol || 0) + Number(counts.missing_patch || 0);
    const upToDate = Number(counts.current || 0) + Number(counts.up_to_date || 0);
    const critical =
      Number(engine.critical || 0) ||
      Number((engine.patch_counts || {}).critical_security_update || 0) +
        Number((engine.patch_counts || {}).exploited_kev || 0);
    return {
      totalProducts: Number(data.total ?? posture.total_products ?? engine.total_installations ?? 0),
      outdatedCount: outdated,
      upToDateCount: upToDate,
      criticalCount: critical,
      health: Number(posture.health_score ?? 100),
    };
  }

  async function fetchSoftwareRows(params) {
    const qs = new URLSearchParams(params || {});
    if (!qs.has("limit")) qs.set("limit", "30");
    const res = await fetch(`/api/software/rows?${qs}`, { headers: authHeaders() }).catch(() => null);
    if (!res || !res.ok) return [];
    const body = await res.json().catch(() => ({}));
    return body.data || [];
  }

  function upsertSoftwareTableRows(rows) {
    const tbody = document.querySelector("#softwarePageBody .sw-table tbody");
    if (!tbody || !rows || !rows.length) return 0;
    const chipFn = typeof window.softwareStatusChip === "function" ? window.softwareStatusChip : null;
    let n = 0;
    rows.forEach((r) => {
      const key = softwareRowKey(r);
      const html = softwareProductRowHtml(r, chipFn);
      let existing = null;
      tbody.querySelectorAll("tr[data-sw-key]").forEach((tr) => {
        if (!existing && tr.getAttribute("data-sw-key") === key) existing = tr;
      });
      if (existing) {
        existing.outerHTML = html;
        tbody.querySelectorAll("tr[data-sw-key]").forEach((tr) => {
          if (tr.getAttribute("data-sw-key") === key) {
            tr.classList.add("sw-row-updated");
            setTimeout(() => tr.classList.remove("sw-row-updated"), 2200);
          }
        });
      } else {
        tbody.insertAdjacentHTML("afterbegin", html);
      }
      n += 1;
    });
    window.__softwarePageCache = window.__softwarePageCache || { rows: {} };
    rows.forEach((r) => {
      window.__softwarePageCache.rows[softwareRowKey(r)] = r;
    });
    wireSoftwareTableInteractions(tbody.closest("#softwarePageBody") || tbody);
    return n;
  }

  async function refreshSoftwareFromPush(push, opts) {
    const options = opts || {};
    const view = window.__securaiqWorkspaceView || "";
    window.__securaiqRealtimeConnected = !!window.__securaiqEsConnected;
    wireSoftwareLiveToggleOnce();

    if (!options.skipPulse && typeof window.pulseSoftwareFromPush === "function") {
      window.pulseSoftwareFromPush(push || {});
    }

    const liveOn = softwareLiveEnabled();
    const liveState = window.__securaiqRealtimeConnected ? "● LIVE" : "○ Polling";
    const agoSec = push && push.ts ? Math.max(0, Math.round(Date.now() / 1000 - Number(push.ts))) : null;
    if (view === "software") {
      setSoftwareSyncLive(
        liveOn
          ? `${liveState}${agoSec != null ? ` · Last event ${agoSec}s ago` : ""}${!window.__securaiqRealtimeConnected ? " · fallback poll" : ""}`
          : "Live updates paused — toggle to resume",
        true
      );
    }

    if (!liveOn) return;

    const onSoftwareView = view === "software";
    if (onSoftwareView) {
      const metrics = await fetchSoftwareSummaryMetrics();
      if (metrics) patchSoftwareKpis(metrics);
    }

    if (!onSoftwareView) return;
    const el = qs("softwarePageBody");
    if (!el) return;

    if (options.summaryOnly || _softwareView === "servers") return;

    let rows = (push && push.changes) || [];
    if (!rows.length && push) {
      const params = {};
      if (push.installation_id) params.installation_id = push.installation_id;
      if (push.product) params.product = push.product;
      if (push.canonical_id) params.canonical_id = push.canonical_id;
      if (push.asset_id) params.asset_id = push.asset_id;
      if (Array.isArray(push.asset_ids) && push.asset_ids.length === 1) params.asset_id = push.asset_ids[0];
      if (Object.keys(params).length) rows = await fetchSoftwareRows(params);
    }
    if (!rows.length && !options.partial) {
      if (typeof renderSoftwarePage === "function") renderSoftwarePage({ quiet: true });
      return;
    }
    if (rows.length) upsertSoftwareTableRows(rows);
  }
  window.refreshSoftwareFromPush = refreshSoftwareFromPush;

  function startSoftwarePollFallback() {
    clearInterval(window.__securaiqSwPollTimer);
    window.__securaiqSwPollTimer = setInterval(() => {
      if (window.__securaiqWorkspaceView !== "software") return;
      if (window.__securaiqEsConnected) return;
      refreshSoftwareFromPush({}, { partial: true, summaryOnly: _softwareView === "servers" });
    }, 60000);
  }

  async function renderSoftwarePage(opts) {
    wireSoftwareLiveToggleOnce();
    const el = qs("softwarePageBody");
    if (!el) return;
    const quiet = !!(opts && opts.quiet);
    if (!quiet) el.innerHTML = `<p class="hint" aria-live="polite">Loading software inventory…</p>`;
    let data = {};
    let invStatus = null;
    try {
      const params = new URLSearchParams({ limit: "500" });
      if (_softwareFilters.status) params.set("status", _softwareFilters.status);
      if (_softwareFilters.source) params.set("source", _softwareFilters.source);
      const assetFilter = window.__softwareAssetFilter || "";
      if (assetFilter.id) params.set("asset_id", assetFilter.id);
      const [res, statusRes] = await Promise.all([
        fetch(`/api/software/inventory?${params}`, { headers: authHeaders() }),
        fetch("/api/inventory/status", { headers: authHeaders() }).catch(() => null),
      ]);
      data = await res.json().catch(() => ({}));
      if (statusRes && statusRes.ok) invStatus = await statusRes.json().catch(() => null);
      if (!res.ok && data.status !== "ok") throw new Error(await readApiError(res));
    } catch (err) {
      const msg = err.message || String(err);
      const staleHint =
        /500|not found|404/i.test(msg)
          ? " The server may be running old code — restart with python run.py and hard-refresh the browser (Ctrl+Shift+R)."
          : "";
      el.innerHTML = `<div class="sw-empty-state sw-empty-error">
        <h2>Could not load inventory</h2>
        <p class="hint">${escapeHtml(msg)}${escapeHtml(staleHint)}</p>
        <div class="cc-action-row">
          <button type="button" class="btn-secondary" id="softwareRetryLoad">Retry</button>
          <button type="button" class="btn-primary-cc" id="softwareSyncEmpty">Sync now</button>
          <button type="button" class="btn-secondary" data-workspace="integrations">Connect sources</button>
        </div></div>`;
      qs("softwareRetryLoad")?.addEventListener("click", () => renderSoftwarePage());
      qs("softwareSyncEmpty")?.addEventListener("click", () => {
        if (typeof window.runSoftwareSyncAll === "function") window.runSoftwareSyncAll();
        else if (typeof window.syncAllAndRebuildSoftware === "function") window.syncAllAndRebuildSoftware({});
      });
      setSoftwareSyncLive("Reconnecting…", true);
      return;
    }
    const posture = data.posture || {};
    const rows = (data.inventory || data.data || []).filter((r) => {
      const q = (_softwareFilters.q || "").trim().toLowerCase();
      if (!q) return true;
      const blob = [r.product, r.version, r.asset_name, r.cve, r.source, r.source_label].join(" ").toLowerCase();
      return blob.includes(q);
    });
    const counts = posture.counts || {};
    const coverage = posture.coverage || {};
    const byLabel = posture.by_source_label || {};
    const serverSummary = posture.server_summary || {};
    const servers = posture.servers || [];
    const health = Number(posture.health_score ?? 100);
    let totalProducts = Number(data.total ?? posture.total_products ?? rows.length ?? 0);
    const outdatedCount =
      Number(counts.outdated || 0) + Number(counts.eol || 0) + Number(counts.missing_patch || 0);
    const upToDateCount = Number(counts.current || 0) + Number(counts.up_to_date || 0);
    const criticalCount = rows.filter((r) => {
      const sev = (r.severity || "").toLowerCase();
      const st = (r.status || "").toLowerCase();
      const patch = (r.patch_status || "").toLowerCase();
      return (
        sev === "critical" ||
        st === "eol" ||
        st === "missing_patch" ||
        patch === "exploited_kev" ||
        patch === "critical_security_update" ||
        r.kev
      );
    }).length;
    const lastSync = data.last_sync ? new Date(Number(data.last_sync) * (Number(data.last_sync) < 1e12 ? 1000 : 1)) : null;
    const lastSyncLabel =
      lastSync && !Number.isNaN(lastSync.getTime()) ? lastSync.toLocaleString() : "Never";
    window.__securaiqRealtimeConnected = !!window.__securaiqEsConnected;
    const liveState = window.__securaiqRealtimeConnected ? "● LIVE" : "○ Polling";
    const engine = data.engine || {};
    const patchCounts = engine.patch_counts || {};
    const engineTotal = Number(engine.total_installations || 0);
    if (engineTotal > totalProducts) totalProducts = engineTotal;
    let engineCritical = Number(engine.critical || 0);
    if (!engineCritical && patchCounts) {
      engineCritical =
        Number(patchCounts.critical_security_update || 0) + Number(patchCounts.exploited_kev || 0);
    }
    let engineOutdated = Number(engine.outdated || 0);
    if (!engineOutdated && patchCounts) {
      engineOutdated =
        Number(patchCounts.update_available || 0) +
        Number(patchCounts.security_update || 0) +
        Number(patchCounts.end_of_life || 0);
    }
    const engineUpToDate = Number(engine.up_to_date || patchCounts.up_to_date || 0);
    const sourceRows = (invStatus && invStatus.sources) || [];
    const sourceFreshness =
      sourceRows.length > 0
        ? sourceRows
            .slice(0, 6)
            .map((s) => {
              const ok = s.healthy === 1 || s.healthy === true;
              const ts = s.last_sync ? new Date(Number(s.last_sync) * (Number(s.last_sync) < 1e12 ? 1000 : 1)) : null;
              const ago =
                ts && !Number.isNaN(ts.getTime())
                  ? `${Math.max(0, Math.round((Date.now() - ts.getTime()) / 60000))}m ago`
                  : "never";
              return `<span class="sw-source-fresh${ok ? " is-healthy" : ""}">${escapeHtml(s.label || s.source_key || "?")} ${ok ? "●" : "○"} ${ago}</span>`;
            })
            .join("")
        : "";
    setSoftwareSyncLive(
      `${liveState} · Last sync ${lastSyncLabel}${data.message && totalProducts === 0 ? ` · ${data.message}` : ""}`,
      true
    );

    if (totalProducts === 0 && servers.length === 0) {
      el.innerHTML = `<div class="sw-empty-state sw-empty-hero">
        <h2>No inventory yet</h2>
        <p class="hint">${escapeHtml(data.message || "Connect an endpoint source or run a scan to begin collecting software inventory.")}</p>
        <div class="cc-action-row">
          <button type="button" class="btn-primary-cc" id="softwareEmptySync">Sync now</button>
          <button type="button" class="btn-secondary" data-workspace="integrations">Connect Wazuh / Open-AudIT</button>
          <button type="button" class="btn-secondary" data-action="new-scan">New scan</button>
          <button type="button" class="btn-secondary" id="softwareEmptyRebuild">Rebuild inventory</button>
        </div>
        <p class="hint sw-empty-sources">Sources: Wazuh · Open-AudIT · LAN · Scans · XDR · OS patches · Control Panel</p>
      </div>`;
      qs("softwareEmptySync")?.addEventListener("click", () => {
        if (typeof window.runSoftwareSyncAll === "function") window.runSoftwareSyncAll();
        else if (typeof window.syncAllAndRebuildSoftware === "function") window.syncAllAndRebuildSoftware({});
      });
      qs("softwareEmptyRebuild")?.addEventListener("click", async () => {
        try {
          await fetch("/api/software/rebuild", { method: "POST", headers: authHeaders() });
          renderSoftwarePage();
        } catch (e) {
          if (typeof notifyUser === "function") notifyUser(`Rebuild failed: ${e.message || e}`);
        }
      });
      return;
    }

    const chipFn = typeof window.softwareStatusChip === "function" ? window.softwareStatusChip : (it) => escapeHtml(it.status || "?");

    const patchChip = (st, label) => {
      const s = (st || "unknown").toLowerCase();
      const cls = s === "up_to_date" ? "done" : s === "needs_update" ? "error" : "planned";
      return `<span class="sw-status-chip status-${cls}">${escapeHtml(label || st || "?")}</span>`;
    };

    const viewTabs = `
      <div class="sw-view-tabs" role="tablist">
        <button type="button" class="sw-view-tab${_softwareView === "servers" ? " is-active" : ""}" data-sw-view="servers">By server / system</button>
        <button type="button" class="sw-view-tab${_softwareView === "products" ? " is-active" : ""}" data-sw-view="products">All products</button>
      </div>`;

    const serverKpis = `
      <div class="vuln-summary-metrics mc-sw-metrics sw-server-kpis">
        <article class="cc-kpi"><span>Software</span><strong>${totalProducts}</strong><em class="hint">installations tracked</em></article>
        <article class="cc-kpi"><span>Outdated</span><strong>${engineOutdated || outdatedCount}</strong><em class="hint">${Number(serverSummary.needs_update || 0)} systems</em></article>
        <article class="cc-kpi cc-kpi-warn"><span>Critical</span><strong>${engineCritical || criticalCount}</strong><em class="hint">KEV / critical CVE</em></article>
        <article class="cc-kpi cc-kpi-ok"><span>Up to date</span><strong>${engineUpToDate || upToDateCount}</strong><em class="hint">${health}% health</em></article>
      </div>`;

    const serverRows = servers
      .map((s) => {
        const issues = (s.top_issues || [])
          .slice(0, 2)
          .map((it) => escapeHtml(it.product || "?"))
          .join(", ");
        return `<tr>
          <td>${patchChip(s.patch_status, s.patch_label)}</td>
          <td><strong>${escapeHtml(s.asset_name || "—")}</strong><br><span class="hint category-chip category-${escapeHtml(s.category || "other")}">${escapeHtml(s.category_label || s.category || "")}</span></td>
          <td>${escapeHtml(s.os_product || "—")}${s.os_version ? `<br><span class="hint">${escapeHtml(s.os_version)}</span>` : ""}${s.os_status_label ? `<br>${chipFn({ status: s.os_status, status_label: s.os_status_label, status_class: s.os_status === "eol" || s.os_status === "outdated" ? "error" : s.os_status === "current" ? "done" : "planned" })}` : ""}</td>
          <td><strong>${Number(s.issues_count || 0)}</strong>${s.xdr_missing_patches ? `<br><span class="hint">${s.xdr_missing_patches} XDR patch gap(s)</span>` : ""}</td>
          <td>${Number(s.products_count || 0)}</td>
          <td class="hint">${issues || "—"}</td>
          <td class="ws-actions">${
            s.patch_status === "needs_update"
              ? `<button type="button" class="btn-secondary ws-server-remed" data-id="${escapeHtml(
                  s.asset_id || ""
                )}" data-name="${escapeHtml(s.asset_name || "")}">Remediate</button> `
              : ""
          }${s.asset_id ? `<button type="button" class="btn-secondary ws-server-drill" data-id="${escapeHtml(s.asset_id)}" data-name="${escapeHtml(s.asset_name || "")}">Details</button>` : ""}</td>
        </tr>`;
      })
      .join("");

    const serverPanel = `
      ${serverKpis}
      <div class="sw-table-wrap">
        <table class="ws-table sw-table sw-server-table">
          <thead><tr><th>Patch status</th><th>Server / system</th><th>OS</th><th>Issues</th><th>Products</th><th>Top gaps</th><th></th></tr></thead>
          <tbody>${serverRows || `<tr><td colspan="7" class="hint">No servers tracked yet — scan assets, sync SIEM/XDR, or rebuild all sources.</td></tr>`}</tbody>
        </table>
      </div>`;

    const sourceOpts = [
      ["", "All sources"],
      ["scan", "Network scan"],
      ["vuln", "Vulnerabilities"],
      ["xdr", "XDR / EDR"],
      ["wazuh", "SIEM (Wazuh)"],
      ["openaudit", "Open-AudIT"],
      ["lan", "LAN inventory"],
      ["asset", "Asset inventory"],
      ["code", "Code / SBOM"],
      ["hardening", "Hardening"],
      ["cloud", "Cloud posture"],
      ["local", "SecuraIQ tools"],
      ["os", "OS patches"],
      ["control_panel", "Control Panel (Windows)"],
    ]
      .map(
        ([v, lab]) =>
          `<option value="${v}"${_softwareFilters.source === v ? " selected" : ""}>${escapeHtml(lab)}</option>`
      )
      .join("");

    const covChips = [
      ["Control Panel", coverage.control_panel, "control_panel"],
      ["OS patches", coverage.os_patches, "os"],
      ["Scans", coverage.scans, "scan"],
      ["Inventory", coverage.inventory, "openaudit"],
      ["XDR", coverage.xdr, "xdr"],
      ["SIEM", coverage.siem, "wazuh"],
      ["Code", coverage.code, "code"],
      ["Hardening", coverage.hardening, "hardening"],
      ["Cloud", coverage.cloud, "cloud"],
      ["Local tools", coverage.local_tools, "local"],
      ["Remote SSH", coverage.remote_ssh, "os"],
    ]
      .map(([lab, n, src]) => {
        const on = _softwareFilters.source === src;
        return `<button type="button" class="sw-cov-chip${Number(n) > 0 ? " has-data" : ""}${on ? " is-active" : ""}" data-sw-source="${src}">${escapeHtml(lab)} <strong>${Number(n || 0)}</strong></button>`;
      })
      .join("");

    const filterBar = `
      <div class="filter-bar sw-filter-bar" aria-label="Software filters">
        <input type="search" id="softwareSearch" placeholder="Search product, host, CVE…" value="${escapeHtml(_softwareFilters.q || "")}" />
        <select id="softwareStatusFilter">
          <option value="">All statuses</option>
          <option value="missing_patch"${_softwareFilters.status === "missing_patch" ? " selected" : ""}>Missing patch</option>
          <option value="eol"${_softwareFilters.status === "eol" ? " selected" : ""}>End of life</option>
          <option value="outdated"${_softwareFilters.status === "outdated" ? " selected" : ""}>Outdated</option>
          <option value="current"${_softwareFilters.status === "current" ? " selected" : ""}>Current</option>
          <option value="up_to_date"${_softwareFilters.status === "up_to_date" ? " selected" : ""}>Up to date</option>
          <option value="unknown"${_softwareFilters.status === "unknown" ? " selected" : ""}>Unknown</option>
        </select>
        <select id="softwareSourceFilter">${sourceOpts}</select>
      </div>
      <div class="sw-coverage" aria-label="Source coverage">${covChips}</div>`;

    const summary = `
      <div class="sw-page-summary">
        ${
          window.__softwareAssetFilter?.name
            ? `<p class="hint sw-asset-filter">Filtered to host: <strong>${escapeHtml(window.__softwareAssetFilter.name)}</strong> <button type="button" class="btn-secondary" id="softwareClearAssetFilter">Show all hosts</button></p>`
            : ""
        }
        ${sourceFreshness ? `<div class="sw-source-freshness" aria-label="Inventory source freshness">${sourceFreshness}</div>` : ""}
        <div class="sw-health-row">
          <div class="sw-health-gauge" style="--p:${health}"><span>${health}%</span></div>
          <div class="sw-health-copy">
            <strong>${Number(posture.issues || 0)} issue(s) across ${Number(posture.hosts_with_issues || 0)} host(s)</strong>
            <p class="hint">${Number(posture.total_products || 0)} products from every tool — ${counts.current || 0} current · ${counts.outdated || 0} outdated · ${counts.eol || 0} EOL · ${counts.missing_patch || 0} patch gaps</p>
            <p class="hint">${Object.entries(byLabel)
              .map(([k, v]) => `${escapeHtml(k)} ${v}`)
              .join(" · ") || "Rebuild inventory after scans / SIEM / XDR / LAN sync."}</p>
          </div>
        </div>
      </div>`;

    const tableRows = rows
      .map((r) => softwareProductRowHtml(r, chipFn))
      .join("");

    window.__softwarePageCache = { rows: {}, view: _softwareView, at: Date.now() };
    rows.forEach((r) => {
      window.__softwarePageCache.rows[softwareRowKey(r)] = r;
    });
    startSoftwarePollFallback();

    el.innerHTML = `
      ${summary}
      ${viewTabs}
      ${_softwareView === "servers" ? serverPanel : `${filterBar}
      <div class="sw-table-wrap">
        <table class="ws-table sw-table">
          <thead><tr><th>Status</th><th>Product</th><th>Source</th><th>Installed</th><th>Latest</th><th>CVE</th><th>Host</th><th>Port</th></tr></thead>
          <tbody>${tableRows || `<tr><td colspan="8" class="hint">No software rows — click Sync all &amp; rebuild.</td></tr>`}</tbody>
        </table>
      </div>`}`;

    el.querySelectorAll(".sw-view-tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        _softwareView = btn.getAttribute("data-sw-view") || "servers";
        renderSoftwarePage({ quiet: true });
      });
    });
    el.querySelectorAll(".ws-server-drill").forEach((btn) => {
      btn.addEventListener("click", () => {
        window.__softwareAssetFilter = {
          id: btn.getAttribute("data-id") || "",
          name: btn.getAttribute("data-name") || "",
        };
        _softwareView = "products";
        renderSoftwarePage();
      });
    });
    el.querySelectorAll(".ws-server-remed").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const assetId = btn.getAttribute("data-id") || "";
        const assetName = btn.getAttribute("data-name") || "";
        btn.disabled = true;
        try {
          const res = await fetch("/api/software/remediations", {
            method: "POST",
            headers: authHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify({ asset_id: assetId, asset_name: assetName }),
          });
          const body = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
          if (typeof notifyUser === "function") {
            notifyUser(`**Remediation created** · ${body.title || assetName}`);
          }
        } catch (err) {
          if (typeof notifyUser === "function") {
            notifyUser(`**Remediation failed:** ${err.message || String(err)}`);
          }
        } finally {
          btn.disabled = false;
        }
      });
    });

    qs("softwareSearch")?.addEventListener("input", (e) => {
      _softwareFilters.q = e.target.value || "";
      renderSoftwarePage({ quiet: true });
    });
    qs("softwareStatusFilter")?.addEventListener("change", (e) => {
      _softwareFilters.status = e.target.value || "";
      renderSoftwarePage();
    });
    qs("softwareSourceFilter")?.addEventListener("change", (e) => {
      _softwareFilters.source = e.target.value || "";
      renderSoftwarePage();
    });
    qs("softwareClearAssetFilter")?.addEventListener("click", () => {
      window.__softwareAssetFilter = null;
      renderSoftwarePage();
    });
    el.querySelectorAll("[data-sw-source]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const src = btn.getAttribute("data-sw-source") || "";
        _softwareFilters.source = _softwareFilters.source === src ? "" : src;
        renderSoftwarePage({ quiet: true });
      });
    });
    wireSoftwareTableInteractions(el);
    const cpCount = Number((posture.coverage || {}).control_panel || 0);
    const winApps = Number((posture.windows_host || {}).installed_apps || 0);
    if (
      Math.max(cpCount, winApps) === 0 &&
      !window.__securaiqSwLocalTried &&
      typeof window.refreshLocalWindowsHost === "function"
    ) {
      window.__securaiqSwLocalTried = true;
      window.refreshLocalWindowsHost(true).then(() => renderSoftwarePage({ quiet: true })).catch(() => {});
    }
  }
  window.renderSoftwarePage = renderSoftwarePage;

  async function renderRisksPage() {
    let data = {};
    try {
      const res = await fetch("/api/risks", { headers: authHeaders() });
      data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    } catch (err) {
      const el = qs("risksPageBody");
      if (el) el.innerHTML = `<p class="hint">Could not load risks: ${escapeHtml(err.message || String(err))}</p>`;
      return;
    }
    const rows = (data.risks || [])
      .map(
        (r) => `<tr>
        <td>${escapeHtml(r.threat)}</td>
        <td>${r.likelihood}</td>
        <td>${r.impact}</td>
        <td><strong>${r.risk_score}</strong></td>
        <td>${escapeHtml(r.owner || "—")}</td>
        <td>${escapeHtml(r.status)}</td>
        <td>${escapeHtml(r.mitigation || "—")}</td>
        <td class="ws-actions">
          <button type="button" class="btn-secondary ws-ask-ai" data-kind="risk" data-json="${escapeHtml(
            JSON.stringify({
              id: r.id,
              threat: r.threat,
              risk_score: r.risk_score,
              likelihood: r.likelihood,
              impact: r.impact,
            })
          )}">Ask AI</button>
          <button type="button" class="btn-secondary ws-mitigate" data-id="${r.id}">Mitigate</button>
          <button type="button" class="btn-secondary ws-del-risk" data-id="${r.id}">Delete</button>
        </td>
      </tr>`
      )
      .join("");
    await renderTable(
      "risksPageBody",
      ["Risk", "L", "I", "Score", "Owner", "Status", "Mitigation", ""],
      rows,
      "No risks yet"
    );
    wireAskAiButtons("risksPageBody");
    qs("risksPageBody")?.querySelectorAll(".ws-mitigate").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await fetch(`/api/risks/${btn.getAttribute("data-id")}`, {
          method: "PATCH",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ status: "mitigated" }),
        });
        renderRisksPage();
        if (typeof loadCommandCenter === "function") loadCommandCenter();
      });
    });
    qs("risksPageBody")?.querySelectorAll(".ws-del-risk").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm("Delete this risk?")) return;
        await fetch(`/api/risks/${btn.getAttribute("data-id")}`, { method: "DELETE", headers: authHeaders() });
        renderRisksPage();
        if (typeof loadCommandCenter === "function") loadCommandCenter();
      });
    });
  }
  let _vulnFilters = { q: "", severity: "", status: "", source: "", owner: "" };
  let _vulnSelectedId = "";

  function vulnAgeDays(v) {
    const raw = v.created_at || v.updated_at || "";
    if (!raw) return null;
    const t = Date.parse(raw);
    if (Number.isNaN(t)) return null;
    return Math.max(0, Math.floor((Date.now() - t) / 86400000));
  }

  function fmtVulnTs(raw) {
    if (raw == null || raw === "") return "—";
    const n = Number(raw);
    if (!Number.isFinite(n)) return String(raw);
    const ms = n < 1e12 ? n * 1000 : n;
    const d = new Date(ms);
    return Number.isNaN(d.getTime()) ? String(raw) : d.toLocaleString();
  }

  function renderVulnDetail(v) {
    const panel = qs("vulnDetailPanel");
    if (!panel) return;
    if (!v) {
      panel.innerHTML = `<p class="hint vuln-detail-empty">Select a finding to see severity, guidance, and AI actions.</p>`;
      return;
    }
    const age = vulnAgeDays(v);
    const src = (v.source || "").split(":")[0] || "import";
    const refs = [];
    if (v.cve) refs.push(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve)}`);
    let raw = v.raw;
    if (typeof raw === "string") {
      try {
        raw = JSON.parse(raw);
      } catch {
        raw = null;
      }
    }
    const guidance =
      (raw && (raw.guidance || raw.note)) ||
      "";
    const scope = (raw && raw.scope) || "";
    const sev = (v.severity || "info").toLowerCase();
    const isHk = /hardeningkitty|hardening_kitty|\[hk/i.test(`${v.source || ""} ${v.title || ""}`);
    const assetBtn = v.display_asset_name || v.asset_name
      ? `<button type="button" class="entity-asset-link" data-workspace="assets" title="Open asset inventory">${escapeHtml(
          v.display_asset_name || displayAssetLabel({ name: v.asset_name, asset_name: v.asset_name })
        )}</button>`
      : "—";
    panel.innerHTML = `
      <header class="entity-detail-head">
        <p class="sev-badge sev-${escapeHtml(sev)}">${escapeHtml(sev)}</p>
        ${isHk ? `<p class="vuln-hk-badge"><span class="auto-job-status status-${v.status === "closed" ? "done" : "running"}">${v.status === "closed" ? "Hardening fixed" : "Hardening open"}</span></p>` : ""}
        <h2 class="entity-detail-title">${escapeHtml(v.title || v.cve || "Finding")}</h2>
        ${v.cve ? `<p class="entity-detail-cve">${escapeHtml(v.cve)}</p>` : ""}
      </header>
      <dl class="entity-meta">
        ${v.cvss != null ? `<div><dt>CVSS</dt><dd>${escapeHtml(v.cvss)}</dd></div>` : ""}
        <div><dt>Asset</dt><dd>${assetBtn}</dd></div>
        <div><dt>Owner</dt><dd>${escapeHtml(v.owner || "Unassigned")}</dd></div>
        <div><dt>Status</dt><dd>${escapeHtml(v.status || "open")}</dd></div>
        ${v.sla_due ? `<div><dt>SLA</dt><dd>${escapeHtml(v.sla_due)}</dd></div>` : ""}
        ${age != null ? `<div><dt>Age</dt><dd>${age}d</dd></div>` : ""}
        <div><dt>Scanner</dt><dd>${escapeHtml(src)}</dd></div>
        ${scope ? `<div><dt>Exposure</dt><dd>${escapeHtml(scope)}</dd></div>` : v.cve ? `<div><dt>Exposure</dt><dd>Check KEV / advisory</dd></div>` : ""}
      </dl>
      ${
        guidance
          ? `<section class="entity-section"><h3>Guidance</h3><p class="entity-guidance">${escapeHtml(String(guidance))}</p></section>`
          : ""
      }
      <section class="entity-section">
        <h3>AI actions</h3>
        <div class="cc-action-row entity-ai-actions">
          <button type="button" class="btn-primary-cc ws-ask-ai" data-kind="vuln" data-json="${escapeHtml(
            JSON.stringify({
              id: v.id,
              cve: v.cve,
              title: v.title,
              severity: v.severity,
              asset_name: v.asset_name,
              cvss: v.cvss,
              scope,
            })
          )}">Ask AI</button>
          <button type="button" class="btn-secondary ws-vuln-ai" data-prompt="root">Root cause</button>
          <button type="button" class="btn-secondary ws-vuln-ai" data-prompt="patch">Suggest fix</button>
          <button type="button" class="btn-secondary ws-vuln-ai" data-prompt="ticket">Ticket</button>
        </div>
      </section>
      <section class="entity-section">
        <h3>References</h3>
        <ul class="entity-refs">
          ${
            refs.length
              ? refs.map((u) => `<li><a href="${escapeHtml(u)}" target="_blank" rel="noopener">${escapeHtml(u)}</a></li>`).join("")
              : "<li class='hint'>No CVE reference</li>"
          }
        </ul>
      </section>
      <section class="entity-section entity-section-muted">
        <h3>Context</h3>
        <p class="hint">MITRE / evidence via Knowledge Graph · SLA ${escapeHtml(
          v.sla_due || "unset"
        )} · updated ${escapeHtml(fmtVulnTs(v.updated_at || v.created_at))}${
          isHk ? " · CIS baseline via HardeningKitty" : ""
        }</p>
      </section>
      <div class="cc-action-row entity-triage-actions">
        <button type="button" class="btn-primary-cc ws-triage-vuln" data-id="${escapeHtml(v.id)}" data-jira="0">Triage</button>
        <button type="button" class="btn-secondary ws-triage-vuln" data-id="${escapeHtml(v.id)}" data-jira="1">Triage+Jira</button>
        <button type="button" class="btn-secondary ws-vuln-jira" data-id="${escapeHtml(v.id)}">Jira</button>
        <button type="button" class="btn-secondary ws-vuln-sn" data-id="${escapeHtml(v.id)}" data-title="${escapeHtml(v.title || v.cve || "")}">ServiceNow</button>
        <button type="button" class="btn-secondary ws-close-vuln" data-id="${escapeHtml(v.id)}">Close</button>
        <button type="button" class="btn-secondary ws-del-vuln" data-id="${escapeHtml(v.id)}">Delete</button>
      </div>`;
    wireAskAiButtons("vulnDetailPanel");
    wireVulnActionButtons(panel);
    panel.querySelectorAll("[data-workspace]").forEach((el) => {
      el.addEventListener("click", (e) => {
        e.preventDefault();
        if (typeof showWorkspace === "function") showWorkspace(el.getAttribute("data-workspace"));
      });
    });
    panel.querySelectorAll(".ws-vuln-ai").forEach((btn) => {
      btn.addEventListener("click", () => {
        const kind = btn.getAttribute("data-prompt");
        const scopeHint =
          /127\.|localhost|::1/i.test(String(v.asset_name || "")) || scope === "loopback"
            ? " Asset is loopback — not remotely exposed; focus on local Windows hardening for SMB/RDP, not internet RCE."
            : scope === "private" || /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(String(v.asset_name || ""))
              ? " Asset is private/lab RFC1918. For SMB/445 RPC/135 NetBIOS/139: treat as expected Windows LAN (info), not internet High ransomware. Prefer real Windows firewall / SMB signing steps. Never invent CLIs."
              : "";
        const prompts = {
          root: `Root-cause analysis for ${v.cve || ""} — ${v.title || v.id} on asset ${v.asset_name || "?"} (severity=${v.severity}, exposure=${scope || "unknown"}).${scopeHint} Include realistic blast radius only.`,
          patch: `Suggest fix and verify steps for ${v.cve || ""} — ${v.title || v.id} (severity=${v.severity}, CVSS=${v.cvss ?? "?"}, exposure=${scope || "unknown"}).${scopeHint} Use only real tools/commands.`,
          ticket: `Draft a Jira-ready remediation ticket for ${v.cve || ""} — ${v.title || v.id} with acceptance criteria and SLA matching true exposure (${scope || v.severity}).${scopeHint}`,
        };
        if (typeof window.runNavPrompt === "function") {
          window.runNavPrompt("blueteam", prompts[kind] || prompts.patch, { stay: true });
        }
      });
    });
  }

  function wireVulnActionButtons(root) {
    root?.querySelectorAll(".ws-triage-vuln").forEach((btn) => {
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        const withJira = btn.getAttribute("data-jira") === "1";
        try {
          const res = await fetch(`/api/vulnerabilities/${btn.getAttribute("data-id")}/triage`, {
            method: "POST",
            headers: authHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify({ owner: "SecOps", create_jira: withJira }),
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(data.detail || res.status);
          if (typeof notifyUser === "function") {
            let msg = `**Triaged** → risk \`${(data.risk || {}).risk_score ?? "?"}\` · remediation created.`;
            if (withJira) {
              if (data.jira?.key) {
                msg += data.jira.url
                  ? ` Jira: [${data.jira.key}](${data.jira.url}).`
                  : ` Jira: \`${data.jira.key}\`.`;
              } else if (data.jira_error) {
                msg += ` Jira failed: ${data.jira_error}`;
              }
            }
            notifyUser(msg);
          }
          renderVulnsPage();
      loadVulnSampleButtons();
          if (typeof loadCommandCenter === "function") loadCommandCenter();
        } catch (err) {
          if (typeof notifyUser === "function") notifyUser(`**Triage failed:** ${err.message}`);
          else alert(err.message);
        } finally {
          btn.disabled = false;
        }
      });
    });
    root?.querySelectorAll(".ws-vuln-jira").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          const res = await fetch(`/api/vulnerabilities/${btn.getAttribute("data-id")}/jira`, {
            method: "POST",
            headers: authHeaders(),
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(data.detail || res.status);
          if (typeof notifyUser === "function") {
            notifyUser(data.url ? `**Jira:** [${data.key}](${data.url})` : `**Jira:** ${data.key || "created"}`);
          }
        } catch (err) {
          if (typeof notifyUser === "function") notifyUser(`**Jira failed:** ${err.message}`);
          else alert(err.message);
        }
      });
    });
    root?.querySelectorAll(".ws-vuln-sn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const title = btn.getAttribute("data-title") || "Vulnerability";
        await createServiceNowIncident(
          {
            summary: `[SecuraIQ] ${title}`.slice(0, 160),
            description: `Vulnerability ${btn.getAttribute("data-id")} from SecuraIQ register.`,
          },
          btn
        );
      });
    });
    root?.querySelectorAll(".ws-close-vuln").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await fetch(`/api/vulnerabilities/${btn.getAttribute("data-id")}`, {
          method: "PATCH",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ status: "closed" }),
        });
        renderVulnsPage();
      loadVulnSampleButtons();
        if (typeof loadCommandCenter === "function") loadCommandCenter();
      });
    });
    root?.querySelectorAll(".ws-del-vuln").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm("Delete this finding? This cannot be undone.")) return;
        const id = btn.getAttribute("data-id");
        try {
          const res = await fetch(`/api/vulnerabilities/${id}`, { method: "DELETE", headers: authHeaders() });
          if (!res.ok) {
            const d = await res.json().catch(() => ({}));
            throw new Error(d.detail || `HTTP ${res.status}`);
          }
          _vulnCache = _vulnCache.filter((v) => v.id !== id);
          if (_vulnSelectedId === id) _vulnSelectedId = "";
          paintVulnTable();
          if (typeof loadCommandCenter === "function") loadCommandCenter();
        } catch (err) {
          if (typeof notifyUser === "function") notifyUser(`**Delete failed:** ${err.message || err}`);
          else alert(err.message || "Delete failed");
        }
      });
    });
  }

  function filteredVulns() {
    const f = _vulnFilters;
    const q = (f.q || "").trim().toLowerCase();
    return _vulnCache.filter((v) => {
      if (f.severity && (v.severity || "").toLowerCase() !== f.severity) return false;
      if (f.status && (v.status || "").toLowerCase() !== f.status) return false;
      if (f.source) {
        const src = ((v.source || "").split(":")[0] || "").toLowerCase();
        if (src !== f.source) return false;
      }
      if (f.owner && !(v.owner || "").toLowerCase().includes(f.owner.toLowerCase())) return false;
      if (q) {
        const blob = `${v.cve || ""} ${v.title || ""} ${v.asset_name || ""} ${v.display_asset_name || ""} ${v.owner || ""}`.toLowerCase();
        if (!blob.includes(q)) return false;
      }
      return true;
    });
  }

  function paintVulnTable() {
    const list = filteredVulns().slice(0, 200);
    const rows = list
      .map((v) => {
        const src = (v.source || "").split(":")[0] || "—";
        const srcLabel = /^zap$/i.test(src)
          ? "SecuraIQ Web Scanner live"
          : /^securaiq|nmap|nuclei|zap$/i.test(src)
            ? `${src} live`
            : src;
        const selected = v.id === _vulnSelectedId ? " is-selected" : "";
        const assetCell = v.display_asset_name || v.asset_name
          ? `<button type="button" class="vuln-asset-link" data-workspace="assets">${escapeHtml(
              v.display_asset_name || displayAssetLabel({ name: v.asset_name, asset_name: v.asset_name })
            )}</button>`
          : "—";
        let raw = v.raw;
        if (typeof raw === "string") {
          try {
            raw = JSON.parse(raw);
          } catch {
            raw = null;
          }
        }
        const ev = ((raw && (raw.evidence || raw.note)) || "").toString().slice(0, 80);
        return `<tr class="vuln-row${selected}" data-id="${escapeHtml(v.id)}" tabindex="0">
        <td><strong>${escapeHtml(v.title || v.cve || "Finding")}</strong>${
          ev ? `<div class="hint">${escapeHtml(ev)}</div>` : ""
        }</td>
        <td>${escapeHtml(v.cve || "—")}</td>
        <td><span class="sev sev-${escapeHtml(v.severity)}">${escapeHtml(v.severity)}</span></td>
        <td>${assetCell}</td>
        <td>${escapeHtml(v.status)}</td>
        <td>${escapeHtml(srcLabel)}</td>
      </tr>`;
      })
      .join("");
    const el = qs("vulnsPageBody");
    if (!el) return;
    if (!rows) {
      el.innerHTML = `<div class="page-empty">
        <p class="page-empty-title">No matching vulnerabilities</p>
        <p class="hint">Run New scan on a host you own, or import a scanner export (Trivy, Semgrep, ZAP, …).</p>
      </div>`;
      renderVulnDetail(null);
      return;
    }
    el.innerHTML = `
      <p class="hint">Live findings from scans on hosts you own — duplicates from earlier auto-scans are merged. Showing ${list.length} of ${_vulnCache.length}.</p>
      <div class="data-table-wrap">
        <table class="data-table vuln-table">
          <thead><tr>
            <th>Finding</th><th>CVE</th><th>Severity</th><th>Asset</th>
            <th>Status</th><th>Source</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
    el.querySelectorAll(".vuln-row").forEach((row) => {
      const open = () => {
        _vulnSelectedId = row.getAttribute("data-id") || "";
        const v = _vulnCache.find((x) => x.id === _vulnSelectedId);
        el.querySelectorAll(".vuln-row").forEach((r) => r.classList.toggle("is-selected", r === row));
        renderVulnDetail(v || null);
      };
      row.addEventListener("click", (e) => {
        if (e.target.closest?.("[data-workspace]")) return;
        open();
      });
      row.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          open();
        }
      });
    });
    if (_vulnSelectedId) {
      const still = list.find((v) => v.id === _vulnSelectedId) || list[0];
      _vulnSelectedId = still?.id || "";
      renderVulnDetail(still || null);
    } else if (list[0]) {
      _vulnSelectedId = list[0].id;
      renderVulnDetail(list[0]);
      el.querySelector(`.vuln-row[data-id="${String(list[0].id).replace(/"/g, "")}"]`)?.classList.add("is-selected");
    }
    el.querySelectorAll("[data-workspace]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (typeof showWorkspace === "function") showWorkspace(btn.getAttribute("data-workspace"));
      });
    });
  }

  function paintVulnFilters() {
    const bar = qs("vulnFilterBar");
    if (!bar) return;
    const sevs = [...new Set(_vulnCache.map((v) => (v.severity || "").toLowerCase()).filter(Boolean))];
    const statuses = [...new Set(_vulnCache.map((v) => (v.status || "").toLowerCase()).filter(Boolean))];
    const sources = [
      ...new Set(_vulnCache.map((v) => ((v.source || "").split(":")[0] || "").toLowerCase()).filter(Boolean)),
    ];
    bar.innerHTML = `
      <input type="search" id="vulnFilterQ" class="filter-input" placeholder="Search CVE, title, asset…" value="${escapeHtml(
        _vulnFilters.q
      )}" />
      <select id="vulnFilterSev" class="filter-select" title="Severity">
        <option value="">Severity</option>
        ${sevs.map((s) => `<option value="${escapeHtml(s)}" ${_vulnFilters.severity === s ? "selected" : ""}>${escapeHtml(s)}</option>`).join("")}
      </select>
      <select id="vulnFilterStatus" class="filter-select" title="Status">
        <option value="">Status</option>
        ${statuses
          .map((s) => `<option value="${escapeHtml(s)}" ${_vulnFilters.status === s ? "selected" : ""}>${escapeHtml(s)}</option>`)
          .join("")}
      </select>
      <select id="vulnFilterSource" class="filter-select" title="Scanner">
        <option value="">Scanner</option>
        ${sources
          .map((s) => `<option value="${escapeHtml(s)}" ${_vulnFilters.source === s ? "selected" : ""}>${escapeHtml(s)}</option>`)
          .join("")}
      </select>
      <input type="text" id="vulnFilterOwner" class="filter-input filter-input-sm" placeholder="Owner" value="${escapeHtml(
        _vulnFilters.owner
      )}" />
      <button type="button" class="btn-ghost" id="vulnFilterReset">Reset</button>`;
    const sync = () => {
      _vulnFilters = {
        q: qs("vulnFilterQ")?.value || "",
        severity: qs("vulnFilterSev")?.value || "",
        status: qs("vulnFilterStatus")?.value || "",
        source: qs("vulnFilterSource")?.value || "",
        owner: qs("vulnFilterOwner")?.value || "",
      };
      paintVulnTable();
    };
    ["vulnFilterQ", "vulnFilterSev", "vulnFilterStatus", "vulnFilterSource", "vulnFilterOwner"].forEach((id) => {
      qs(id)?.addEventListener("input", sync);
      qs(id)?.addEventListener("change", sync);
    });
    qs("vulnFilterReset")?.addEventListener("click", () => {
      _vulnFilters = { q: "", severity: "", status: "", source: "", owner: "" };
      paintVulnFilters();
      paintVulnTable();
    });
  }

  async function renderVulnSummaryBar() {
    const el = qs("vulnSummaryBar");
    if (!el) return;
    const total = _vulnCache.length;
    const assets = [
      ...new Set(
        _vulnCache.map((v) => v.display_asset_name || displayAssetLabel({ name: v.asset_name, asset_name: v.asset_name })).filter(Boolean)
      ),
    ];
    const open = _vulnCache.filter((v) => (v.status || "open") === "open").length;
    const hkOpen = _vulnCache.filter(
      (v) => /hardeningkitty/i.test(v.source || "") && (v.status || "open") === "open"
    ).length;
    let hk = {};
    try {
      const dash = await fetch("/api/dashboard", { headers: authHeaders() });
      if (dash.ok) {
        const d = await dash.json();
        hk = d.hardening || {};
      }
    } catch {
      /* ignore */
    }
    let hkChip = `<span class="auto-job-status status-planned">Hardening: not installed</span>`;
    if (hk.audit_done) {
      hkChip = `<span class="auto-job-status status-done">Hardening audit done</span>`;
    } else if (hk.installed) {
      hkChip = `<span class="auto-job-status status-running">Hardening: run audit</span>`;
    }
    el.innerHTML = `
      <div class="vuln-summary-metrics">
        <strong>${total}</strong> findings · <strong>${open}</strong> open · <strong>${assets.length}</strong> assets
        ${hkOpen ? ` · <strong>${hkOpen}</strong> hardening open` : ""}
      </div>
      <div class="vuln-summary-actions">
        ${hkChip}
        ${
          assets.length
            ? `<button type="button" class="btn-secondary" data-workspace="assets">View assets (${assets.length})</button>`
            : `<button type="button" class="btn-secondary" data-action="new-scan">New scan</button>`
        }
        ${
          hk.installed && !hk.audit_done
            ? `<button type="button" class="btn-secondary" id="hkVulnSummaryAudit">Run hardening audit</button>`
            : ""
        }
      </div>`;
    el.querySelectorAll("[data-workspace]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        if (typeof showWorkspace === "function") showWorkspace(btn.getAttribute("data-workspace"));
      });
    });
    el.querySelector("#hkVulnSummaryAudit")?.addEventListener("click", () => {
      if (typeof window.runHardeningKittyAudit === "function") window.runHardeningKittyAudit();
    });
    const details = qs("vulnSourcesDetails");
    if (details && total > 0) details.open = false;
  }

  async function renderHkVulnPanel() {
    const el = qs("hkVulnPanelBody");
    if (!el) return;
    try {
      const [stRes, dashRes] = await Promise.all([
        fetch("/api/hardeningkitty/status", { headers: authHeaders() }),
        fetch("/api/dashboard", { headers: authHeaders() }).catch(() => null),
      ]);
      const st = await stRes.json().catch(() => ({}));
      const dash = dashRes && dashRes.ok ? await dashRes.json().catch(() => ({})) : {};
      const hk = dash.hardening || {};
      const runs = st.recent_runs || [];
      const auditDone = Boolean(hk.audit_done);
      const installed = Boolean(st.installed || hk.installed);
      let chip = `<span class="auto-job-status status-planned">Not installed</span>`;
      if (auditDone) chip = `<span class="auto-job-status status-done">Audit done</span>`;
      else if (installed) chip = `<span class="auto-job-status status-running">Ready — not audited</span>`;
      const hkFindings = _vulnCache.filter((v) => /hardeningkitty/i.test(v.source || ""));
      const hkOpen = hkFindings.filter((v) => (v.status || "open") === "open").length;
      el.innerHTML = `
        <p class="vuln-source-status">${chip}
          <span class="hint">${hkOpen} open / ${hkFindings.length} total HK findings</span>
        </p>
        ${
          !installed
            ? `<p class="hint">Not installed on this host yet.</p>
               <details class="hk-setup-advanced">
                 <summary>Advanced: install manually</summary>
                 <code class="hk-setup-code">.\\scripts\\use_hardeningkitty.cmd -Download</code>
               </details>`
            : auditDone
              ? `<p class="hint">Last score ${hk.last_score != null ? escapeHtml(String(hk.last_score)) : "—"} · failed ${hk.last_failed || 0} · imported ${hk.last_imported || 0}</p>`
              : `<p class="hint">${Number(st.finding_lists) || 0} CIS lists ready — run Audit to populate findings.</p>`
        }
        ${
          runs.length
            ? `<ul class="cc-list">${runs
                .slice(0, 3)
                .map(
                  (r) =>
                    `<li><strong>${escapeHtml(r.mode || "")}</strong> · score ${
                      r.score != null ? escapeHtml(String(r.score)) : "—"
                    } · failed ${r.failed || 0}</li>`
                )
                .join("")}</ul>`
            : ""
        }`;
    } catch (err) {
      el.innerHTML = `<p class="hint">Couldn't load the hardening panel — try refreshing. <span class="hint-sub">(${escapeHtml(err.message)})</span></p>`;
    }
  }

  function wireHkVulnAuditBtn() {
    const btn = qs("hkVulnAuditBtn");
    if (!btn || btn.dataset.wired) return;
    btn.dataset.wired = "1";
    btn.addEventListener("click", () => {
      if (typeof window.runHardeningKittyAudit === "function") window.runHardeningKittyAudit();
      else if (typeof showWorkspace === "function") showWorkspace("frameworks");
    });
  }

  async function renderVulnsPage(opts) {
    const quiet = !!(opts && opts.quiet);
    let data = {};
    try {
      const res = await fetch("/api/vulnerabilities", { headers: authHeaders() });
      data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    } catch (err) {
      if (!quiet) {
        const el = qs("vulnsPageBody");
        if (el) el.innerHTML = `<p class="hint">Could not load vulnerabilities: ${escapeHtml(err.message || String(err))}</p>`;
      }
      return;
    }
    _vulnCache = data.vulnerabilities || [];
    if (!quiet) paintVulnFilters();
    await renderVulnSummaryBar();
    paintVulnTable();
    if (quiet) return;
    renderCloudPosturePanel();
    renderSonarPanel();
    renderHkVulnPanel();
    wireCloudSyncBtn();
    wireCloudImportBtn();
    wireSonarSyncBtns();
    wireCodeScanUi();
    wireHkVulnAuditBtn();
  }

  async function renderSonarPanel() {
    const el = qs("sonarPanelBody");
    if (!el) return;
    const pathEl = qs("codeScanPath");
    if (pathEl && !pathEl.value) {
      const fromLive =
        (typeof window.getScanTarget === "function" && window.getScanTarget()) ||
        (document.getElementById("scanTargetIp") || {}).value ||
        "";
      if (fromLive && (/[\\/]/.test(fromLive) || fromLive.length > 2)) {
        pathEl.value = fromLive;
      }
    }
    try {
      const res = await fetch("/api/code/status", { headers: authHeaders() });
      const st = await res.json().catch(() => ({}));
      const ping = st.ping || {};
      const chip = st.configured
        ? ping.ok
          ? `<span class="auto-job-status status-done">connected</span>`
          : `<span class="auto-job-status status-error">error</span>`
        : `<span class="auto-job-status status-planned">local SAST</span>`;
      el.innerHTML = `
        <p class="vuln-source-status">${chip}${
          st.base_url ? ` <span class="hint">${escapeHtml(st.base_url)}</span>` : ""
        }${st.project_key ? ` <span class="hint">· ${escapeHtml(st.project_key)}</span>` : ""}</p>
        <p class="hint">${
          st.configured
            ? ping.ok
              ? `Engine ready · ${escapeHtml(String(ping.status || "UP"))}${ping.version ? ` · v${escapeHtml(String(ping.version))}` : ""}`
              : escapeHtml(ping.error || "Connection failed — check Settings → SecuraIQ Code")
            : "Path + Auth → Scan folder. Findings stream into the register. Optional engine Sync in Settings."
        }</p>`;
    } catch (err) {
      el.innerHTML = `<p class="hint">Couldn't load the code scan panel — try refreshing. <span class="hint-sub">(${escapeHtml(err.message)})</span></p>`;
    }
  }

  function setCodeScanLive(text, show) {
    const live = qs("codeScanLive");
    if (!live) return;
    if (!show) {
      live.hidden = true;
      live.textContent = "";
      return;
    }
    live.hidden = false;
    live.textContent = text || "";
  }

  async function runCodeFolderScan() {
    const pathEl = qs("codeScanPath");
    const authEl = qs("codeScanAuth");
    const btn = qs("codeScanRunBtn");
    const path = ((pathEl && pathEl.value) || "").trim();
    const authorized = !!(authEl && authEl.checked);
    if (!path) {
      if (typeof notifyUser === "function") {
        notifyUser("**Set a local project path** in SecuraIQ Code (folder you own), then Scan folder.");
      }
      pathEl?.focus();
      return;
    }
    if (typeof window.setScanTarget === "function") {
      window.setScanTarget(path, authorized);
    } else {
      const liveTarget = document.getElementById("scanTargetIp");
      const liveAuth = document.getElementById("scanAuthorized");
      if (liveTarget) liveTarget.value = path;
      if (liveAuth) liveAuth.checked = authorized;
    }
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Scanning…";
    }
    setCodeScanLive("Starting code analysis…", true);
    if (typeof setLiveState === "function") {
      setLiveState("live-busy", "Code analysis…", path);
    }
    try {
      const res = await fetch("/api/code/scan/stream", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ path, authorized, sync_engine: false }),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(errBody.detail || `HTTP ${res.status}`);
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      let data = null;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const parts = buf.split("\n");
        buf = parts.pop() || "";
        for (const line of parts) {
          const raw = line.trim();
          if (!raw) continue;
          let ev;
          try {
            ev = JSON.parse(raw);
          } catch {
            continue;
          }
          if (ev.event === "tool_progress") {
            const scanned = Number(ev.scanned || 0);
            const total = Number(ev.total || 0);
            const findings = Number(ev.findings || 0);
            setCodeScanLive(
              `Scanning ${scanned}/${total || "?"} · ${findings} hit(s)${ev.file ? ` · ${ev.file}` : ""}`,
              true
            );
            if (typeof setLiveState === "function") {
              setLiveState(
                "live-busy",
                `Code scan ${scanned}/${total || "?"}`,
                `${findings} findings`
              );
            }
          } else if (ev.event === "tool_start") {
            setCodeScanLive(`Running ${ev.name || ev.tool}…`, true);
          } else if (ev.event === "done") {
            data = ev.payload || {};
          }
        }
      }
      const vp = (data && data.vulnerabilities_persisted) || {};
      const created = Number(vp.created || 0);
      const ok = !!(data && data.ok);
      setCodeScanLive(
        ok
          ? `Done · ${created} finding(s) saved${vp.asset_name ? ` · asset ${vp.asset_name}` : ""}`
          : `Finished with errors · ${(data && data.error) || "see chat / tool output"}`,
        true
      );
      if (typeof notifyUser === "function") {
        notifyUser(
          ok
            ? `**Code analysis complete** · **${created}** finding(s) live in Vulnerabilities`
            : `**Code analysis issue:** ${(data && data.error) || "see output"}`
        );
      }
      renderSonarPanel();
      renderVulnsPage();
      if (typeof loadCommandCenter === "function") loadCommandCenter();
      if (typeof loadAssets === "function") loadAssets();
      if (typeof setLiveState === "function") setLiveState("live-on", "Ready", "");
    } catch (err) {
      setCodeScanLive(`Failed: ${err.message || err}`, true);
      if (typeof notifyUser === "function") notifyUser(`**Code scan failed:** ${err.message || err}`);
      if (typeof setLiveState === "function") setLiveState("live-off", "Code scan error", "");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Scan folder";
      }
    }
  }

  function wireCodeScanUi() {
    const runBtn = qs("codeScanRunBtn");
    if (runBtn && !runBtn.dataset.wired) {
      runBtn.dataset.wired = "1";
      runBtn.addEventListener("click", () => runCodeFolderScan());
    }
    const pathEl = qs("codeScanPath");
    if (pathEl && !pathEl.dataset.wired) {
      pathEl.dataset.wired = "1";
      pathEl.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          runCodeFolderScan();
        }
      });
    }
    const openBtn = qs("vulnsOpenCodeScan");
    if (openBtn && !openBtn.dataset.wired) {
      openBtn.dataset.wired = "1";
      openBtn.addEventListener("click", () => {
        const panel = qs("sonarPanel");
        panel?.scrollIntoView({ behavior: "smooth", block: "start" });
        qs("codeScanPath")?.focus();
      });
    }
  }

  function wireSonarSyncBtns() {
    ["sonarSyncBtn", "sonarPanelSyncBtn"].forEach((id) => {
      const btn = qs(id);
      if (!btn || btn.dataset.wired) return;
      btn.dataset.wired = "1";
      btn.addEventListener("click", async () => {
        const label = btn.textContent;
        btn.disabled = true;
        btn.textContent = "Syncing…";
        try {
          const res = await fetch("/api/code/sync", { method: "POST", headers: authHeaders() });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) {
            if (typeof notifyUser === "function") {
              notifyUser(`**SecuraIQ Code sync failed:** ${data.detail || res.status}`);
            }
            return;
          }
          if (typeof notifyUser === "function") {
            notifyUser(`**SecuraIQ Code sync queued** · job \`${(data.job && data.job.id) || "?"}\``);
          }
          const jobId = data.job && data.job.id;
          if (jobId && typeof window.waitForJob === "function") {
            await window.waitForJob(jobId, { timeoutMs: 180000 });
          }
          renderSonarPanel();
          renderVulnsPage();
        } catch (err) {
          if (typeof notifyUser === "function") notifyUser(`**SecuraIQ Code sync failed:** ${err.message || err}`);
        } finally {
          btn.disabled = false;
          btn.textContent = label || "Sync";
        }
      });
    });
  }

  async function renderCloudPosturePanel() {
    const el = qs("cloudPosturePanelBody");
    if (!el) return;
    try {
      const [stRes, findRes] = await Promise.all([
        fetch("/api/cloud/status", { headers: authHeaders() }),
        fetch("/api/cloud/findings?limit=8", { headers: authHeaders() }),
      ]);
      const st = await stRes.json().catch(() => ({}));
      const findData = await findRes.json().catch(() => ({}));
      const vendors = st.vendors || {};
      const vendorLabels = {
        aws_security_hub: "AWS Security Hub",
        azure_defender: "Azure Defender",
        gcp_scc: "GCP SCC",
      };
      const ping = st.ping || {};
      const vendorChips = `<ul class="integ-status-list">${Object.entries(vendors)
        .map(([id, v]) => {
          const p = ping[id] || {};
          const ok = v.configured && p.ok;
          const err = v.configured && !p.ok ? p.error : "";
          return `<li class="${ok ? "ok" : v.configured ? "warn" : "muted"}"><span>${escapeHtml(
            vendorLabels[id] || id
          )}</span><strong>${v.configured ? (ok ? "Connected" : err || "error") : "Not configured"}</strong></li>`;
        })
        .join("")}</ul>`;
      const findings = findData.findings || [];
      const findingsHtml = findings.length
        ? findings
            .map(
              (f) =>
                `<li><strong>${escapeHtml(f.severity || "?")}</strong> [${escapeHtml(f.vendor || "")}] ${escapeHtml(
                  f.title || ""
                )}${f.resource ? ` — <code>${escapeHtml(f.resource)}</code>` : ""}</li>`
            )
            .join("")
        : `<li class="hint">${
            (st.configured_count || 0) > 0
              ? "No findings synced yet — click Sync cloud"
              : "Configure AWS, Azure, or GCP in Settings, or import JSON via API"
          }</li>`;
      el.innerHTML = `
        ${vendorChips}
        <div class="vuln-cloud-kpis">
          <article class="cc-kpi"><span>Cached</span><strong>${st.findings_cached || 0}</strong></article>
          <article class="cc-kpi"><span>Vendors</span><strong>${st.configured_count || 0}</strong></article>
        </div>
        <p class="hint vuln-cloud-label">Recent cloud findings</p>
        <ul class="cc-list">${findingsHtml}</ul>
        <p class="hint">Settings → Cloud posture to connect Security Hub / Defender / SCC.</p>`;
    } catch (err) {
      el.innerHTML = `<p class="hint">Couldn't load cloud posture — try refreshing. <span class="hint-sub">(${escapeHtml(err.message)})</span></p>`;
    }
  }

  function wireCloudImportBtn() {
    const btn = qs("cloudImportBtn");
    const input = qs("cloudImportInput");
    if (!btn || !input || btn.dataset.wired) return;
    btn.dataset.wired = "1";
    btn.addEventListener("click", () => input.click());
    input.addEventListener("change", async () => {
      const file = input.files?.[0];
      input.value = "";
      if (!file) return;
      btn.disabled = true;
      btn.textContent = "Importing…";
      try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        const findings = Array.isArray(parsed) ? parsed : parsed.findings || [];
        if (!findings.length) throw new Error("JSON must be an array of findings or { findings: [...] }");
        const res = await fetch("/api/cloud/import", {
          method: "POST",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({
            vendor: parsed.vendor || "cloud_import",
            findings,
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || `Import failed (${res.status})`);
        if (typeof notifyUser === "function") {
          notifyUser(`**Cloud import OK** · ${data.imported ?? findings.length} finding(s)`);
        }
        renderVulnsPage();
      } catch (err) {
        if (typeof notifyUser === "function") notifyUser(`**Cloud import failed:** ${err.message || err}`);
      } finally {
        btn.disabled = false;
        btn.textContent = "Import JSON";
      }
    });
  }

  function wireCloudSyncBtn() {
    const btn = qs("cloudSyncBtn");
    if (!btn || btn.dataset.wired) return;
    btn.dataset.wired = "1";
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      btn.textContent = "Syncing…";
      try {
        const res = await fetch("/api/cloud/sync", { method: "POST", headers: authHeaders() });
        const data = await res.json().catch(() => ({}));
        if (!res.ok && typeof notifyUser === "function") {
          notifyUser(`**Cloud sync failed:** ${data.detail || res.status}`);
        } else if (typeof notifyUser === "function") {
          notifyUser(`**Cloud sync queued** · job \`${(data.job && data.job.id) || "?"}\``);
        }
        const jobId = data.job && data.job.id;
        if (jobId && typeof window.waitForJob === "function") {
          await window.waitForJob(jobId, { timeoutMs: 120000 });
        }
      } catch (err) {
        if (typeof notifyUser === "function") notifyUser(`**Cloud sync error:** ${err.message || err}`);
      }
      renderVulnsPage();
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Sync cloud";
      }
    });
  }
  window.renderVulnsPage = renderVulnsPage;

  async function renderRemsPage() {
    const res = await fetch("/api/gap/remediations", { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      await renderTable(
        "remsPageBody",
        ["Control", "Title", "Owner", "Status", "Due", ""],
        "",
        `Failed to load remediations (${res.status})`
      );
      if (typeof notifyUser === "function") {
        notifyUser(
          `**Remediations:** ${
            typeof window.formatApiDetail === "function"
              ? window.formatApiDetail(data.detail, res.status)
              : res.status
          }`
        );
      }
      return;
    }
    const rows = (data.remediations || [])
      .map(
        (r) => `<tr>
        <td>${escapeHtml(r.control_id)}</td>
        <td>${escapeHtml(r.title)}</td>
        <td>${escapeHtml(r.owner || "unassigned")}</td>
        <td>${escapeHtml(r.status)}</td>
        <td>${escapeHtml(r.due_date || "—")}</td>
        <td class="ws-actions">
          ${
            r.status !== "done"
              ? `<button type="button" class="btn-secondary ws-rem-done" data-id="${r.id}">Mark done</button>`
              : ""
          }
          <button type="button" class="btn-secondary ws-ask-ai" data-kind="remediation" data-json="${escapeHtml(
            JSON.stringify({ id: r.id, control_id: r.control_id, title: r.title })
          )}">Ask AI</button>
          <button type="button" class="btn-secondary ws-rem-jira" data-id="${r.id}" data-title="${escapeHtml(
            r.title
          )}" data-control="${escapeHtml(r.control_id)}">Jira</button>
          <button type="button" class="btn-secondary ws-rem-sn" data-id="${r.id}" data-title="${escapeHtml(
            r.title
          )}" data-control="${escapeHtml(r.control_id)}">ServiceNow</button>
          <button type="button" class="btn-secondary ws-rem-del" data-id="${r.id}">Delete</button>
        </td>
      </tr>`
      )
      .join("");
    await renderTable(
      "remsPageBody",
      ["Control", "Title", "Owner", "Status", "Due", ""],
      rows,
      "No remediations — run Gap analysis"
    );
    wireAskAiButtons("remsPageBody");
    qs("remsPageBody")?.querySelectorAll(".ws-rem-done").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await fetch(`/api/gap/remediations/${btn.getAttribute("data-id")}`, {
          method: "PATCH",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ status: "done" }),
        });
        renderRemsPage();
        if (typeof loadCommandCenter === "function") loadCommandCenter();
      });
    });
    qs("remsPageBody")?.querySelectorAll(".ws-rem-del").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm("Delete this remediation/control task?")) return;
        const id = btn.getAttribute("data-id");
        try {
          const res = await fetch(`/api/gap/remediations/${id}`, { method: "DELETE", headers: authHeaders() });
          if (!res.ok) {
            const d = await res.json().catch(() => ({}));
            throw new Error(d.detail || `HTTP ${res.status}`);
          }
          renderRemsPage();
          if (typeof loadCommandCenter === "function") loadCommandCenter();
        } catch (err) {
          if (typeof notifyUser === "function") notifyUser(`**Delete failed:** ${err.message || err}`);
          else alert(err.message || "Delete failed");
        }
      });
    });
    qs("remsPageBody")?.querySelectorAll(".ws-rem-jira").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-id");
        const title = btn.getAttribute("data-title") || "Remediation";
        const control = btn.getAttribute("data-control") || "";
        btn.disabled = true;
        try {
          const res = await fetch("/api/integrations/jira/issue", {
            method: "POST",
            headers: authHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify({
              remediation_id: id,
              summary: `[SecuraIQ] ${control} — ${title}`.slice(0, 255),
            }),
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(
            typeof window.formatApiDetail === "function"
              ? window.formatApiDetail(data.detail, `HTTP ${res.status}`)
              : data.detail || `HTTP ${res.status}`
          );
          const msg = data.url
            ? `**Jira created:** [${data.key}](${data.url})`
            : `**Jira created:** ${data.key || "ok"}`;
          if (typeof window.notifyUser === "function") window.notifyUser(msg);
          else if (typeof appendMessage === "function") appendMessage("assistant", renderMarkdown(msg), true);
          else alert(data.key || "Jira issue created");
        } catch (err) {
          if (typeof window.notifyUser === "function") window.notifyUser(`**Jira failed:** ${err.message}`);
          else if (typeof appendMessage === "function")
            appendMessage("assistant", renderMarkdown(`**Jira failed:** ${err.message}`), true);
          else alert(err.message);
        } finally {
          btn.disabled = false;
        }
      });
    });
    qs("remsPageBody")?.querySelectorAll(".ws-rem-sn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const title = btn.getAttribute("data-title") || "Remediation";
        const control = btn.getAttribute("data-control") || "";
        await createServiceNowIncident(
          {
            summary: `[SecuraIQ] ${control} — ${title}`.slice(0, 160),
            remediationId: btn.getAttribute("data-id"),
          },
          btn
        );
      });
    });
    if (!window.__securaiqRemFormWired) {
      window.__securaiqRemFormWired = true;
      qs("remCreateForm")?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const title = qs("remNewTitle")?.value?.trim();
        if (!title) return;
        const res = await fetch("/api/gap/remediations", {
          method: "POST",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({
            title,
            control_id: qs("remNewControl")?.value?.trim() || "MC",
            owner: qs("remNewOwner")?.value?.trim() || "",
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          alert(data.detail || `HTTP ${res.status}`);
          return;
        }
        qs("remNewTitle").value = "";
        qs("remNewControl").value = "";
        qs("remNewOwner").value = "";
        renderRemsPage();
        if (typeof loadCommandCenter === "function") loadCommandCenter();
      });
    }
  }
  window.renderRemsPage = renderRemsPage;

  async function renderPlaybooksPage() {
    const res = await fetch("/api/playbooks", { headers: authHeaders() });
    const data = await res.json();
    const rows = (data.playbooks || [])
      .map(
        (p) => `<tr>
        <td><strong>${escapeHtml(p.title)}</strong></td>
        <td>${escapeHtml(p.category)}</td>
        <td>${escapeHtml(p.severity)}</td>
        <td><pre class="mini-pre">${escapeHtml(p.steps || "")}</pre></td>
        <td class="ws-actions">
          <button type="button" class="btn-secondary ws-ask-ai" data-kind="playbook" data-json="${escapeHtml(
            JSON.stringify({ id: p.id, title: p.title })
          )}">Ask AI</button>
          <button type="button" class="btn-secondary ws-pb-del" data-id="${escapeHtml(p.id)}">Delete</button>
        </td>
      </tr>`
      )
      .join("");
    await renderTable("playbooksPageBody", ["Title", "Category", "Severity", "Steps", ""], rows, "No playbooks");
    wireAskAiButtons("playbooksPageBody");
    qs("playbooksPageBody")?.querySelectorAll(".ws-pb-del").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm("Delete this playbook?")) return;
        await fetch(`/api/playbooks/${btn.getAttribute("data-id")}`, { method: "DELETE", headers: authHeaders() });
        renderPlaybooksPage();
      });
    });
  }

  async function renderCampaignsPage() {
    const res = await fetch("/api/campaigns", { headers: authHeaders() });
    const data = await res.json();
    const rows = (data.campaigns || [])
      .map((c) => {
        const sent = Number(c.sent_count || 0);
        const click = sent ? Math.round((100 * Number(c.click_count || 0)) / sent) : 0;
        const report = sent ? Math.round((100 * Number(c.report_count || 0)) / sent) : 0;
        return `<tr>
          <td>${escapeHtml(c.name)}</td>
          <td>${escapeHtml(c.status)}</td>
          <td>${escapeHtml(c.audience || "—")}</td>
          <td>${click}%</td>
          <td>${report}%</td>
          <td class="ws-actions">
            <button type="button" class="btn-secondary ws-camp-done" data-id="${escapeHtml(c.id)}">Mark done</button>
            <button type="button" class="btn-secondary ws-camp-del" data-id="${escapeHtml(c.id)}">Delete</button>
          </td>
        </tr>`;
      })
      .join("");
    await renderTable(
      "campaignsPageBody",
      ["Campaign", "Status", "Audience", "Click %", "Report %", ""],
      rows,
      "No campaigns"
    );
    qs("campaignsPageBody")?.querySelectorAll(".ws-camp-done").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await fetch(`/api/campaigns/${btn.getAttribute("data-id")}`, {
          method: "PATCH",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ status: "completed" }),
        });
        renderCampaignsPage();
      });
    });
    qs("campaignsPageBody")?.querySelectorAll(".ws-camp-del").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm("Delete this campaign?")) return;
        await fetch(`/api/campaigns/${btn.getAttribute("data-id")}`, { method: "DELETE", headers: authHeaders() });
        renderCampaignsPage();
      });
    });
  }

  async function renderIntelPage() {
    const body = qs("intelPageBody");
    if (!body) return;
    if (window.__securaiqIntelLookupBusy) return;
    const [watchRes, vulnRes, kevRes, catalogRes] = await Promise.all([
      fetch("/api/intel/watch", { headers: authHeaders() }),
      fetch("/api/vulnerabilities", { headers: authHeaders() }),
      fetch("/api/intel/kev?limit=12", { headers: authHeaders() }),
      fetch("/api/intel/free/catalog", { headers: authHeaders() }),
    ]);
    const watch = (await watchRes.json()).watch || [];
    const vulns = ((await vulnRes.json()).vulnerabilities || [])
      .filter((v) => (v.severity || "") === "critical" || (v.cve || "").startsWith("CVE-"))
      .slice(0, 12);
    const kevData = await kevRes.json().catch(() => ({}));
    const kevItems = kevData.items || [];
    const catalog = await catalogRes.json().catch(() => ({}));
    const catalogItems = catalog.items || [];
    const counts = catalog.counts || {};
    const statusClass = (st) => {
      if (st === "live") return "ok";
      if (st === "keyed") return "";
      if (st === "skipped") return "warn";
      return "";
    };
    body.innerHTML = `
      <div class="intel-stack">
        <section class="cc-panel intel-panel intel-panel-lookup">
          <header class="intel-panel-head">
            <div>
              <h2>IOC / CVE lookup</h2>
              <p class="hint">Queries built-in providers (${counts.live || 0} live · ${counts.keyed || 0} keyed). Add keys in Settings for AbuseIPDB, VirusTotal, Shodan, and more.</p>
            </div>
            <span class="intel-status">${catalog.total || 0} providers</span>
          </header>
          <form id="intelLookupForm" class="intel-lookup-form">
            <input id="intelLookupQ" placeholder="IP, domain, URL, email, hash, or CVE-…" required autocomplete="off" spellcheck="false" />
            <button type="submit" class="btn-primary-cc">Lookup</button>
          </form>
          <div class="intel-catalog" id="intelCatalogStrip" aria-label="Integrated providers">
            ${catalogItems
              .filter((it) => it.status === "live" || it.status === "keyed")
              .map(
                (it) =>
                  `<span class="integ-pill integ-chip ${statusClass(it.status)}" title="${escapeHtml(
                    it.notes || it.auth || ""
                  )}">${escapeHtml(it.name)} · ${escapeHtml(it.status)}${it.key_configured ? " ✓" : ""}</span>`
              )
              .join("")}
          </div>
          <div id="intelLookupOut" class="intel-lookup-results hidden" aria-live="polite"></div>
        </section>

        <section class="cc-panel intel-panel intel-panel-stix">
          <header class="intel-panel-head">
            <div>
              <h2>STIX 2.1 / TAXII</h2>
              <p class="hint">Standard intel exchange — ingest bundles or poll a configured TAXII collection.</p>
            </div>
            <span class="intel-status" id="stixStatusHint">Loading…</span>
          </header>
          <div class="intel-toolbar">
            <button type="button" class="btn-secondary" id="stixExportBtn">Export watchlist</button>
            <button type="button" class="btn-secondary" id="stixTaxiiPollBtn">Poll TAXII</button>
            <label class="btn-secondary intel-file-btn">Import STIX JSON
              <input type="file" id="stixFileInput" accept=".json,application/json" hidden />
            </label>
          </div>
          <pre id="stixOut" class="tools-palette-out intel-out hidden"></pre>
        </section>

        <div class="intel-grid">
          <section class="cc-panel intel-panel">
            <header class="intel-panel-head">
              <div><h2>Watchlist</h2></div>
              <button type="button" class="btn-secondary" id="intelKevSync">Sync CISA KEV</button>
            </header>
            <ul class="cc-list intel-list">${
              watch.length
                ? watch
                    .map(
                      (w) =>
                        `<li class="intel-watch-row">
                          <div class="intel-watch-main">
                            <strong class="intel-kind">${escapeHtml(w.kind)}</strong>
                            <code>${escapeHtml(w.value)}</code>
                            ${w.notes ? `<span class="hint">${escapeHtml((w.notes || "").slice(0, 100))}</span>` : ""}
                          </div>
                          <button type="button" class="btn-ghost ws-del-watch" data-id="${w.id}">Remove</button>
                        </li>`
                    )
                    .join("")
                : `<li class="hint">No watched CVEs / IOCs yet — sync KEV or add below.</li>`
            }</ul>
            <form id="intelWatchForm" class="intel-lookup-form intel-lookup-form-compact">
              <input id="intelValue" placeholder="CVE-2024-… or IOC" required autocomplete="off" />
              <button type="submit" class="btn-primary-cc">Add</button>
            </form>
            <form id="intelNvdForm" class="intel-lookup-form intel-lookup-form-compact">
              <input id="intelNvdCve" placeholder="Lookup NVD CVE…" required autocomplete="off" />
              <button type="submit" class="btn-secondary">NVD</button>
            </form>
            <pre id="intelNvdOut" class="tools-palette-out intel-out hidden"></pre>
          </section>

          <section class="cc-panel intel-panel">
            <header class="intel-panel-head"><div><h2>CISA KEV</h2><p class="hint">Recently exploited vulnerabilities</p></div></header>
            <ul class="cc-list intel-list">${
              kevItems.length
                ? kevItems
                    .map(
                      (k) =>
                        `<li>
                          <strong>${escapeHtml(k.cve || "")}</strong>
                          <span class="hint">${escapeHtml([k.vendor, k.product].filter(Boolean).join(" · "))}</span>
                          ${k.name ? `<div class="hint">${escapeHtml(k.name)}</div>` : ""}
                        </li>`
                    )
                    .join("")
                : `<li class="hint">${escapeHtml(kevData.detail || "KEV feed unavailable offline")}</li>`
            }</ul>
            <header class="intel-panel-head intel-subhead"><div><h2>Critical in register</h2></div></header>
            <ul class="cc-list intel-list">${
              vulns.length
                ? vulns
                    .map(
                      (v) =>
                        `<li><strong class="sev-${escapeHtml((v.severity || "").toLowerCase())}">${escapeHtml(
                          v.severity
                        )}</strong> ${escapeHtml(v.cve || "")} — ${escapeHtml(v.title)}</li>`
                    )
                    .join("")
                : `<li class="hint">Run New scan or import vulns to populate</li>`
            }</ul>
            <button type="button" class="cc-action" id="intelAskAi">Ask AI for weekly threat brief</button>
          </section>
        </div>

        <section class="cc-panel intel-panel">
          <header class="intel-panel-head">
            <div>
              <h2>Provider feeds</h2>
              <p class="hint">Pull MSRC updates, FilterLists, or check password exposure (HIBP when keyed).</p>
            </div>
          </header>
          <div class="intel-toolbar">
            <button type="button" class="btn-secondary" id="intelFeedMsrc">MSRC updates</button>
            <button type="button" class="btn-secondary" id="intelFeedFilterlists">FilterLists</button>
            <button type="button" class="btn-secondary" id="intelFeedPassword">Password exposure</button>
          </div>
          <pre id="intelFeedOut" class="tools-palette-out intel-out hidden"></pre>
        </section>

        <section class="cc-panel intel-panel">
          <header class="intel-panel-head">
            <div>
              <h2>Threat detection catalog</h2>
              <p class="hint">Searchable Sigma / Sysmon / Zeek / lab references (cached in-app).</p>
            </div>
            <button type="button" class="btn-secondary" id="intelAtdRefresh">Refresh</button>
          </header>
          <form id="intelAtdForm" class="intel-lookup-form">
            <input id="intelAtdQ" placeholder="Search Sigma, Sysmon, Zeek, labs…" autocomplete="off" />
            <select id="intelAtdCat"><option value="">All categories</option></select>
            <button type="submit" class="btn-primary-cc">Search</button>
          </form>
          <p class="hint" id="intelAtdMeta">Loading catalog…</p>
          <ul class="cc-list intel-list" id="intelAtdList"><li class="hint">…</li></ul>
        </section>
      </div>`;
    // Threat detection catalog (awesome list)
    const atdMeta = qs("intelAtdMeta");
    const atdList = qs("intelAtdList");
    const atdCat = qs("intelAtdCat");
    const paintAtd = (data) => {
      if (!atdList) return;
      const items = data.items || [];
      if (atdMeta) {
        atdMeta.textContent = `${data.total_matched ?? data.matched ?? items.length} shown · ${data.total || 0} total · ${data.fetched_from || "?"}${data.cached ? " (cached)" : ""}`;
      }
      if (atdCat && !(atdCat.options.length > 1)) {
        (data.categories || []).forEach((c) => {
          const opt = document.createElement("option");
          opt.value = c.name;
          opt.textContent = `${c.name} (${c.count})`;
          atdCat.appendChild(opt);
        });
      }
      atdList.innerHTML = items.length
        ? items
            .map(
              (it) =>
                `<li><strong>${escapeHtml(it.name)}</strong>
                <span class="hint">${escapeHtml(it.category || "")}${it.subcategory ? " · " + escapeHtml(it.subcategory) : ""}</span>
                ${it.description ? `<div class="hint">${escapeHtml(it.description)}</div>` : ""}
                <a href="${escapeHtml(it.url)}" target="_blank" rel="noopener">Open</a></li>`
            )
            .join("")
        : `<li class="hint">No matches</li>`;
    };
    const loadAtd = async ({ refresh = false } = {}) => {
      if (atdMeta) atdMeta.textContent = refresh ? "Refreshing from GitHub…" : "Loading…";
      const q = qs("intelAtdQ")?.value?.trim() || "";
      const cat = qs("intelAtdCat")?.value || "";
      const url = `/api/intel/threat-detection?limit=60&q=${encodeURIComponent(q)}&category=${encodeURIComponent(cat)}${refresh ? "&refresh=true" : ""}`;
      try {
        const res = await fetch(url, { headers: authHeaders() });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          if (atdMeta) atdMeta.textContent = data.detail || `HTTP ${res.status}`;
          if (atdList) atdList.innerHTML = `<li class="hint">Catalog unavailable</li>`;
          return;
        }
        paintAtd(data);
      } catch (err) {
        if (atdMeta) atdMeta.textContent = String(err.message || err);
      }
    };
    qs("intelAtdForm")?.addEventListener("submit", (e) => {
      e.preventDefault();
      loadAtd();
    });
    qs("intelAtdCat")?.addEventListener("change", () => loadAtd());
    qs("intelAtdRefresh")?.addEventListener("click", async () => {
      try {
        await fetch("/api/intel/threat-detection/refresh", { method: "POST", headers: authHeaders() });
      } catch {
        /* ignore */
      }
      loadAtd({ refresh: true });
    });
    loadAtd();
    qs("intelLookupForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const q = qs("intelLookupQ")?.value?.trim();
      const out = qs("intelLookupOut");
      if (!q || !out) return;
      window.__securaiqIntelLookupBusy = true;
      out.classList.remove("hidden");
      out.innerHTML = `<p class="hint">Looking up across integrated providers…</p>`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 45000);
      try {
        const res = await fetch(`/api/intel/lookup?q=${encodeURIComponent(q)}`, {
          headers: authHeaders(),
          signal: controller.signal,
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          out.innerHTML = `<p class="hint">${escapeHtml(data.detail || `HTTP ${res.status}`)}</p>`;
          return;
        }
        const cards = (data.results || [])
          .map((r) => {
            const src = escapeHtml(r.source || "?");
            const payload = r.data != null ? r.data : r;
            const preview = escapeHtml(JSON.stringify(payload, null, 2).slice(0, 1200));
            return `<article class="intel-result-card">
            <header><strong>${src}</strong>${r.cached ? ' <span class="hint">cached</span>' : ""}</header>
            <pre>${preview}</pre>
          </article>`;
          })
          .join("");
        const errs = (data.errors || [])
          .map((err) => `<li>${escapeHtml(err.provider || "?")}: ${escapeHtml(err.error || "")}</li>`)
          .join("");
        out.innerHTML = `
        <div class="intel-lookup-meta">
          <strong>${escapeHtml(data.kind || "ioc")}</strong>
          <span class="hint">${escapeHtml(String(data.query || q))} · ok ${data.providers_ok ?? 0} · failed ${data.providers_failed ?? 0}</span>
        </div>
        <div class="intel-result-grid">${cards || `<p class="hint">No provider hits</p>`}</div>
        ${errs ? `<ul class="hint intel-lookup-errors"><li>Errors</li>${errs}</ul>` : ""}`;
      } catch (err) {
        const msg =
          err && err.name === "AbortError"
            ? "Lookup timed out after 45s — slow providers may still be running; try again."
            : String((err && err.message) || err || "Lookup failed");
        out.innerHTML = `<p class="hint">${escapeHtml(msg)}</p>`;
      } finally {
        clearTimeout(timer);
        window.__securaiqIntelLookupBusy = false;
      }
    });
    const stixOut = qs("stixOut");
    const stixHint = qs("stixStatusHint");
    const showStix = (data) => {
      if (!stixOut) return;
      stixOut.classList.remove("hidden");
      stixOut.textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2);
    };
    fetch("/api/intel/stix/status", { headers: authHeaders() })
      .then((r) => r.json().catch(() => ({})))
      .then((s) => {
        if (!stixHint) return;
        stixHint.textContent = s.taxii_configured
          ? `TAXII ready · ${s.stix_version || "2.1"}`
          : `STIX ${s.stix_version || "2.1"} · set TAXII in Settings`;
        stixHint.classList.toggle("ok", !!s.taxii_configured);
      })
      .catch(() => {
        if (stixHint) stixHint.textContent = "STIX unavailable";
      });
    qs("stixExportBtn")?.addEventListener("click", async () => {
      const res = await fetch("/api/intel/stix/export", { headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showStix(data.detail || `HTTP ${res.status}`);
        return;
      }
      showStix(data);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `securaiq-stix-export-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
      if (typeof notifyUser === "function") notifyUser("**STIX export** downloaded");
    });
    qs("stixTaxiiPollBtn")?.addEventListener("click", async () => {
      showStix("Polling TAXII…");
      const res = await fetch("/api/intel/stix/taxii/poll", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ ingest: true, limit: 100 }),
      });
      const data = await res.json().catch(() => ({}));
      showStix(data.detail || data);
      if (res.ok && typeof notifyUser === "function") {
        const n = data.ingest?.watch_added ?? data.watch_added ?? data.ingested ?? "—";
        notifyUser(`**TAXII poll:** watch added ${n}`);
      }
    });
    qs("stixFileInput")?.addEventListener("change", async (ev) => {
      const file = ev.target?.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const bundle = JSON.parse(text);
        showStix("Ingesting…");
        const res = await fetch("/api/intel/stix/ingest", {
          method: "POST",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ bundle, also_vulns: true }),
        });
        const data = await res.json().catch(() => ({}));
        showStix(data.detail || data);
        if (res.ok && typeof notifyUser === "function") {
          notifyUser(`**STIX ingest:** watch +${data.watch_added ?? 0}, vulns +${data.vulns_added ?? 0}`);
        }
      } catch (err) {
        showStix(String(err?.message || err));
      }
      ev.target.value = "";
    });
    qs("intelKevSync")?.addEventListener("click", async () => {
      const res = await fetch("/api/intel/kev/sync", { method: "POST", headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      if (typeof notifyUser === "function") notifyUser(`**KEV sync:** added ${data.added ?? "?"} items`);
      renderIntelPage();
    });
    qs("intelWatchForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const value = qs("intelValue")?.value?.trim();
      if (!value) return;
      await fetch("/api/intel/watch", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ kind: value.toUpperCase().startsWith("CVE-") ? "cve" : "ioc", value }),
      });
      renderIntelPage();
    });
    qs("intelNvdForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const cve = qs("intelNvdCve")?.value?.trim();
      if (!cve) return;
      const out = qs("intelNvdOut");
      const res = await fetch(`/api/intel/nvd/${encodeURIComponent(cve)}`, { headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      if (out) {
        out.classList.remove("hidden");
        out.textContent = res.ok
          ? `${data.cve} · CVSS ${data.cvss ?? "—"} · ${data.severity || ""}\n${data.description || ""}`
          : data.detail || `HTTP ${res.status}`;
      }
    });
    body.querySelectorAll(".ws-del-watch").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await fetch(`/api/intel/watch/${btn.getAttribute("data-id")}`, { method: "DELETE", headers: authHeaders() });
        renderIntelPage();
      });
    });
    qs("intelAskAi")?.addEventListener("click", () => {
      if (typeof runNavPrompt === "function") {
        runNavPrompt(
          "research",
          "Summarize latest critical CVEs and KEV items relevant to Windows and cloud this week"
        );
      }
    });
    const showIntelFeed = async (url, label) => {
      const out = qs("intelFeedOut");
      if (!out) return;
      out.classList.remove("hidden");
      out.textContent = `Loading ${label}…`;
      const res = await fetch(url, { headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      out.textContent = res.ok ? JSON.stringify(data, null, 2) : data.detail || `HTTP ${res.status}`;
    };
    qs("intelFeedMsrc")?.addEventListener("click", () => showIntelFeed("/api/intel/msrc", "MSRC"));
    qs("intelFeedFilterlists")?.addEventListener("click", () => showIntelFeed("/api/intel/filterlists", "FilterLists"));
    qs("intelFeedPassword")?.addEventListener("click", async () => {
      const pwd = prompt("Check password exposure (HIBP k-anonymity — not stored or shown):");
      if (!pwd) return;
      const out = qs("intelFeedOut");
      if (!out) return;
      out.classList.remove("hidden");
      out.textContent = "Checking…";
      // POST body only — never put passwords in the URL/query string
      const res = await fetch("/api/intel/password/check", {
        method: "POST",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ password: pwd }),
      });
      const data = await res.json().catch(() => ({}));
      out.textContent = res.ok
        ? `Exposed: ${data.exposed ? "yes" : "no"} · breach count: ${data.count ?? 0}\n${data.note || ""}`
        : data.detail || `HTTP ${res.status}`;
    });
  }
  window.renderIntelPage = renderIntelPage;

  async function renderReportsPage() {
    const body = qs("reportsPageBody");
    if (!body) return;
    let items = [];
    try {
      const res = await fetch("/api/reports", { headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      items = data.reports || [];
    } catch (err) {
      body.innerHTML = `<p class="hint page-pad">Could not load reports: ${escapeHtml(err.message || String(err))}</p>`;
      return;
    }

    const fmtWhen = (ts) => {
      if (ts == null || ts === "") return "—";
      const d = new Date(typeof ts === "number" && ts < 1e12 ? ts * 1000 : ts);
      return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
    };
    const parseScanTitle = (title) => {
      const raw = String(title || "").replace(/\s*\(PDF\)\s*$/i, "");
      const m = raw.match(/^(?:Scan|Archive)\s*-\s*(.+?)\s*\(([^)]+)\)(?:\s*-\s*(\d+)\s*findings)?/i);
      if (!m) return { target: raw || "Scan", scanner: "", findings: "" };
      return { target: m[1], scanner: m[2], findings: m[3] || "" };
    };
    const groupByScan = (rows) => {
      const map = new Map();
      rows.forEach((r) => {
        const key = r.scan_id || r.id;
        if (!key) return;
        const cur = map.get(key) || {
          id: key,
          title: r.title,
          created_at: r.created_at,
          md: null,
          pdf: null,
        };
        const href = r.href || "";
        if (r.kind === "pdf" || href.endsWith(".pdf")) cur.pdf = r;
        else cur.md = r;
        cur.title = (r.title || cur.title || "").replace(/\s*\(PDF\)\s*$/i, "");
        if (r.created_at) cur.created_at = r.created_at;
        map.set(key, cur);
      });
      return [...map.values()];
    };

    const liveScans = groupByScan(items.filter((r) => r.kind === "scan" || (r.kind === "pdf" && r.scan_id && !String(r.id || "").startsWith("archive"))));
    const liveIds = new Set(liveScans.map((s) => s.id));
    const archives = groupByScan(items.filter((r) => r.kind === "archive" || String(r.id || "").startsWith("archive-"))).filter(
      (s) => !liveIds.has(s.id)
    );
    const gaps = items.filter((r) => r.kind === "gap" || r.kind === "audit_pack");
    const gapGroups = [];
    const gapMap = new Map();
    gaps.forEach((r) => {
      const key = String(r.id || "").replace(/^audit-pack-/, "") || r.href;
      const cur = gapMap.get(key) || { id: key, title: r.title, md: null, zip: null };
      if (r.kind === "audit_pack") cur.zip = r;
      else cur.md = r;
      cur.title = (r.title || "").replace(/^Audit pack ZIP — /, "Gap — ");
      gapMap.set(key, cur);
    });
    gapMap.forEach((v) => gapGroups.push(v));

    const dlBtn = (href, kind, label) =>
      href
        ? `<button type="button" class="btn-secondary reports-dl" data-href="${escapeHtml(href)}" data-kind="${escapeHtml(
            kind || ""
          )}">${escapeHtml(label)}</button>`
        : `<span class="hint">—</span>`;

    const scanTable = (rows, empty) =>
      rows.length
        ? `<div class="data-table-wrap reports-table-wrap"><table class="data-table reports-table">
            <thead><tr><th>Target</th><th>Engine</th><th>Findings</th><th>When</th><th>Download</th></tr></thead>
            <tbody>${rows
              .map((s) => {
                const p = parseScanTitle(s.title);
                return `<tr>
                  <td><strong>${escapeHtml(p.target)}</strong></td>
                  <td>${escapeHtml(p.scanner || "—")}</td>
                  <td>${p.findings ? escapeHtml(p.findings) : "—"}</td>
                  <td class="hint">${escapeHtml(fmtWhen(s.created_at))}</td>
                  <td class="reports-dl-cell">${dlBtn(s.md?.href, s.md?.kind || "scan", "Markdown")}${dlBtn(
                    s.pdf?.href,
                    "pdf",
                    "PDF"
                  )}</td>
                </tr>`;
              })
              .join("")}</tbody></table></div>`
        : `<p class="hint page-pad">${empty}</p>`;

    body.innerHTML = `
      <div class="reports-page">
        <section class="cc-panel reports-toolbar">
          <header class="reports-toolbar-head">
            <div>
              <h2>Workspace exports</h2>
              <p class="hint">Always generated from current assets, vulns, and risks.</p>
            </div>
            <button type="button" class="btn-secondary" id="reportClearScans">Archive &amp; clear live scans</button>
          </header>
          <div class="reports-export-grid">
            <button type="button" class="btn-secondary" id="reportExecPdf">Executive PDF</button>
            <button type="button" class="btn-secondary" id="reportExecDocx">Executive DOCX</button>
            <button type="button" class="btn-secondary" id="reportComplianceDocx">Compliance DOCX</button>
            <button type="button" class="btn-secondary" id="reportRisksPdf">Risks PDF</button>
            <button type="button" class="btn-secondary" id="reportRisksXlsx">Risks Excel</button>
            <button type="button" class="btn-secondary" id="reportVulnsPdf">Vulns PDF</button>
            <button type="button" class="btn-secondary" id="reportVulnsXlsx">Vulns Excel</button>
          </div>
          <div class="reports-ai-row">
            <span class="hint">Ask AI</span>
            <button type="button" class="btn-ghost" id="reportExecAi">Executive</button>
            <button type="button" class="btn-ghost" id="reportBoardAi">Board</button>
            <button type="button" class="btn-ghost" id="reportSecurityAi">Security</button>
            <button type="button" class="btn-ghost" id="reportTechAi">Technical</button>
          </div>
        </section>
        <section class="reports-section">
          <header class="reports-section-head">
            <h2>Scan reports</h2>
            <span class="hint">${liveScans.length} completed</span>
          </header>
          ${scanTable(liveScans, "No completed scans yet — run New scan. Each scan appears once with Markdown + PDF.")}
        </section>
        ${
          archives.length
            ? `<section class="reports-section">
                <header class="reports-section-head"><h2>Archived</h2><span class="hint">${archives.length}</span></header>
                ${scanTable(archives, "")}
              </section>`
            : ""
        }
        ${
          gapGroups.length
            ? `<section class="reports-section">
                <header class="reports-section-head"><h2>Gap assessments</h2><span class="hint">${gapGroups.length}</span></header>
                <div class="data-table-wrap reports-table-wrap"><table class="data-table reports-table">
                  <thead><tr><th>Assessment</th><th>Download</th></tr></thead>
                  <tbody>${gapGroups
                    .map(
                      (g) => `<tr>
                        <td>${escapeHtml(g.title || "Gap")}</td>
                        <td class="reports-dl-cell">${dlBtn(g.md?.href, "gap", "Markdown")}${dlBtn(
                          g.zip?.href,
                          "audit_pack",
                          "Audit pack"
                        )}</td>
                      </tr>`
                    )
                    .join("")}</tbody>
                </table></div>
              </section>`
            : ""
        }
      </div>`;

    const downloadReport = async (href, kind) => {
      if (!href) return;
      try {
        if (kind === "pdf" || href.endsWith(".pdf")) {
          const name = href.split("/").pop() || "securaiq-report.pdf";
          if (typeof window.downloadBinary === "function") {
            await window.downloadBinary(href, name, "application/pdf");
          } else {
            const r = await fetch(href, { headers: authHeaders() });
            const buf = await r.arrayBuffer();
            const a = document.createElement("a");
            a.href = URL.createObjectURL(new Blob([buf], { type: "application/pdf" }));
            a.download = name;
            a.click();
          }
        } else if (kind === "docx" || href.endsWith(".docx") || kind === "xlsx" || href.endsWith(".xlsx") || kind === "audit_pack") {
          const name = href.split("/").pop() || "securaiq-report.bin";
          const mime = href.endsWith(".xlsx")
            ? "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            : href.endsWith(".zip") || kind === "audit_pack"
              ? "application/zip"
              : "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
          if (typeof window.downloadBinary === "function") {
            await window.downloadBinary(href, name, mime);
          }
        } else if (typeof downloadMd === "function") {
          const name =
            kind === "scan" || kind === "archive"
              ? `securaiq-scan-${(href.split("/")[3] || "report").slice(0, 8)}.md`
              : "securaiq-report.md";
          await downloadMd(href, name);
        } else {
          const r = await fetch(href, { headers: authHeaders() });
          const md = await r.text();
          const a = document.createElement("a");
          a.href = URL.createObjectURL(new Blob([md], { type: "text/markdown" }));
          a.download = "securaiq-report.md";
          a.click();
        }
      } catch (err) {
        alert(err.message || "Download failed");
      }
    };

    body.querySelectorAll(".reports-dl").forEach((btn) => {
      btn.addEventListener("click", () => downloadReport(btn.getAttribute("data-href"), btn.getAttribute("data-kind") || ""));
    });
    qs("reportExecPdf")?.addEventListener("click", () => {
      if (typeof window.downloadBinary === "function") {
        window.downloadBinary("/api/reports/executive.pdf", "securaiq-executive.pdf", "application/pdf").catch((e) =>
          alert(e.message)
        );
      }
    });
    qs("reportClearScans")?.addEventListener("click", async () => {
      if (
        !confirm(
          "Archive scan reports to data/archive, then clear live scan records and findings so you can start fresh? Archives stay available under Reports."
        )
      )
        return;
      try {
        const res = await fetch("/api/scans/clear", { method: "POST", headers: authHeaders() });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        const archived = data.archived_count || 0;
        alert(
          `Archived ${archived} scan(s)${data.archive_batch ? ` → ${data.archive_batch}` : ""}.\nCleared: ${data.scans_deleted || 0} live scans, ${data.vulnerabilities_deleted || 0} findings.`
        );
        await renderReportsPage();
        if (typeof loadVulns === "function") await loadVulns();
        if (typeof refreshMissionControl === "function") await refreshMissionControl();
      } catch (err) {
        alert(err.message || "Clear failed");
      }
    });
    const bin = (href, name, mime) => {
      if (typeof window.downloadBinary === "function") {
        window.downloadBinary(href, name, mime).catch((e) => alert(e.message));
      }
    };
    qs("reportExecDocx")?.addEventListener("click", () =>
      bin(
        "/api/reports/executive.docx",
        "securaiq-executive.docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
      )
    );
    qs("reportRisksPdf")?.addEventListener("click", () =>
      bin("/api/reports/risks.pdf", "securaiq-risks.pdf", "application/pdf")
    );
    qs("reportVulnsPdf")?.addEventListener("click", () =>
      bin("/api/reports/vulns.pdf", "securaiq-vulns.pdf", "application/pdf")
    );
    qs("reportComplianceDocx")?.addEventListener("click", () =>
      bin(
        "/api/reports/compliance.docx",
        "securaiq-compliance.docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
      )
    );
    qs("reportRisksXlsx")?.addEventListener("click", () =>
      bin(
        "/api/reports/risks.xlsx",
        "securaiq-risks.xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
      )
    );
    qs("reportVulnsXlsx")?.addEventListener("click", () =>
      bin(
        "/api/reports/vulns.xlsx",
        "securaiq-vulns.xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
      )
    );
    qs("reportExecAi")?.addEventListener("click", () => {
      if (typeof runNavPrompt === "function")
        runNavPrompt("ciso", "Generate an executive security status report from our current posture");
    });
    qs("reportBoardAi")?.addEventListener("click", () => {
      if (typeof runNavPrompt === "function")
        runNavPrompt("ciso", "Draft a board report: security score, top risks, compliance %, and decisions needed");
    });
    qs("reportSecurityAi")?.addEventListener("click", () => {
      if (typeof runNavPrompt === "function")
        runNavPrompt("blueteam", "Generate a technical security report covering critical vulns, remediations, and verify steps");
    });
    qs("reportTechAi")?.addEventListener("click", () => {
      if (typeof runNavPrompt === "function")
        runNavPrompt("assess", "Generate a technical findings report with remediation owners and SLAs");
    });
  }

  async function renderXdrPanel() {
    const el = qs("xdrPanelBody");
    if (!el) return;
    try {
      const [statusRes, detRes, patchRes] = await Promise.all([
        fetch("/api/xdr/status", { headers: authHeaders() }),
        fetch("/api/xdr/detections?limit=8", { headers: authHeaders() }),
        fetch("/api/xdr/patches", { headers: authHeaders() }),
      ]);
      const statusData = await statusRes.json();
      const detData = await detRes.json();
      const patchData = await patchRes.json();
      const vendors = statusData.vendors || {};
      const vendorLabels = { sophos: "Sophos", crowdstrike: "CrowdStrike", sentinelone: "SentinelOne", defender: "Defender" };
      const vendorChips = `<ul class="integ-status-list">${Object.entries(vendors)
        .map(
          ([id, v]) =>
            `<li class="${v.configured ? "ok" : "muted"}"><span>${escapeHtml(vendorLabels[id] || id)}</span><strong>${
              v.configured ? "Connected" : "Not configured"
            }</strong></li>`
        )
        .join("")}</ul>`;
      const anyConfigured = Object.values(vendors).some((v) => v.configured);
      const events = detData.events || [];
      const eventsHtml = events.length
        ? events
            .map(
              (e) =>
                `<li><strong>${escapeHtml(e.severity)}</strong> [${escapeHtml(e.vendor)}] ${escapeHtml(e.title)}${
                  e.host ? ` — <code>${escapeHtml(e.host)}</code>` : ""
                }</li>`
            )
            .join("")
        : `<li class="hint">${anyConfigured ? "No detections synced yet" : "Connect an EDR vendor in Settings to see live detections here"}</li>`;
      const streaming = statusData.streaming || {};
      const nearRtSec = Number(statusData.near_realtime_interval_sec) || 60;
      const streamLabels = {
        crowdstrike: "CrowdStrike",
        sophos: "Sophos",
        sentinelone: "SentinelOne",
        defender: "Defender",
      };
      const streamHtml = Object.keys(streamLabels)
        .map((id) => {
          const st = streaming[id] || {};
          const configured = !!(vendors[id] && vendors[id].configured);
          const mode = st.mode || (id === "crowdstrike" ? "stream" : "near_realtime_poll");
          const modeLabel = mode === "stream" ? "live stream" : `near-realtime (${nearRtSec}s)`;
          if (st.connected) {
            return `<p class="hint" style="color:var(--accent)">⚡ ${streamLabels[id]} ${modeLabel} connected</p>`;
          }
          if (configured) {
            return `<p class="hint">${streamLabels[id]} ${modeLabel}: reconnecting… (slow ${Math.round(
              (window.__xdrIntervalSec || 1800) / 60
            )}-min sync still runs)</p>`;
          }
          if (id === "crowdstrike") {
            return `<p class="hint">${streamLabels[id]} live stream: off — set credentials + "Event streams: Read" scope</p>`;
          }
          return `<p class="hint">${streamLabels[id]} near-realtime: off — configure in Settings (or push via /api/xdr/ingest)</p>`;
        })
        .join("");
      const patchTotal = patchData.total_missing_patches || 0;
      const huntConfigured = !!(statusData.hunting && statusData.hunting.configured);
      const defaultQuery =
        (statusData.hunting && statusData.hunting.default_query) ||
        window.__securaiqHuntQuery ||
        "DeviceProcessEvents\n| where Timestamp > ago(1h)\n| project Timestamp, DeviceName, FileName, InitiatingProcessFileName\n| order by Timestamp desc\n| limit 25";
      const liveOn = !!window.__securaiqHuntLive;
      const liveSec = Number(window.__securaiqHuntLiveSec) || 8;
      // Stop prior live timer before rewiring the panel
      if (window.__securaiqHuntLiveTimer) {
        clearInterval(window.__securaiqHuntLiveTimer);
        window.__securaiqHuntLiveTimer = null;
      }
      el.innerHTML = `
        ${vendorChips}
        ${streamHtml}
        <div class="cc-kpi-grid" style="margin:0.5rem 0">
          <article class="cc-kpi"><span>Missing patches (open)</span><strong>${patchTotal}</strong></article>
          <article class="cc-kpi"><span>Hosts with patch gaps</span><strong>${patchData.hosts_with_gaps || 0}</strong></article>
        </div>
        <p class="hint">Recent detections</p>
        <ul class="cc-list" id="xdrDetectionsList">${eventsHtml}</ul>
        <div class="hunt-box" id="defenderHuntBox" style="margin-top:1rem">
          <header style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">
            <h3 style="margin:0;font-size:1rem">Defender live hunting</h3>
            <span class="auto-job-status ${huntConfigured ? "status-done" : "status-error"}" id="xdrHuntModeChip">
              ${huntConfigured ? "live tenant" : "not configured"}
            </span>
            <span class="hint" id="xdrHuntPulse">idle</span>
          </header>
          <p class="hint">Paste KQL and enable Live to poll your Defender XDR tenant (Graph / legacy MTP). Requires DEFENDER_* credentials — no demo data.</p>
          <textarea id="xdrHuntQuery" rows="5" spellcheck="false" ${huntConfigured ? "" : "disabled"} style="width:100%;font-family:ui-monospace,monospace;font-size:0.85rem">${escapeHtml(defaultQuery)}</textarea>
          <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:0.4rem;align-items:center">
            <label class="hint">Timespan <input type="text" id="xdrHuntTimespan" placeholder="P1H" style="width:6rem" value="${escapeHtml(window.__securaiqHuntTimespan || "")}" ${huntConfigured ? "" : "disabled"} /></label>
            <label class="hint">Every <input type="number" id="xdrHuntLiveSec" min="3" max="120" value="${liveSec}" style="width:3.5rem" ${huntConfigured ? "" : "disabled"} /> s</label>
            <label class="hint"><input type="checkbox" id="xdrHuntLive" ${liveOn && huntConfigured ? "checked" : ""} ${huntConfigured ? "" : "disabled"} /> Live</label>
            <label class="hint"><input type="checkbox" id="xdrHuntIngest" ${huntConfigured ? "" : "disabled"} /> Ingest rows</label>
            <button type="button" class="btn-primary" id="xdrHuntRunBtn" ${huntConfigured ? "" : "disabled"}>Run once</button>
          </div>
          <div id="xdrHuntMeta" class="hint" style="margin-top:0.45rem"></div>
          <div id="xdrHuntTableWrap" style="overflow:auto;max-height:18rem;margin-top:0.4rem"></div>
        </div>
        <p class="hint">Set vendor credentials in Settings (Sophos/CrowdStrike/SentinelOne/Defender) — detections and missing-patch data sync automatically every ${Math.round(
          (window.__xdrIntervalSec || 1800) / 60
        )} min, or click "Sync now".</p>`;

      const queryEl = qs("xdrHuntQuery");
      const tableWrap = qs("xdrHuntTableWrap");
      const metaEl = qs("xdrHuntMeta");
      const pulseEl = qs("xdrHuntPulse");
      let huntBusy = false;

      const paintHuntResult = (data) => {
        window.__securaiqLastHunt = data;
        const rows = data.results || [];
        const backend = data.backend || "?";
        if (metaEl) {
          metaEl.innerHTML = data.ok
            ? `<strong>${escapeHtml(String(data.result_count || 0))}</strong> rows · ${escapeHtml(backend)} · ${new Date().toLocaleTimeString()}${
                data.hint ? ` · <span>${escapeHtml(data.hint)}</span>` : ""
              }`
            : `<span class="auto-job-status status-error">${escapeHtml(data.error || "failed")}</span> ${escapeHtml(data.hint || "")}`;
        }
        if (pulseEl) pulseEl.textContent = `pulse ${new Date().toLocaleTimeString()}`;
        if (!tableWrap) return;
        if (!data.ok || !rows.length) {
          tableWrap.innerHTML = `<p class="hint">${escapeHtml(data.error || data.hint || "No rows")}</p>`;
          return;
        }
        const cols = Object.keys(rows[0]);
        const thead = cols.map((c) => `<th>${escapeHtml(c)}</th>`).join("");
        const body = rows
          .slice(0, 40)
          .map(
            (r) =>
              `<tr>${cols.map((c) => `<td>${escapeHtml(String(r[c] ?? ""))}</td>`).join("")}</tr>`
          )
          .join("");
        tableWrap.innerHTML = `<table class="data-table" style="width:100%;font-size:0.8rem;border-collapse:collapse"><thead><tr>${thead}</tr></thead><tbody>${body}</tbody></table>`;
      };

      const runHunt = async ({ quiet = false } = {}) => {
        if (huntBusy) return;
        huntBusy = true;
        const btn = qs("xdrHuntRunBtn");
        if (btn && !quiet) btn.disabled = true;
        window.__securaiqHuntQuery = queryEl?.value || "";
        window.__securaiqHuntTimespan = qs("xdrHuntTimespan")?.value?.trim() || "";
        if (!quiet && metaEl) metaEl.textContent = "Querying…";
        try {
          const res = await fetch("/api/xdr/hunting/run", {
            method: "POST",
            headers: { ...authHeaders(), "Content-Type": "application/json" },
            body: JSON.stringify({
              query: queryEl?.value || "",
              timespan: qs("xdrHuntTimespan")?.value?.trim() || undefined,
              ingest: !!qs("xdrHuntIngest")?.checked,
              limit: 50,
            }),
          });
          const data = await res.json();
          paintHuntResult(data);
          if (data.ingested && data.ingested.new) {
            try {
              const dr = await fetch("/api/xdr/detections?limit=8", { headers: authHeaders() });
              const dd = await dr.json();
              const list = qs("xdrDetectionsList");
              const ev = dd.events || [];
              if (list) {
                list.innerHTML = ev.length
                  ? ev
                      .map(
                        (e) =>
                          `<li><strong>${escapeHtml(e.severity)}</strong> [${escapeHtml(e.vendor)}] ${escapeHtml(e.title)}${
                            e.host ? ` — <code>${escapeHtml(e.host)}</code>` : ""
                          }</li>`
                      )
                      .join("")
                  : `<li class="hint">No detections</li>`;
              }
            } catch {
              /* ignore */
            }
          }
        } catch (err) {
          paintHuntResult({ ok: false, error: String(err.message || err), results: [] });
        } finally {
          huntBusy = false;
          if (btn) btn.disabled = false;
        }
      };

      const syncLiveTimer = () => {
        if (window.__securaiqHuntLiveTimer) {
          clearInterval(window.__securaiqHuntLiveTimer);
          window.__securaiqHuntLiveTimer = null;
        }
        if (!huntConfigured) {
          window.__securaiqHuntLive = false;
          const chip = qs("xdrHuntModeChip");
          if (chip) {
            chip.textContent = "not configured";
            chip.className = "auto-job-status status-error";
          }
          if (metaEl) {
            metaEl.innerHTML =
              `<span class="auto-job-status status-error">not_configured</span> Set DEFENDER_TENANT_ID / CLIENT_ID / CLIENT_SECRET in Settings for live hunting.`;
          }
          if (tableWrap) tableWrap.innerHTML = `<p class="hint">Live hunting requires a configured Defender tenant.</p>`;
          return;
        }
        const on = !!qs("xdrHuntLive")?.checked;
        window.__securaiqHuntLive = on;
        const sec = Math.max(3, Math.min(120, Number(qs("xdrHuntLiveSec")?.value) || 8));
        window.__securaiqHuntLiveSec = sec;
        const chip = qs("xdrHuntModeChip");
        if (chip) {
          chip.textContent = on ? "live tenant" : "tenant";
          chip.className = "auto-job-status status-done";
        }
        if (on) {
          runHunt({ quiet: true });
          window.__securaiqHuntLiveTimer = setInterval(() => runHunt({ quiet: true }), sec * 1000);
        }
      };

      qs("xdrHuntRunBtn")?.addEventListener("click", () => {
        if (!huntConfigured) return;
        runHunt({ quiet: false });
      });
      qs("xdrHuntLive")?.addEventListener("change", syncLiveTimer);
      qs("xdrHuntLiveSec")?.addEventListener("change", () => {
        if (qs("xdrHuntLive")?.checked) syncLiveTimer();
      });
      window.__securaiqRunLiveHunt = () => {
        if (huntConfigured && window.__securaiqHuntLive) runHunt({ quiet: true });
      };

      if (huntConfigured) {
        if (window.__securaiqLastHunt && window.__securaiqLastHunt.ok && !window.__securaiqLastHunt.demo) {
          paintHuntResult(window.__securaiqLastHunt);
        }
        if (liveOn) syncLiveTimer();
        else runHunt({ quiet: true });
      } else {
        window.__securaiqHuntLive = false;
        syncLiveTimer();
      }
    } catch (err) {
      el.innerHTML = `<p class="hint">Couldn't load XDR — try refreshing. <span class="hint-sub">(${escapeHtml(err.message)})</span></p>`;
    }
  }

  async function renderWazuhPanel() {
    const el = qs("wazuhPanelBody");
    if (!el) return;
    try {
      const res = await fetch("/api/siem/overview", { headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        el.innerHTML = `<p class="hint">SecuraIQ SIEM unavailable (${res.status})</p>`;
        return;
      }
      const ov = data.overview || {};
      const agentsStats = ov.agents || {};
      const manager = ov.manager || {};
      const agents = data.agents_cached || [];
      const events = data.alerts || [];
      const groups = data.groups || [];
      const rules = data.rules || {};
      const sca = data.sca || [];
      const fim = data.fim || [];
      const statusChip = data.configured
        ? ov.ok
          ? `<span class="auto-job-status status-done">connected</span>`
          : `<span class="auto-job-status status-error">auth/error</span>`
        : `<span class="auto-job-status status-planned">not configured</span>`;
      const kpi = (label, val) =>
        `<div class="comp-kpi"><span>${escapeHtml(label)}</span><strong>${escapeHtml(String(val ?? "—"))}</strong></div>`;
      const agentsHtml = agents.length
        ? `<div class="data-table-wrap"><table class="data-table"><thead><tr>
            <th>Status</th><th>Agent</th><th>IP</th><th>OS</th><th>Group</th><th>Version</th>
          </tr></thead><tbody>${agents
            .slice(0, 25)
            .map(
              (a) => `<tr>
              <td><span class="wq-badge pri-${
                (a.status || "").toLowerCase() === "active" ? "low" : "high"
              }">${escapeHtml(a.status || "?")}</span></td>
              <td>${escapeHtml(a.name || a.agent_id || "")}</td>
              <td><code>${escapeHtml(a.ip || "—")}</code></td>
              <td>${escapeHtml(a.os || "—")}</td>
              <td>${escapeHtml(a.group_name || a.group || "—")}</td>
              <td>${escapeHtml(a.version || "—")}</td>
            </tr>`
            )
            .join("")}</tbody></table></div>`
        : `<p class="hint">${
            data.configured
              ? "No agents synced yet — click Sync SIEM"
              : "Connect your SIEM manager in Settings → SecuraIQ SIEM"
          }</p>`;
      const alertsHtml = events.length
        ? events
            .slice(0, 12)
            .map(
              (e) =>
                `<li><strong>${escapeHtml(e.severity || "")}</strong> ${escapeHtml(e.title || "")}${
                  e.host ? ` — <code>${escapeHtml(e.host)}</code>` : ""
                }</li>`
            )
            .join("")
        : `<li class="hint">${
            data.configured
              ? data.indexer_configured
                ? "No alerts yet — sync or push via webhook"
                : "Indexer off — agent/vuln signals appear after Sync SIEM"
              : "Configure manager credentials to pull SIEM data"
          }</li>`;
      const groupsHtml = groups.length
        ? groups
            .slice(0, 10)
            .map((g) => `<li><strong>${escapeHtml(g.name)}</strong> · ${escapeHtml(String(g.count ?? 0))} agents</li>`)
            .join("")
        : `<li class="hint">No groups yet</li>`;
      const scaHtml = sca.length
        ? sca
            .slice(0, 8)
            .map(
              (s) =>
                `<li><strong>${escapeHtml(String(s.score ?? "—"))}%</strong> ${escapeHtml(s.name || "")}
                 — ${escapeHtml(s.agent_name || s.agent_id || "")}
                 · fail ${escapeHtml(String(s.fail ?? 0))}</li>`
            )
            .join("")
        : `<li class="hint">No SCA results (needs live manager + agents)</li>`;
      const fimHtml = fim.length
        ? fim
            .slice(0, 8)
            .map(
              (f) =>
                `<li><strong>${escapeHtml(f.severity || "info")}</strong> ${escapeHtml(f.event || "FIM")}
                 · <code>${escapeHtml(f.path || "")}</code>
                 ${f.agent ? ` — ${escapeHtml(f.agent)}` : ""}</li>`
            )
            .join("")
        : `<li class="hint">${
            data.indexer_configured
              ? "No recent FIM events"
              : "FIM feed needs Indexer configured in SecuraIQ SIEM settings"
          }</li>`;
      const rulesHtml = (rules.rules || []).length
        ? (rules.rules || [])
            .slice(0, 6)
            .map(
              (r) =>
                `<li><code>${escapeHtml(r.id || "")}</code> L${escapeHtml(String(r.level ?? ""))}
                 — ${escapeHtml(r.description || "")}</li>`
            )
            .join("")
        : `<li class="hint">${rules.error ? escapeHtml(rules.error) : "Rules catalog unavailable offline"}</li>`;

      el.innerHTML = `
        <p>${statusChip}
          <strong>SecuraIQ SIEM</strong>
          <span class="hint">SecuraIQ brand · manager-connected</span>
          ${data.base_url ? `<span class="hint">${escapeHtml(data.base_url)}</span>` : ""}
          ${data.indexer_configured ? '<span class="hint">Indexer on</span>' : '<span class="hint">Indexer off</span>'}
          ${ov.api_version ? `<span class="hint">API ${escapeHtml(ov.api_version)}</span>` : ""}
          ${manager.version ? `<span class="hint">Manager ${escapeHtml(manager.version)}</span>` : ""}
          ${ov.error && data.configured ? `<span class="hint">${escapeHtml(ov.error)}</span>` : ""}
        </p>
        <div class="comp-kpi-row" aria-label="SIEM health">
          ${kpi("Active agents", agentsStats.active)}
          ${kpi("Disconnected", agentsStats.disconnected)}
          ${kpi("Pending", agentsStats.pending)}
          ${kpi("Total agents", agentsStats.total || agents.length)}
          ${kpi("Rules", rules.total || (rules.rules || []).length)}
          ${kpi("Groups", groups.length)}
          ${kpi("SCA policies", sca.length)}
          ${kpi("FIM events", fim.length)}
        </div>
        <div class="ws-grid-2" style="margin-top:0.75rem">
          <div>
            <p class="hint">Endpoint agents</p>
            ${agentsHtml}
          </div>
          <div>
            <p class="hint">SIEM alerts & signals</p>
            <ul class="cc-list">${alertsHtml}</ul>
            <p class="hint" style="margin-top:0.75rem">Agent groups</p>
            <ul class="cc-list">${groupsHtml}</ul>
          </div>
        </div>
        <div class="ws-grid-2" style="margin-top:0.75rem">
          <div>
            <p class="hint">Configuration assessment (SCA)</p>
            <ul class="cc-list">${scaHtml}</ul>
          </div>
          <div>
            <p class="hint">File integrity (FIM)</p>
            <ul class="cc-list">${fimHtml}</ul>
            <p class="hint" style="margin-top:0.75rem">Recent detection rules</p>
            <ul class="cc-list">${rulesHtml}</ul>
          </div>
        </div>
        <p class="hint" style="margin-top:0.75rem">
          Settings → <strong>SecuraIQ SIEM</strong>. Optional Indexer enables full alert + FIM search.
          Webhook ingest: <code>/api/siem/webhook</code>. Sync pulls agents and alerts into your SOC.
        </p>`;
    } catch (err) {
      el.innerHTML = `<p class="hint">Couldn't load SIEM data — try refreshing. <span class="hint-sub">(${escapeHtml(err.message)})</span></p>`;
    }
  }

  async function renderRiskPriorityPanel() {
    const el = qs("riskPriorityBody");
    if (!el) return;
    try {
      const res = await fetch("/api/risk/priority?limit=10", { headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      const items = data.items || [];
      if (!items.length) {
        el.innerHTML = `<p class="hint">No open findings to rank${data.total_open ? "" : " — nothing open right now"}.</p>`;
        return;
      }
      const bandCls = (band) =>
        band === "critical" || band === "high" ? "status-error" : band === "medium" ? "status-planned" : "status-done";
      el.innerHTML = `
        <p class="hint" style="margin:0 0 8px">Ranked from ${data.total_open} open finding(s)${data.kev_count ? ` · ${data.kev_count} actively exploited (KEV)` : ""}${data.quick_win_count ? ` · ${data.quick_win_count} quick win(s) with a patch already ready` : ""}.</p>
        <div class="data-table-wrap"><table class="data-table">
          <thead><tr><th>Score</th><th>Finding</th><th>Asset</th><th>Why</th></tr></thead>
          <tbody>${items
            .map(
              (i) => `<tr>
                <td><span class="auto-job-status ${bandCls(i.band)}">${escapeHtml(String(i.score))}</span></td>
                <td><strong>${escapeHtml(i.title || i.cve || "Untitled finding")}</strong>${i.cve ? ` <span class="hint">${escapeHtml(i.cve)}</span>` : ""}</td>
                <td class="hint">${escapeHtml(i.asset_name || "—")}</td>
                <td class="hint">${i.reasons.map((r) => escapeHtml(r)).join(" · ")}</td>
              </tr>`
            )
            .join("")}</tbody></table></div>`;
    } catch (err) {
      el.innerHTML = `<p class="hint">Couldn't load the priority list right now. <span class="hint-sub">(${escapeHtml(err.message || String(err))})</span></p>`;
    }
  }

  async function renderAgentsPanel() {
    const el = qs("agentsPanelBody");
    if (!el) return;
    try {
      const [res, threatsRes, pendingRes, campaignsRes] = await Promise.all([
        fetch("/api/agents", { headers: authHeaders() }),
        fetch("/api/agents/threats?limit=50", { headers: authHeaders() }).catch(() => null),
        fetch("/api/agents/commands/pending?limit=100", { headers: authHeaders() }).catch(() => null),
        fetch("/api/agents/campaigns?limit=50", { headers: authHeaders() }).catch(() => null),
      ]);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      const agents = data.agents || [];
      const threatsData = threatsRes && threatsRes.ok ? await threatsRes.json().catch(() => ({})) : {};
      const threats = threatsData.threats || [];
      const pendingData = pendingRes && pendingRes.ok ? await pendingRes.json().catch(() => ({})) : {};
      const pendingCommands = pendingData.commands || [];
      const campaignsData = campaignsRes && campaignsRes.ok ? await campaignsRes.json().catch(() => ({})) : {};
      const campaigns = campaignsData.campaigns || [];
      const threatsByAgent = {};
      threats.forEach((t) => {
        (threatsByAgent[t.agent_id] = threatsByAgent[t.agent_id] || []).push(t);
      });
      if (!agents.length) {
        el.innerHTML = `<p class="hint">No agents enrolled yet. Click <strong>Enroll new agent</strong>, then install <code>scripts/securaiq_agent.py</code> on a server to monitor.</p>`;
        return;
      }
      const statusChip = (st) => {
        const cls = st === "online" ? "status-done" : st === "pending" ? "status-planned" : st === "revoked" ? "status-error" : "status-error";
        return `<span class="auto-job-status ${cls}">${escapeHtml(st)}</span>`;
      };
      const sevRank = { critical: 4, high: 3, medium: 2, low: 1 };
      const sevChip = (sev) => {
        const cls = sev === "critical" || sev === "high" ? "status-error" : sev === "medium" ? "status-planned" : "status-done";
        return `<span class="auto-job-status ${cls}">${escapeHtml(sev)}</span>`;
      };
      const sentinelBadge = (agentThreats) => {
        const active = (agentThreats || []).filter((t) => t.status !== "resolved");
        if (!active.length) return `<span class="auto-job-status status-done">clean</span>`;
        const worst = active.reduce((w, t) => (sevRank[t.severity] > sevRank[w] ? t.severity : w), "low");
        return `${sevChip(worst)} <span class="hint">${active.length} active</span>`;
      };
      const fmtWhen = (ts) => {
        if (!ts) return "never";
        const d = new Date(Number(ts) * 1000);
        return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
      };
      el.innerHTML = `<div class="data-table-wrap"><table class="data-table">
        <thead><tr><th>Host</th><th>Status</th><th>OS</th><th>Ports</th><th>Packages</th><th>Sentinel</th><th>Last check-in</th><th></th></tr></thead>
        <tbody>${agents
          .map((a) => {
            const payload = a.last_payload || {};
            return `<tr>
              <td><strong>${escapeHtml(a.hostname || a.name || a.id.slice(0, 8))}</strong>${a.ip ? `<div class="hint">${escapeHtml(a.ip)}</div>` : ""}</td>
              <td>${statusChip(a.status)}</td>
              <td class="hint">${escapeHtml(a.os || "—")} ${escapeHtml(a.os_version || "")}</td>
              <td>${(payload.listening_ports || []).length}</td>
              <td>${(payload.packages || []).length}</td>
              <td>${sentinelBadge(threatsByAgent[a.id])}</td>
              <td class="hint">${escapeHtml(fmtWhen(a.last_checkin))} · ${Number(a.checkin_count || 0)} check-in(s)</td>
              <td class="reports-dl-cell">
                ${a.asset_id ? `<button type="button" class="btn-secondary agents-view-asset" data-id="${escapeHtml(a.asset_id)}">View asset</button>` : ""}
                <button type="button" class="btn-secondary agents-revoke" data-id="${escapeHtml(a.id)}">Revoke</button>
                <button type="button" class="btn-secondary agents-delete" data-id="${escapeHtml(a.id)}">Delete</button>
              </td>
            </tr>`;
          })
          .join("")}</tbody></table></div>
        ${
          threats.length
            ? `<div class="agents-threats-feed" style="margin-top:12px">
                <h4 style="margin:0 0 6px">SecuraIQ Sentinel — recent detections</h4>
                <ul class="hint" style="list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:4px;max-height:220px;overflow:auto">
                  ${threats
                    .slice(0, 20)
                    .map(
                      (t) =>
                        `<li>${sevChip(t.severity)} <strong>${escapeHtml(t.title)}</strong> — ${escapeHtml(t.hostname || t.agent_id.slice(0, 8))} · ${escapeHtml(t.category)} · ${fmtWhen(t.last_seen)}${t.hit_count > 1 ? ` · seen ${Number(t.hit_count)}x` : ""}</li>`
                    )
                    .join("")}
                </ul>
              </div>`
            : ""
        }
        ${
          pendingCommands.length
            ? `<div class="agents-pending-approvals" style="margin-top:12px">
                <h4 style="margin:0 0 6px">Pending approvals</h4>
                <p class="hint" style="margin:0 0 6px">Patch commands requested via "Patch via Agent" wait here until approved — nothing runs on a host until you approve it.</p>
                <div class="data-table-wrap"><table class="data-table">
                  <thead><tr><th>Host</th><th>Command</th><th>Requested</th><th></th></tr></thead>
                  <tbody>${pendingCommands
                    .map((cmd) => {
                      const agent = agents.find((a) => a.id === cmd.agent_id);
                      const p = cmd.payload || {};
                      return `<tr>
                        <td>${escapeHtml((agent && (agent.hostname || agent.name)) || cmd.agent_id.slice(0, 8))}</td>
                        <td><code>${escapeHtml(p.manager || "")} upgrade ${escapeHtml(p.package || "")}</code></td>
                        <td class="hint">${escapeHtml(fmtWhen(cmd.created_at))}</td>
                        <td class="reports-dl-cell">
                          <button type="button" class="btn-primary-cc agents-approve-cmd" data-agent-id="${escapeHtml(cmd.agent_id)}" data-cmd-id="${escapeHtml(cmd.id)}">Approve</button>
                          <button type="button" class="btn-secondary agents-reject-cmd" data-agent-id="${escapeHtml(cmd.agent_id)}" data-cmd-id="${escapeHtml(cmd.id)}">Reject</button>
                        </td>
                      </tr>`;
                    })
                    .join("")}</tbody></table></div>
              </div>`
            : ""
        }
        ${
          campaigns.length
            ? `<div class="agents-campaigns" style="margin-top:12px">
                <h4 style="margin:0 0 6px">Patch campaigns</h4>
                <div class="data-table-wrap"><table class="data-table">
                  <thead><tr><th>Name</th><th>Package</th><th>Progress</th><th>Status</th><th></th></tr></thead>
                  <tbody>${campaigns
                    .map((c) => {
                      const s = c.summary || {};
                      const total = s.total || 0;
                      const done = s.done || 0;
                      const errored = s.error || 0;
                      const pending = s.pending_approval || 0;
                      const waiting = s.waiting_for_agent || 0;
                      const verified = s.verified || 0;
                      const verifFailed = s.verification_failed || 0;
                      const verifPending = s.verification_pending || 0;
                      let rings = [];
                      try { rings = JSON.parse(c.rings_json || "[]"); } catch (e) { rings = []; }
                      const hasWindow = c.window_start_hour !== -1 && c.window_end_hour !== -1;
                      const localWindow = hasWindow ? _utcHourRangeToLocal(c.window_start_hour, c.window_end_hour) : "";
                      const statusCls =
                        c.status === "completed"
                          ? "status-done"
                          : c.status === "completed_with_failures" || c.status === "halted"
                          ? "status-error"
                          : c.status === "canceled"
                          ? "status-planned"
                          : "status-planned";
                      const statusLabel = (c.status || "").replace(/_/g, " ");
                      return `<tr>
                        <td>${escapeHtml(c.name || "")}${rings.length > 1 ? `<div class="hint">${rings.length} rings</div>` : ""}${hasWindow ? `<div class="hint">window ${c.window_start_hour}:00–${c.window_end_hour}:00 UTC${localWindow ? ` (${escapeHtml(localWindow)} your time)` : ""}</div>` : ""}</td>
                        <td><code>${escapeHtml(c.manager)} upgrade ${escapeHtml(c.package)}</code>${c.target_version ? ` <span class="hint">→ ${escapeHtml(c.target_version)}</span>` : ""}</td>
                        <td class="hint">${done}/${total} executed${errored ? ` · ${errored} failed` : ""}${pending ? ` · ${pending} awaiting approval` : ""}${waiting ? ` · ${waiting} waiting for agent` : ""}${done ? `<div>${verified} verified${verifFailed ? ` · ${verifFailed} not confirmed fixed` : ""}${verifPending ? ` · ${verifPending} verifying…` : ""}</div>` : ""}</td>
                        <td><span class="auto-job-status ${statusCls}">${escapeHtml(statusLabel)}</span></td>
                        <td class="reports-dl-cell">
                          ${pending ? `<button type="button" class="btn-primary-cc agents-approve-campaign" data-id="${escapeHtml(c.id)}">Approve all</button><button type="button" class="btn-secondary agents-reject-campaign" data-id="${escapeHtml(c.id)}">Reject</button>` : ""}
                        </td>
                      </tr>`;
                    })
                    .join("")}</tbody></table></div>
              </div>`
            : ""
        }`;
      el.querySelectorAll(".agents-approve-campaign").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const id = btn.getAttribute("data-id");
          if (!confirm("Approve all pending items in this campaign? They will run on each agent's next check-in.")) return;
          btn.disabled = true;
          try {
            const r = await fetch(`/api/agents/campaigns/${encodeURIComponent(id)}/approve`, {
              method: "POST",
              headers: authHeaders(),
            });
            if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
            if (typeof notifyUser === "function") notifyUser("Campaign approved — items queued for delivery.");
            renderAgentsPanel();
          } catch (err) {
            alert(err.message || "Approve failed");
            btn.disabled = false;
          }
        });
      });
      el.querySelectorAll(".agents-reject-campaign").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const id = btn.getAttribute("data-id");
          const reason = prompt("Reason for rejecting this campaign (optional):") || "";
          btn.disabled = true;
          try {
            const r = await fetch(`/api/agents/campaigns/${encodeURIComponent(id)}/reject`, {
              method: "POST",
              headers: authHeaders({ "Content-Type": "application/json" }),
              body: JSON.stringify({ reason }),
            });
            if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
            if (typeof notifyUser === "function") notifyUser("Campaign rejected.");
            renderAgentsPanel();
          } catch (err) {
            alert(err.message || "Reject failed");
            btn.disabled = false;
          }
        });
      });
      el.querySelectorAll(".agents-approve-cmd").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const agentId = btn.getAttribute("data-agent-id");
          const cmdId = btn.getAttribute("data-cmd-id");
          if (!confirm("Approve this patch command? It will run on the agent's next check-in.")) return;
          btn.disabled = true;
          try {
            const r = await fetch(`/api/agents/${encodeURIComponent(agentId)}/commands/${encodeURIComponent(cmdId)}/approve`, {
              method: "POST",
              headers: authHeaders(),
            });
            if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
            if (typeof notifyUser === "function") notifyUser("Patch command approved — queued for delivery.");
            renderAgentsPanel();
          } catch (err) {
            alert(err.message || "Approve failed");
            btn.disabled = false;
          }
        });
      });
      el.querySelectorAll(".agents-reject-cmd").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const agentId = btn.getAttribute("data-agent-id");
          const cmdId = btn.getAttribute("data-cmd-id");
          const reason = prompt("Reason for rejecting this patch request (optional):") || "";
          btn.disabled = true;
          try {
            const r = await fetch(`/api/agents/${encodeURIComponent(agentId)}/commands/${encodeURIComponent(cmdId)}/reject`, {
              method: "POST",
              headers: authHeaders({ "Content-Type": "application/json" }),
              body: JSON.stringify({ reason }),
            });
            if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
            if (typeof notifyUser === "function") notifyUser("Patch command rejected.");
            renderAgentsPanel();
          } catch (err) {
            alert(err.message || "Reject failed");
            btn.disabled = false;
          }
        });
      });
      el.querySelectorAll(".agents-view-asset").forEach((btn) => {
        btn.addEventListener("click", () => {
          window.showWorkspace?.("assets");
        });
      });
      el.querySelectorAll(".agents-revoke").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const id = btn.getAttribute("data-id");
          try {
            const r = await fetch(`/api/agents/${encodeURIComponent(id)}/revoke`, { method: "POST", headers: authHeaders() });
            if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
            renderAgentsPanel();
          } catch (err) {
            alert(err.message || "Revoke failed");
          }
        });
      });
      el.querySelectorAll(".agents-delete").forEach((btn) => {
        btn.addEventListener("click", async () => {
          if (!confirm("Delete this agent record? The install token will stop working.")) return;
          const id = btn.getAttribute("data-id");
          try {
            const r = await fetch(`/api/agents/${encodeURIComponent(id)}`, { method: "DELETE", headers: authHeaders() });
            if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
            renderAgentsPanel();
          } catch (err) {
            alert(err.message || "Delete failed");
          }
        });
      });
    } catch (err) {
      el.innerHTML = `<p class="hint">Couldn't load agents right now — try refreshing this page. <span class="hint-sub">(${escapeHtml(err.message || String(err))})</span></p>`;
    }
  }
  window.renderAgentsPanel = renderAgentsPanel;

  async function renderTheHivePanel() {
    const el = qs("thehivePanelBody");
    if (!el) return;
    try {
      const [stRes, casesRes] = await Promise.all([
        fetch("/api/thehive/status", { headers: authHeaders() }),
        fetch("/api/thehive/cases?limit=8", { headers: authHeaders() }),
      ]);
      const st = await stRes.json().catch(() => ({}));
      const casesData = await casesRes.json().catch(() => ({}));
      const ping = st.ping || {};
      const statusChip = st.configured
        ? ping.ok
          ? `<span class="auto-job-status status-done">connected</span>`
          : `<span class="auto-job-status status-error">auth/error</span>`
        : `<span class="auto-job-status status-planned">not configured</span>`;
      const cases = casesData.cases || [];
      const casesHtml = cases.length
        ? cases
            .map(
              (c) =>
                `<li><strong>${escapeHtml(c.severity || "?")}</strong> ${escapeHtml(c.title || c.case_id || "")}
                · ${escapeHtml(c.status || "")}${
                  c.incident_id ? ` · incident <code>${escapeHtml(c.incident_id)}</code>` : ""
                }</li>`
            )
            .join("")
        : `<li class="hint">${
            st.configured ? "No cases synced yet — click Sync TheHive" : "Set TheHive credentials in Settings"
          }</li>`;
      el.innerHTML = `
        <p>${statusChip}
          ${st.base_url ? `<span class="hint">${escapeHtml(st.base_url)}</span>` : ""}
          ${ping.error && st.configured ? `<span class="hint">${escapeHtml(ping.error)}</span>` : ""}
        </p>
        <div class="cc-kpi-grid" style="margin:0.5rem 0">
          <article class="cc-kpi"><span>Cases cached</span><strong>${st.cases_cached || 0}</strong></article>
        </div>
        <p class="hint">Recent TheHive cases (sync creates SecuraIQ incidents)</p>
        <ul class="cc-list">${casesHtml}</ul>
        <p class="hint">Settings → TheHive. Authorized IR labs only.</p>`;
    } catch (err) {
      el.innerHTML = `<p class="hint">Couldn't load TheHive — try refreshing. <span class="hint-sub">(${escapeHtml(err.message)})</span></p>`;
    }
  }

  // --- Web URL Scan: dedicated page (not buried in the New Scan modal's
  // scanner dropdown) that drives the SecuraIQ Web Scanner (scanner="zap",
  // app/scanners/zap.py + app/scanners/web_builtin.py) directly against a
  // URL. Reuses the same /api/scans endpoints as "New scan" — this is a
  // focused front-end for the same real, install-free DAST engine, not a
  // separate backend.
  function renderWebScanSteps(progress) {
    const ul = qs("webscanSteps");
    if (!ul) return;
    const steps = Array.isArray(progress) ? progress : [];
    ul.innerHTML = steps
      .map((s) => {
        const st = s.status || "pending";
        const mark = st === "done" ? "✓" : st === "active" ? "●" : st === "failed" ? "✗" : "○";
        return `<li class="scan-step scan-step-${st}"><span>${mark}</span> ${escapeHtml(s.label || s.id || "")}</li>`;
      })
      .join("");
  }

  function renderWebScanResult(scan) {
    const resultPanel = qs("webscanResultPanel");
    const body = qs("webscanResultBody");
    if (!resultPanel || !body) return;
    resultPanel.style.display = "";
    if (!scan || scan.status !== "completed") {
      body.innerHTML = `<p class="hint">${escapeHtml((scan && (scan.error || scan.status)) || "Scan did not complete")}</p>`;
      return;
    }
    const sum = scan.summary || {};
    const reportUrl = `/api/scans/${encodeURIComponent(scan.id)}/report`;
    const pdfUrl = `/api/scans/${encodeURIComponent(scan.id)}/report.pdf`;
    body.innerHTML = `
      <div class="comp-kpi-row">
        <div class="comp-kpi"><span>Findings</span><strong>${sum.findings_created ?? sum.findings ?? 0}</strong></div>
        <div class="comp-kpi"><span>Alerts</span><strong>${sum.alerts ?? "—"}</strong></div>
        <div class="comp-kpi"><span>Risk</span><strong>${
          sum.risk?.score != null ? `${sum.risk.score} (${sum.risk.band || "—"})` : "—"
        }</strong></div>
      </div>
      <div class="cc-action-row" style="margin-top:0.75rem">
        <button type="button" class="btn-secondary" id="webscanDlMd">Download Markdown</button>
        <button type="button" class="btn-secondary" id="webscanDlPdf">Download PDF</button>
        <button type="button" class="btn-secondary" data-workspace="vulns">View findings</button>
        <button type="button" class="btn-secondary" data-workspace="reports">Open Reports</button>
      </div>`;
    body.querySelectorAll("[data-workspace]").forEach((b) =>
      b.addEventListener("click", () => window.showWorkspace?.(b.getAttribute("data-workspace")))
    );
    qs("webscanDlMd")?.addEventListener("click", async () => {
      try {
        if (typeof downloadMd === "function") {
          await downloadMd(reportUrl, `securaiq-scan-${String(scan.id).slice(0, 8)}.md`);
        } else {
          const r = await fetch(reportUrl, { headers: authHeaders() });
          const md = await r.text();
          const a = document.createElement("a");
          a.href = URL.createObjectURL(new Blob([md], { type: "text/markdown" }));
          a.download = `securaiq-scan-${String(scan.id).slice(0, 8)}.md`;
          a.click();
        }
      } catch (err) {
        alert(err.message || "Download failed");
      }
    });
    qs("webscanDlPdf")?.addEventListener("click", async () => {
      try {
        if (typeof window.downloadBinary === "function") {
          await window.downloadBinary(pdfUrl, `securaiq-va-${String(scan.id).slice(0, 8)}.pdf`, "application/pdf");
        } else {
          const r = await fetch(pdfUrl, { headers: authHeaders() });
          const buf = await r.arrayBuffer();
          const a = document.createElement("a");
          a.href = URL.createObjectURL(new Blob([buf], { type: "application/pdf" }));
          a.download = `securaiq-va-${String(scan.id).slice(0, 8)}.pdf`;
          a.click();
        }
      } catch (err) {
        alert(err.message || "Download failed");
      }
    });
  }

  async function pollWebScan(scanId) {
    const statusLabel = qs("webscanStatusLabel");
    const summaryEl = qs("webscanSummary");
    if (typeof window.watchScanRealtime === "function") window.watchScanRealtime(scanId);
    for (let i = 0; i < 240; i++) {
      let res;
      try {
        res = await fetch(`/api/scans/${encodeURIComponent(scanId)}`, { headers: authHeaders() });
      } catch {
        break;
      }
      if (!res.ok) break;
      const scan = await res.json().catch(() => ({}));
      if (statusLabel) statusLabel.textContent = (scan.status || "").toUpperCase();
      renderWebScanSteps(scan.progress);
      const terminal = ["completed", "failed", "blocked"].includes(scan.status);
      if (terminal) {
        if (typeof window.unwatchScanRealtime === "function") window.unwatchScanRealtime(scanId);
        renderWebScanResult(scan);
        if (summaryEl) {
          summaryEl.textContent =
            scan.status === "completed" ? `Scan complete on ${scan.target || ""}` : scan.error || scan.status;
        }
        if (typeof syncLiveWorkspace === "function") syncLiveWorkspace({ pushType: "scan" });
        return scan;
      }
      if (summaryEl) summaryEl.textContent = `Scanning ${scan.target || ""}…`;
      await new Promise((r) => setTimeout(r, 800));
    }
    if (summaryEl) summaryEl.textContent = "Still running — check Reports or refresh later.";
    return null;
  }

  async function submitWebScan(ev) {
    ev.preventDefault();
    const targetEl = qs("webscanTarget");
    const target = (targetEl?.value || "").trim();
    const profile = qs("webscanProfile")?.value || "vulnerability";
    const authorized = !!qs("webscanAuthorized")?.checked;
    if (!target) {
      alert("Enter a URL to scan.");
      targetEl?.focus();
      return;
    }
    if (!authorized) {
      alert("Confirm you're authorized to scan this target before starting.");
      return;
    }
    const btn = qs("webscanStart");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Starting…";
    }
    const progressPanel = qs("webscanProgressPanel");
    const resultPanel = qs("webscanResultPanel");
    const statusLabel = qs("webscanStatusLabel");
    const summaryEl = qs("webscanSummary");
    if (resultPanel) resultPanel.style.display = "none";
    if (progressPanel) progressPanel.style.display = "";
    if (statusLabel) statusLabel.textContent = "QUEUED";
    if (summaryEl) summaryEl.textContent = `Starting web scan on ${target}…`;
    renderWebScanSteps([]);
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          target,
          scanner: "zap",
          profile,
          authorized: true,
          scope: [target],
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      const scanId = data.scan_id;
      if (!scanId) throw new Error("No scan_id returned");
      await pollWebScan(scanId);
    } catch (err) {
      if (statusLabel) statusLabel.textContent = "FAILED";
      if (summaryEl) summaryEl.textContent = String(err.message || err);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Start scan";
      }
      refreshWebScanHistory();
    }
  }

  async function refreshWebScanHistory() {
    const el = qs("webscanHistoryBody");
    if (!el) return;
    try {
      const res = await fetch("/api/scans?limit=25", { headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      const rows = (data.scans || []).filter((s) => s.scanner === "zap");
      if (!rows.length) {
        el.innerHTML = `<p class="hint">No web scans yet — enter a URL above and click Start scan.</p>`;
        return;
      }
      const fmtWhen = (ts) => {
        if (ts == null || ts === "") return "—";
        const d = new Date(typeof ts === "number" && ts < 1e12 ? ts * 1000 : ts);
        return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
      };
      el.innerHTML = `<div class="data-table-wrap"><table class="data-table">
        <thead><tr><th>Target</th><th>Status</th><th>Findings</th><th>When</th><th></th></tr></thead>
        <tbody>${rows
          .map((s) => {
            const sum = s.summary || {};
            return `<tr>
              <td><strong>${escapeHtml(s.target || "")}</strong></td>
              <td>${escapeHtml(s.status || "")}</td>
              <td>${sum.findings_created ?? sum.findings ?? "—"}</td>
              <td class="hint">${escapeHtml(fmtWhen(s.created_at))}</td>
              <td><button type="button" class="btn-secondary webscan-view" data-id="${escapeHtml(s.id)}">View</button></td>
            </tr>`;
          })
          .join("")}</tbody></table></div>`;
      el.querySelectorAll(".webscan-view").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const id = btn.getAttribute("data-id");
          try {
            const r = await fetch(`/api/scans/${encodeURIComponent(id)}`, { headers: authHeaders() });
            const scan = await r.json().catch(() => ({}));
            if (!r.ok) throw new Error(scan.detail || `HTTP ${r.status}`);
            const progressPanel = qs("webscanProgressPanel");
            if (progressPanel) progressPanel.style.display = "none";
            renderWebScanResult(scan);
            qs("webscanResultPanel")?.scrollIntoView({ behavior: "smooth", block: "start" });
          } catch (err) {
            alert(err.message || "Could not load scan");
          }
        });
      });
    } catch (err) {
      el.innerHTML = `<p class="hint">Could not load web scan history: ${escapeHtml(err.message || String(err))}</p>`;
    }
  }

  async function renderWebScanPage() {
    const body = qs("webscanPageBody");
    if (!body) return;
    body.innerHTML = `
      <div class="webscan-page">
        <section class="cc-panel">
          <header><h2>Scan a URL</h2></header>
          <form id="webscanForm" class="inline-form inline-form-col" style="gap:0.6rem">
            <input id="webscanTarget" type="text" placeholder="https://example.com" required style="width:100%" />
            <div style="display:flex;gap:0.75rem;flex-wrap:wrap;align-items:center">
              <label class="hint">Depth
                <select id="webscanProfile">
                  <option value="web">Standard — headers, TLS, robots/sitemap</option>
                  <option value="vulnerability" selected>Deep — + sensitive paths, cookies, CORS</option>
                  <option value="full">Full — + active checks (reflected input, open redirect)</option>
                </select>
              </label>
              <label class="hint"><input type="checkbox" id="webscanAuthorized" checked /> I'm authorized to scan this target</label>
              <button type="submit" class="btn-primary" id="webscanStart">Start scan</button>
            </div>
            <p class="hint">Authorized lab/owned targets only. Public targets need the checkbox above confirmed.</p>
          </form>
        </section>
        <section class="cc-panel" id="webscanProgressPanel" style="margin-top:1rem;display:none">
          <header><h2>Scan progress</h2><span class="hint" id="webscanStatusLabel"></span></header>
          <ul class="cc-list scan-steps" id="webscanSteps"></ul>
          <p class="hint" id="webscanSummary"></p>
        </section>
        <section class="cc-panel" id="webscanResultPanel" style="margin-top:1rem;display:none">
          <header><h2>Results</h2></header>
          <div id="webscanResultBody"></div>
        </section>
        <section class="cc-panel" style="margin-top:1rem">
          <header><h2>Recent web scans</h2></header>
          <div id="webscanHistoryBody"><p class="hint">Loading…</p></div>
        </section>
      </div>`;
    qs("webscanForm")?.addEventListener("submit", submitWebScan);
    await refreshWebScanHistory();
  }
  window.renderWebScanPage = renderWebScanPage;

  // Push types that actually affect the SOC page's SIEM/XDR/incident panels.
  // Used to skip pointless sub-panel refetches when a live event (e.g. an
  // unrelated scan/tool tick) fires while the user is sitting on SOC view.
  const SOC_RELEVANT_PUSH_TYPES = new Set(["siem", "xdr", "xdr_batch", "incident", "hunt", "thehive", "agent", "agent_threat"]);

  async function renderSocPage(opts) {
    opts = opts || {};
    const quiet = !!opts.quiet;
    const body = qs("socPageBody");
    if (!body) return;
    const alreadyRendered = body.dataset.socRendered === "1";
    // Quiet realtime refresh on an already-painted page: update numbers/lists
    // in place instead of wiping the whole page to "Loading…" and rebuilding
    // — that flash/rebuild was firing on every SSE tick (scans, tools, jobs),
    // not just SIEM/XDR-relevant ones, and re-fetched all three sub-panels
    // every time regardless of relevance.
    if (quiet && alreadyRendered) {
      let data = {};
      try {
        const res = await fetch("/api/soc", { headers: authHeaders() });
        data = await res.json().catch(() => ({}));
        if (!res.ok) return; // keep last-good view rather than flashing an error
      } catch {
        return;
      }
      const incidents = data.incidents || [];
      const alerts = data.alerts || [];
      const kpiEls = body.querySelectorAll(".cc-kpi-grid .cc-kpi strong");
      if (kpiEls[0]) kpiEls[0].textContent = String(data.incidents_open || 0);
      if (kpiEls[1]) kpiEls[1].textContent = String(data.critical_vulns || 0);
      if (kpiEls[2]) kpiEls[2].textContent = String(data.playbooks || 0);
      const alertsList = qs("socAlertsList");
      if (alertsList) {
        alertsList.innerHTML = alerts.length
          ? alerts.map((a) => `<li><strong>${escapeHtml(a.kind)}</strong> ${escapeHtml(a.title)}</li>`).join("")
          : `<li class="hint">No alerts</li>`;
      }
      const incList = qs("socIncidentsList");
      if (incList) {
        incList.innerHTML = incidents.length
          ? incidents
              .map(
                (i) =>
                  `<li><strong>${escapeHtml(i.severity)}</strong> ${escapeHtml(i.title)}
                  <button type="button" class="btn-secondary ws-ask-ai" data-kind="incident" data-json="${escapeHtml(
                    JSON.stringify({ id: i.id, title: i.title, severity: i.severity })
                  )}">Ask AI</button>
                  <button type="button" class="btn-secondary ws-close-inc" data-id="${i.id}">Close</button>
                  <button type="button" class="btn-secondary ws-del-inc" data-id="${i.id}">Delete</button></li>`
              )
              .join("")
          : `<li class="hint">No open incidents</li>`;
        wireAskAiButtons("socPageBody");
        incList.querySelectorAll(".ws-close-inc").forEach((btn) => {
          btn.addEventListener("click", async () => {
            await fetch(`/api/incidents/${btn.getAttribute("data-id")}`, {
              method: "PATCH",
              headers: authHeaders({ "Content-Type": "application/json" }),
              body: JSON.stringify({ status: "closed" }),
            });
            renderSocPage();
          });
        });
        incList.querySelectorAll(".ws-del-inc").forEach((btn) => {
          btn.addEventListener("click", async () => {
            if (!confirm("Delete this incident?")) return;
            await fetch(`/api/incidents/${btn.getAttribute("data-id")}`, { method: "DELETE", headers: authHeaders() });
            renderSocPage();
            if (typeof loadCommandCenter === "function") loadCommandCenter();
          });
        });
      }
      // Only refetch the SIEM/XDR/TheHive sub-panels when the push is
      // actually relevant to them — a bare heartbeat or unrelated scan/tool
      // event shouldn't re-hit /api/siem/overview, /api/xdr/status, etc.
      if (!opts.pushType || SOC_RELEVANT_PUSH_TYPES.has(opts.pushType)) {
        renderAgentsPanel();
        renderXdrPanel(true);
        renderWazuhPanel(true);
        renderTheHivePanel(true);
      }
      return;
    }

    body.innerHTML = `<p class="hint">Loading…</p>`;
    let data = {};
    try {
      const res = await fetch("/api/soc", { headers: authHeaders() });
      data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `SOC failed (${res.status})`);
    } catch (err) {
      body.innerHTML = `<p class="hint">Could not load SOC: ${escapeHtml(err.message || String(err))}</p>`;
      return;
    }
    const incidents = data.incidents || [];
    const alerts = data.alerts || [];
    body.innerHTML = `
      <div class="cc-kpi-grid">
        <article class="cc-kpi"><span>Open incidents</span><strong>${data.incidents_open || 0}</strong></article>
        <article class="cc-kpi"><span>Critical/high vulns</span><strong>${data.critical_vulns || 0}</strong></article>
        <article class="cc-kpi"><span>Playbooks</span><strong>${data.playbooks || 0}</strong></article>
      </div>
      <section class="cc-panel" id="riskPriorityPanel" style="margin-top:1rem">
        <header><h2>What to fix first</h2></header>
        <div id="riskPriorityBody"><p class="hint">Loading…</p></div>
      </section>
      <div class="ws-grid-2" style="margin-top:1rem">
        <section class="cc-panel">
          <header><h2>Alerts</h2></header>
          <ul class="cc-list" id="socAlertsList">${
            alerts.length
              ? alerts.map((a) => `<li><strong>${escapeHtml(a.kind)}</strong> ${escapeHtml(a.title)}</li>`).join("")
              : `<li class="hint">No alerts</li>`
          }</ul>
        </section>
        <section class="cc-panel">
          <header><h2>Open incidents</h2></header>
          <ul class="cc-list" id="socIncidentsList">${
            incidents.length
              ? incidents
                  .map(
                    (i) =>
                      `<li><strong>${escapeHtml(i.severity)}</strong> ${escapeHtml(i.title)}
                      <button type="button" class="btn-secondary ws-ask-ai" data-kind="incident" data-json="${escapeHtml(
                        JSON.stringify({ id: i.id, title: i.title, severity: i.severity })
                      )}">Ask AI</button>
                      <button type="button" class="btn-secondary ws-close-inc" data-id="${i.id}">Close</button>
                      <button type="button" class="btn-secondary ws-del-inc" data-id="${i.id}">Delete</button></li>`
                  )
                  .join("")
              : `<li class="hint">No open incidents</li>`
          }</ul>
          <form id="incidentForm" class="inline-form">
            <input id="incidentTitle" placeholder="New incident title" required />
            <select id="incidentSeverity"><option value="critical">Critical</option><option value="high" selected>High</option><option value="medium">Medium</option></select>
            <button type="submit">Create</button>
          </form>
        </section>
      </div>
      <section class="cc-panel" id="agentsPanel" style="margin-top:1rem">
        <header><h2>SecuraIQ Agents</h2><div style="display:flex;gap:0.5rem"><button type="button" class="btn-secondary" id="agentsCampaignBtn">New patch campaign</button><button type="button" class="btn-secondary" id="agentsEnrollBtn">Enroll new agent</button></div></header>
        <div id="agentsEnrollResult"></div>
        <div id="agentsCampaignForm"></div>
        <div id="agentsPanelBody"><p class="hint">Loading…</p></div>
      </section>
      <section class="cc-panel" id="xdrPanel" style="margin-top:1rem">
        <header><h2>XDR / EDR</h2><button type="button" class="btn-secondary" id="xdrSyncBtn">Sync now</button></header>
        <div id="xdrPanelBody"><p class="hint">Loading…</p></div>
      </section>
      <section class="cc-panel" id="wazuhPanel" style="margin-top:1rem">
        <header><h2>SecuraIQ SIEM</h2><button type="button" class="btn-secondary" id="wazuhSyncBtn">Sync SIEM</button></header>
        <div id="wazuhPanelBody"><p class="hint">Loading…</p></div>
      </section>
      <section class="cc-panel" id="thehivePanel" style="margin-top:1rem">
        <header><h2>TheHive</h2><button type="button" class="btn-secondary" id="thehiveSyncBtn">Sync TheHive</button></header>
        <div id="thehivePanelBody"><p class="hint">Loading…</p></div>
      </section>`;
    body.dataset.socRendered = "1";
    renderRiskPriorityPanel();
    renderAgentsPanel();
    renderXdrPanel();
    renderWazuhPanel();
    renderTheHivePanel();
    qs("agentsEnrollBtn")?.addEventListener("click", async () => {
      const btn = qs("agentsEnrollBtn");
      const resultEl = qs("agentsEnrollResult");
      if (btn) { btn.disabled = true; btn.textContent = "Enrolling…"; }
      try {
        const res = await fetch("/api/agents/enroll", {
          method: "POST",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ name: "" }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        if (resultEl) {
          resultEl.innerHTML = `
            <div class="cc-panel" style="margin:0.75rem 0;background:var(--panel-2,rgba(255,255,255,0.03))">
              <p class="hint"><strong>Agent enrolled</strong> · id <code>${escapeHtml(data.agent_id)}</code></p>
              <p class="hint">This token is shown ONCE — copy it now. Run this on the server you want to monitor:</p>
              <textarea readonly rows="3" style="width:100%;font-family:ui-monospace,monospace;font-size:0.82rem" onclick="this.select()">${escapeHtml(
                data.install_hint || ""
              )}</textarea>
              <button type="button" class="btn-secondary" id="agentsEnrollDismiss" style="margin-top:0.5rem">Dismiss</button>
            </div>`;
          qs("agentsEnrollDismiss")?.addEventListener("click", () => {
            resultEl.innerHTML = "";
          });
        }
        renderAgentsPanel();
      } catch (err) {
        if (typeof notifyUser === "function") notifyUser(`**Agent enroll failed:** ${err.message || err}`);
        else alert(err.message || "Enroll failed");
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = "Enroll new agent"; }
      }
    });
    qs("agentsCampaignBtn")?.addEventListener("click", async () => {
      const formEl = qs("agentsCampaignForm");
      if (!formEl) return;
      if (formEl.innerHTML) { formEl.innerHTML = ""; return; }
      let agents = [];
      try {
        const r = await fetch("/api/agents", { headers: authHeaders() });
        const d = await r.json().catch(() => ({}));
        agents = (d.agents || []).filter((a) => !a.revoked);
      } catch (e) {
        agents = [];
      }
      if (!agents.length) {
        if (typeof notifyUser === "function") notifyUser("No enrolled agents to target — enroll one first.");
        return;
      }
      formEl.innerHTML = `
        <div class="cc-panel" style="margin:0.75rem 0;background:var(--panel-2,rgba(255,255,255,0.03))">
          <h4 style="margin:0 0 8px">New patch campaign</h4>
          <form id="campaignForm" class="inline-form" style="flex-wrap:wrap">
            <input id="campaignName" placeholder="Campaign name (optional)" style="min-width:220px" />
            <select id="campaignManager">
              <option value="apt">apt (Linux)</option>
              <option value="winget">winget (Windows)</option>
              <option value="brew">brew (macOS)</option>
              <option value="pip">pip</option>
            </select>
            <input id="campaignPackage" placeholder="Package name" required style="min-width:160px" />
            <input id="campaignTargetVersion" placeholder="Target version (optional)" style="min-width:160px" />
            <button type="submit" class="btn-primary-cc">Create campaign</button>
          </form>
          <p class="hint" style="margin:8px 0 4px">Target agents (optional ring # for a phased rollout — 0 goes first, higher rings only dispatch once the prior ring succeeds):</p>
          <div style="max-height:160px;overflow:auto;display:flex;flex-direction:column;gap:4px">
            ${agents
              .map(
                (a) =>
                  `<label class="hint" style="display:flex;align-items:center;gap:6px"><input type="checkbox" class="campaign-target" value="${escapeHtml(a.id)}" /> ${escapeHtml(a.hostname || a.name || a.id.slice(0, 8))} <span style="margin-left:auto">ring <input type="number" class="campaign-target-ring" data-agent-id="${escapeHtml(a.id)}" min="0" value="0" style="width:48px" /></span></label>`
              )
              .join("")}
          </div>
          <details class="hk-setup-advanced" style="margin-top:8px">
            <summary class="hint">Advanced: ring threshold + maintenance window</summary>
            <div class="inline-form" style="flex-wrap:wrap;margin-top:6px">
              <label class="hint">Ring success threshold % <input id="campaignRingThreshold" type="number" min="0" max="100" value="100" style="width:64px" /></label>
              <label class="hint">Window start hour (UTC) <input id="campaignWindowStart" type="number" min="0" max="23" placeholder="none" style="width:64px" /></label>
              <label class="hint">Window end hour (UTC) <input id="campaignWindowEnd" type="number" min="0" max="23" placeholder="none" style="width:64px" /></label>
            </div>
            <p class="hint" style="margin:4px 0 0">Leave window fields blank for no restriction. A command still won't be delivered to its agent outside the window, even once approved.</p>
          </details>
        </div>`;
      qs("campaignForm")?.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const checked = Array.from(formEl.querySelectorAll(".campaign-target:checked"));
        if (!checked.length) {
          if (typeof notifyUser === "function") notifyUser("Select at least one target agent for the campaign.");
          return;
        }
        const manager = qs("campaignManager")?.value || "apt";
        const pkg = (qs("campaignPackage")?.value || "").trim();
        const targetVersion = (qs("campaignTargetVersion")?.value || "").trim();
        const name = (qs("campaignName")?.value || "").trim();
        if (!pkg) return;

        // group targets by ring number into an ordered rings array
        const byRing = {};
        checked.forEach((cb) => {
          const ringInput = formEl.querySelector(`.campaign-target-ring[data-agent-id="${cb.value}"]`);
          const ring = Math.max(0, parseInt((ringInput && ringInput.value) || "0", 10) || 0);
          (byRing[ring] = byRing[ring] || []).push(cb.value);
        });
        const ringNumbers = Object.keys(byRing).map(Number).sort((a, b) => a - b);
        const rings = ringNumbers.map((r) => byRing[r]);
        const usesRings = ringNumbers.length > 1 || ringNumbers[0] !== 0;
        const totalTargets = checked.length;

        const thresholdVal = parseFloat(qs("campaignRingThreshold")?.value || "100");
        const startVal = (qs("campaignWindowStart")?.value || "").trim();
        const endVal = (qs("campaignWindowEnd")?.value || "").trim();
        const windowStartHour = startVal === "" ? -1 : parseInt(startVal, 10);
        const windowEndHour = endVal === "" ? -1 : parseInt(endVal, 10);

        if (
          !confirm(
            `Create a patch campaign requesting a real ${manager} upgrade of "${pkg}" across ${totalTargets} agent(s)` +
              (rings.length > 1 ? ` in ${rings.length} rings` : "") +
              `?\n\nEach target lands as a pending approval — nothing runs until approved.`
          )
        ) {
          return;
        }
        try {
          const payload = {
            name,
            manager,
            package: pkg,
            target_version: targetVersion,
            ring_threshold_pct: Number.isFinite(thresholdVal) ? thresholdVal : 100,
            window_start_hour: Number.isFinite(windowStartHour) ? windowStartHour : -1,
            window_end_hour: Number.isFinite(windowEndHour) ? windowEndHour : -1,
          };
          if (usesRings) {
            payload.rings = rings;
          } else {
            payload.agent_ids = rings[0] || [];
          }
          const res = await fetch("/api/agents/campaigns", {
            method: "POST",
            headers: authHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify(payload),
          });
          const body = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
          if (typeof notifyUser === "function") {
            notifyUser(`**Campaign created** · ${body.requested} target(s) pending approval.`);
          }
          formEl.innerHTML = "";
          renderAgentsPanel();
        } catch (err) {
          if (typeof notifyUser === "function") notifyUser(`Campaign creation failed: ${err.message || err}`);
          else alert(err.message || "Campaign creation failed");
        }
      });
    });
    qs("xdrSyncBtn")?.addEventListener("click", async () => {
      const btn = qs("xdrSyncBtn");
      if (btn) { btn.disabled = true; btn.textContent = "Syncing…"; }
      try {
        const res = await fetch("/api/xdr/sync", { method: "POST", headers: authHeaders() });
        const data = await res.json().catch(() => ({}));
        if (!res.ok && typeof notifyUser === "function") {
          notifyUser(`**XDR sync failed:** ${data.detail || res.status}`);
        } else if (typeof notifyUser === "function") {
          notifyUser(`**XDR sync queued** · job \`${(data.job && data.job.id) || "?"}\``);
        }
        const jobId = data.job && data.job.id;
        if (jobId && typeof window.waitForJob === "function") {
          await window.waitForJob(jobId, { timeoutMs: 120000 });
        }
      } catch (err) {
        if (typeof notifyUser === "function") notifyUser(`**XDR sync error:** ${err.message || err}`);
      }
      renderXdrPanel();
      if (btn) { btn.disabled = false; btn.textContent = "Sync now"; }
    });
    qs("wazuhSyncBtn")?.addEventListener("click", async () => {
      const btn = qs("wazuhSyncBtn");
      if (btn) { btn.disabled = true; btn.textContent = "Syncing…"; }
      try {
        const res = await fetch("/api/siem/sync", { method: "POST", headers: authHeaders() });
        const data = await res.json().catch(() => ({}));
        if (!res.ok && typeof notifyUser === "function") {
          notifyUser(`**SecuraIQ SIEM sync failed:** ${data.detail || res.status}`);
        } else if (typeof notifyUser === "function") {
          notifyUser(`**SecuraIQ SIEM sync queued** · job \`${(data.job && data.job.id) || "?"}\``);
        }
        const jobId = data.job && data.job.id;
        if (jobId && typeof window.waitForJob === "function") {
          const job = await window.waitForJob(jobId, { timeoutMs: 120000 });
          const r = job?.result || {};
          if ((job?.status || "") === "done" && typeof notifyUser === "function") {
            notifyUser(
              `**SIEM sync done** · ${r.agents_total || 0} agents · ${r.assets_linked || 0} assets · ${r.alerts_new || 0} new alerts`
            );
          } else if ((job?.status || "") === "error" && typeof notifyUser === "function") {
            notifyUser(`**SIEM sync error:** ${job.error || "failed"}`);
          }
        }
      } catch (err) {
        if (typeof notifyUser === "function") notifyUser(`**SecuraIQ SIEM sync error:** ${err.message || err}`);
      }
      renderWazuhPanel();
      renderXdrPanel();
      if (typeof renderAssetsPage === "function") renderAssetsPage();
      if (typeof loadCommandCenter === "function") loadCommandCenter();
      if (btn) { btn.disabled = false; btn.textContent = "Sync SIEM"; }
    });
    qs("thehiveSyncBtn")?.addEventListener("click", async () => {
      const btn = qs("thehiveSyncBtn");
      if (btn) { btn.disabled = true; btn.textContent = "Syncing…"; }
      try {
        const res = await fetch("/api/thehive/sync", { method: "POST", headers: authHeaders() });
        const data = await res.json().catch(() => ({}));
        if (!res.ok && typeof notifyUser === "function") {
          notifyUser(`**TheHive sync failed:** ${data.detail || res.status}`);
        } else if (typeof notifyUser === "function") {
          notifyUser(`**TheHive sync queued** · job \`${(data.job && data.job.id) || "?"}\``);
        }
        const jobId = data.job && data.job.id;
        if (jobId && typeof window.waitForJob === "function") {
          const job = await window.waitForJob(jobId, { timeoutMs: 120000 });
          const r = job?.result || {};
          if ((job?.status || "") === "done" && typeof notifyUser === "function") {
            notifyUser(
              `**TheHive sync done** · ${r.cases || 0} cases · ${r.new_or_updated || 0} new/updated · ${r.incidents_created || 0} incident(s) created`
            );
          } else if ((job?.status || "") === "error" && typeof notifyUser === "function") {
            notifyUser(`**TheHive sync error:** ${job.error || "failed"}`);
          }
        }
      } catch (err) {
        if (typeof notifyUser === "function") notifyUser(`**TheHive sync error:** ${err.message || err}`);
      }
      renderSocPage();
      if (btn) { btn.disabled = false; btn.textContent = "Sync TheHive"; }
    });
    qs("incidentForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      await fetch("/api/incidents", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          title: qs("incidentTitle")?.value?.trim(),
          severity: qs("incidentSeverity")?.value || "high",
        }),
      });
      renderSocPage();
    });
    wireAskAiButtons("socPageBody");
    body.querySelectorAll(".ws-close-inc").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await fetch(`/api/incidents/${btn.getAttribute("data-id")}`, {
          method: "PATCH",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ status: "closed" }),
        });
        renderSocPage();
      });
    });
    body.querySelectorAll(".ws-del-inc").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm("Delete this incident?")) return;
        await fetch(`/api/incidents/${btn.getAttribute("data-id")}`, { method: "DELETE", headers: authHeaders() });
        renderSocPage();
        if (typeof loadCommandCenter === "function") loadCommandCenter();
      });
    });
  }

  async function renderEvidencePage() {
    const body = qs("evidencePageBody");
    if (!body) return;
    let filesRes, linksRes, remsRes, queueRes;
    try {
      [filesRes, linksRes, remsRes, queueRes] = await Promise.all([
        fetch("/api/files", { headers: authHeaders() }),
        fetch("/api/evidence", { headers: authHeaders() }),
        fetch("/api/gap/remediations", { headers: authHeaders() }),
        fetch("/api/gap/evidence-queue?limit=40", { headers: authHeaders() }),
      ]);
    } catch (err) {
      body.innerHTML = `<p class="hint">Could not load evidence: ${escapeHtml(err.message || String(err))}</p>`;
      return;
    }
    const filesData = await filesRes.json().catch(() => ({}));
    const linksData = await linksRes.json().catch(() => ({}));
    const remsData = await remsRes.json().catch(() => ({}));
    const queueData = await queueRes.json().catch(() => ({}));
    const queueError = !queueRes.ok
      ? typeof queueData.detail === "string"
        ? queueData.detail
        : `Evidence queue unavailable (HTTP ${queueRes.status})`
      : null;
    // Real bug found in audit: files/links/remediations were parsed and
    // rendered regardless of HTTP status, so a failed fetch looked exactly
    // like a genuinely empty (healthy) evidence locker. Track and surface it.
    const loadErrors = [];
    if (!filesRes.ok) loadErrors.push(`files (HTTP ${filesRes.status})`);
    if (!linksRes.ok) loadErrors.push(`evidence links (HTTP ${linksRes.status})`);
    if (!remsRes.ok) loadErrors.push(`remediations (HTTP ${remsRes.status})`);
    const files = filesRes.ok ? filesData.files || filesData.items || [] : [];
    const links = linksRes.ok ? linksData.evidence || [] : [];
    const rems = remsRes.ok ? remsData.remediations || [] : [];
    const queue = queueData.items || [];
    const remOpts = rems
      .map((r) => `<option value="${escapeHtml(r.id)}">${escapeHtml(r.control_id)} — ${escapeHtml(r.title)}</option>`)
      .join("");
    const fileOpts = files
      .map((f) => `<option value="${escapeHtml(f.id)}">${escapeHtml(f.filename || f.name || f.id)}</option>`)
      .join("");
    const fmtTs = (ts) => {
      if (!ts) return "—";
      const d = new Date(Number(ts) * (Number(ts) < 1e12 ? 1000 : 1));
      return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleDateString();
    };
    const queueRows = queueError
      ? `<tr><td colspan="4" class="hint">Could not load evidence queue: ${escapeHtml(queueError)}</td></tr>`
      : queue.length
      ? queue
          .slice(0, 25)
          .map(
            (q) => `<tr>
              <td><code>${escapeHtml(q.control_id || "")}</code></td>
              <td>${escapeHtml(q.title || "")}<div class="hint">${escapeHtml(q.framework_id || "")} · ${escapeHtml(
                q.status || ""
              )}</div></td>
              <td class="hint">${escapeHtml((q.suggested_artifacts || []).slice(0, 2).join(" · ") || "—")}</td>
              <td><button type="button" class="btn-secondary ws-queue-fill" data-control="${escapeHtml(
                q.control_id || ""
              )}" data-aid="${escapeHtml(q.assessment_id || "")}">Collect</button></td>
            </tr>`
          )
          .join("")
      : `<tr><td colspan="4" class="hint">No open gaps without evidence — run a gap analysis or link artifacts</td></tr>`;
    body.innerHTML = `
      <p class="hint">Evidence Control Center — map artifacts to controls with owner, status, and expiry for audits.</p>
      ${
        loadErrors.length
          ? `<p class="hint" style="color:#c0392b">Could not load ${escapeHtml(
              loadErrors.join(", ")
            )} — showing partial data, not a confirmed clean/empty state. Reload to retry.</p>`
          : ""
      }
      <section class="cc-panel">
        <header>
          <h2>Collect next</h2>
          <span class="hint">${queueData.count || 0} controls need accepted evidence</span>
        </header>
        <div class="data-table-wrap">
          <table class="data-table">
            <thead><tr><th>Control</th><th>Gap</th><th>Suggested artifacts</th><th></th></tr></thead>
            <tbody>${queueRows}</tbody>
          </table>
        </div>
      </section>
      <section class="cc-panel" style="margin-top:1rem">
        <header><h2>Evidence register</h2></header>
        <div class="data-table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Evidence</th>
                <th>Owner</th>
                <th>Mapped control</th>
                <th>Status</th>
                <th>Expiry</th>
                <th>Comments</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              ${
                links.length
                  ? links
                      .map((l) => {
                        const owner = l.owner || l.remediation_owner || "Unassigned";
                        return `<tr>
                          <td><strong>${escapeHtml(l.filename || l.file_id || "file")}</strong>
                            <div class="hint">${escapeHtml(l.remediation_title || "")}</div></td>
                          <td>${escapeHtml(owner)}</td>
                          <td><code>${escapeHtml(l.control_id || "—")}</code></td>
                          <td><span class="wq-badge pri-${escapeHtml((l.status || "accepted").toLowerCase())}">${escapeHtml(
                            l.status || "accepted"
                          )}</span></td>
                          <td>${escapeHtml(l.expiry || "—")}</td>
                          <td>${escapeHtml(l.notes || "—")}</td>
                          <td>
                            <button type="button" class="btn-secondary ws-edit-ev" data-id="${escapeHtml(l.id)}"
                              data-owner="${escapeHtml(l.owner || "")}" data-control="${escapeHtml(l.control_id || "")}"
                              data-status="${escapeHtml(l.status || "accepted")}" data-expiry="${escapeHtml(l.expiry || "")}"
                              data-notes="${escapeHtml(l.notes || "")}">Edit</button>
                            <button type="button" class="btn-secondary ws-del-ev" data-id="${escapeHtml(l.id)}">Remove</button>
                          </td>
                        </tr>`;
                      })
                      .join("")
                  : `<tr><td colspan="7" class="hint">No evidence links yet — upload and link below</td></tr>`
              }
            </tbody>
          </table>
        </div>
        <p class="hint" style="margin-top:0.5rem">${links.length} linked · ${files.length} files in locker · last refresh ${fmtTs(
          Date.now() / 1000
        )}</p>
      </section>
      <div class="ws-grid-2" style="margin-top:1rem">
        <section class="cc-panel">
          <header><h2>Files</h2></header>
          <div class="data-table-wrap">
            <table class="data-table">
              <thead><tr><th>File</th><th>Size</th><th>Uploaded</th></tr></thead>
              <tbody>
                ${
                  files.length
                    ? files
                        .map(
                          (f) =>
                            `<tr><td>${escapeHtml(f.filename || f.name || f.id)}</td><td>${escapeHtml(
                              String(f.size_bytes || f.size || "—")
                            )}</td><td>${escapeHtml(fmtTs(f.created_at))}</td></tr>`
                        )
                        .join("")
                    : `<tr><td colspan="3" class="hint">No files yet — use Upload</td></tr>`
                }
              </tbody>
            </table>
          </div>
        </section>
        <section class="cc-panel">
          <header><h2>Link evidence</h2></header>
          <form id="evidenceLinkForm" class="inline-form inline-form-col" style="gap:0.5rem">
            <select id="evidenceFileId" required ${files.length ? "" : "disabled"}>
              <option value="">Select file</option>${fileOpts}
            </select>
            <select id="evidenceRemId">
              <option value="">No remediation (control note only)</option>${remOpts}
            </select>
            <input id="evidenceControlId" placeholder="Mapped control (e.g. A.5.1)" />
            <input id="evidenceOwner" placeholder="Owner" />
            <select id="evidenceStatus">
              <option value="accepted">accepted</option>
              <option value="review">review</option>
              <option value="draft">draft</option>
              <option value="expired">expired</option>
              <option value="rejected">rejected</option>
            </select>
            <input id="evidenceExpiry" type="date" title="Expiry" />
            <input id="evidenceNotes" placeholder="Comments" />
            <button type="submit" ${files.length ? "" : "disabled"}>Link evidence</button>
          </form>
        </section>
      </div>
      <div class="cc-action-row" style="margin-top:1rem">
        <button type="button" class="cc-action" id="evidenceAsk">Ask AI: missing evidence</button>
        <button type="button" class="btn-secondary" id="evidenceAuditPack">Download latest audit pack</button>
        <button type="button" class="btn-secondary" data-workspace="frameworks">Open frameworks</button>
        <button type="button" class="btn-secondary" data-workspace="remediations">Open controls</button>
      </div>`;
    qs("evidenceLinkForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fileId = qs("evidenceFileId")?.value;
      if (!fileId) return;
      await fetch("/api/evidence", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          file_id: fileId,
          remediation_id: qs("evidenceRemId")?.value || null,
          control_id: qs("evidenceControlId")?.value?.trim() || "",
          owner: qs("evidenceOwner")?.value?.trim() || "",
          status: qs("evidenceStatus")?.value || "accepted",
          expiry: qs("evidenceExpiry")?.value || "",
          notes: qs("evidenceNotes")?.value?.trim() || "",
        }),
      });
      renderEvidencePage();
    });
    body.querySelectorAll(".ws-del-ev").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await fetch(`/api/evidence/${btn.getAttribute("data-id")}`, {
          method: "DELETE",
          headers: authHeaders(),
        });
        renderEvidencePage();
      });
    });
    body.querySelectorAll(".ws-edit-ev").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const owner = window.prompt("Owner", btn.getAttribute("data-owner") || "") ?? null;
        if (owner === null) return;
        const control = window.prompt("Mapped control", btn.getAttribute("data-control") || "") ?? null;
        if (control === null) return;
        const status = window.prompt("Status (draft|review|accepted|expired|rejected)", btn.getAttribute("data-status") || "accepted");
        if (status === null) return;
        const expiry = window.prompt("Expiry (YYYY-MM-DD)", btn.getAttribute("data-expiry") || "");
        if (expiry === null) return;
        const notes = window.prompt("Comments", btn.getAttribute("data-notes") || "");
        if (notes === null) return;
        await fetch(`/api/evidence/${btn.getAttribute("data-id")}`, {
          method: "PATCH",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ owner, control_id: control, status, expiry, notes }),
        });
        renderEvidencePage();
      });
    });
    qs("evidenceAsk")?.addEventListener("click", () => {
      if (typeof runNavPrompt === "function")
        runNavPrompt("ciso", "Summarize evidence needed for our next ISO 27001 audit and list expiry risks");
    });
    body.querySelectorAll(".ws-queue-fill").forEach((btn) => {
      btn.addEventListener("click", () => {
        const cid = btn.getAttribute("data-control") || "";
        const controlInput = qs("evidenceControlId");
        if (controlInput) controlInput.value = cid;
        controlInput?.focus();
        if (typeof notifyUser === "function") {
          notifyUser(`**Collect evidence** for control \`${cid}\` — upload a file, then Link evidence.`);
        }
      });
    });
    qs("evidenceAuditPack")?.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/gap/assessments", { headers: authHeaders() });
        const data = await res.json().catch(() => ({}));
        const latest = (data.assessments || [])[0];
        if (!latest?.id) {
          alert("Run a gap analysis first, then export an audit pack.");
          return;
        }
        await downloadApiExport(
          `/api/gap/assessments/${latest.id}/audit-pack`,
          `securaiq-audit-pack-${latest.framework_id || "gap"}.zip`
        );
        if (typeof notifyUser === "function") notifyUser("**Audit pack downloaded** (ZIP).");
      } catch (err) {
        alert(err.message || "Audit pack failed");
      }
    });
    body.querySelectorAll("[data-workspace]").forEach((el) => {
      el.addEventListener("click", (e) => {
        e.preventDefault();
        showWorkspace(el.getAttribute("data-workspace"));
      });
    });
  }

  async function renderOrgsPage() {
    const body = qs("orgsPageBody");
    if (!body) return;
    const res = await fetch("/api/orgs", { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    const orgs = data.organizations || [];
    const roles = data.roles || ["admin", "analyst", "viewer", "client"];
    body.innerHTML = `
      <div class="ws-grid-2">
        <section class="cc-panel">
          <header><h2>Your organizations</h2></header>
          <ul class="cc-list" id="orgsList">${
            orgs.length
              ? orgs
                  .map(
                    (o) =>
                      `<li><button type="button" class="linkish ws-org-pick" data-id="${o.id}">
                        <strong>${escapeHtml(o.name)}</strong> <span class="hint">${escapeHtml(o.member_role || o.role || "")}</span>
                      </button></li>`
                  )
                  .join("")
              : `<li class="hint">No orgs yet — create one for multi-user tenancy</li>`
          }</ul>
          <form id="orgCreateForm" class="inline-form">
            <input id="orgName" placeholder="Organization name" required />
            <button type="submit">Create</button>
          </form>
        </section>
        <section class="cc-panel">
          <header><h2>Members</h2></header>
          <div id="orgMembersBody"><p class="hint">Select an organization</p></div>
          <form id="orgMemberForm" class="inline-form" style="margin-top:0.75rem;display:none">
            <input id="orgMemberUser" placeholder="Username" required />
            <select id="orgMemberRole">${roles.map((r) => `<option value="${r}">${r}</option>`).join("")}</select>
            <button type="submit">Add member</button>
          </form>
        </section>
      </div>
      <p class="hint" style="margin-top:1rem">Roles: admin · analyst · viewer · client. MFA (TOTP) and OIDC SSO available in Settings → Enterprise auth.</p>`;
    let selectedOrg = null;
    async function loadMembers(orgId) {
      selectedOrg = orgId;
      const membersBody = qs("orgMembersBody");
      const form = qs("orgMemberForm");
      if (form) form.style.display = "flex";
      const mres = await fetch(`/api/orgs/${orgId}/members`, { headers: authHeaders() });
      const mdata = await mres.json().catch(() => ({}));
      if (!mres.ok) {
        membersBody.innerHTML = `<p class="hint">${escapeHtml(mdata.detail || "Cannot load members")}</p>`;
        return;
      }
      const members = mdata.members || [];
      membersBody.innerHTML = `<ul class="cc-list">${
        members.length
          ? members
              .map((m) => `<li><strong>${escapeHtml(m.username || m.user_id)}</strong> — ${escapeHtml(m.role)}</li>`)
              .join("")
          : `<li class="hint">No members</li>`
      }</ul>`;
    }
    qs("orgCreateForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = qs("orgName")?.value?.trim();
      if (!name) return;
      await fetch("/api/orgs", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ name }),
      });
      renderOrgsPage();
    });
    body.querySelectorAll(".ws-org-pick").forEach((btn) => {
      btn.addEventListener("click", () => loadMembers(btn.getAttribute("data-id")));
    });
    qs("orgMemberForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!selectedOrg) return;
      const username = qs("orgMemberUser")?.value?.trim();
      if (!username) return;
      const res = await fetch(`/api/orgs/${selectedOrg}/members`, {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          username,
          role: qs("orgMemberRole")?.value || "analyst",
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(data.detail || `HTTP ${res.status}`);
        return;
      }
      qs("orgMemberUser").value = "";
      loadMembers(selectedOrg);
    });
    if (orgs.length) loadMembers(orgs[0].id);
  }

  async function renderHardeningPanel() {
    const el = qs("hkPanelBody");
    if (!el) return;
    try {
      const [stRes, listRes] = await Promise.all([
        fetch("/api/hardeningkitty/status", { headers: authHeaders() }),
        fetch("/api/hardeningkitty/lists", { headers: authHeaders() }),
      ]);
      const st = await stRes.json().catch(() => ({}));
      const listsPayload = await listRes.json().catch(() => ({}));
      const lists = listsPayload.lists || [];
      const cisLists = lists.filter((l) => l.kind === "cis").slice(0, 8);
      const chip = st.installed
        ? `<span class="auto-job-status status-done">installed</span>`
        : `<span class="auto-job-status status-planned">not installed</span>`;
      const runs = st.recent_runs || [];
      const auditRuns = runs.filter((r) => ["Audit", "Import", "Config"].includes(r.mode) && (r.status || "done") === "done");
      const auditDone = auditRuns.length > 0;
      const lastAudit = auditRuns[0] || runs[0];
      let auditChip = `<span class="auto-job-status status-planned">Not audited</span>`;
      if (auditDone) {
        auditChip = `<span class="auto-job-status status-done">Audit done</span>`;
      } else if (st.installed) {
        auditChip = `<span class="auto-job-status status-running">Ready — run audit</span>`;
      }
      const runsHtml = runs.length
        ? runs
            .map(
              (r) =>
                `<li><strong>${escapeHtml(r.mode || "")}</strong> · score ${
                  r.score != null ? escapeHtml(String(r.score)) : "—"
                } · failed ${r.failed || 0} · imported ${r.imported || 0}
                ${r.list_name ? ` · <span class="hint">${escapeHtml(String(r.list_name).replace(/^.*[\\\\\\/]/, ""))}</span>` : ""}</li>`
            )
            .join("")
        : `<li class="hint">No audits yet</li>`;
      const listHtml = cisLists.length
        ? cisLists.map((l) => `<li><code>${escapeHtml(l.name)}</code></li>`).join("")
        : lists
            .slice(0, 6)
            .map((l) => `<li><code>${escapeHtml(l.name)}</code></li>`)
            .join("") || `<li class="hint">No finding lists on disk</li>`;
      el.innerHTML = `
        <div class="hk-status">
          ${chip}
          ${auditChip}
          ${st.module_path ? `<code class="hk-path">${escapeHtml(st.module_path)}</code>` : ""}
          <span class="hint">${Number(st.finding_lists) || 0} lists · ${Number(st.cis_lists) || 0} CIS${
            lastAudit && lastAudit.score != null ? ` · last score ${escapeHtml(String(lastAudit.score))}` : ""
          }</span>
        </div>
        ${
          !st.installed
            ? `<div class="hk-setup-block">
                <p class="hint">Windows hardening checks aren't installed on this host yet.</p>
                <details class="hk-setup-advanced">
                  <summary>Advanced: install manually</summary>
                  <p class="hint">Run this in PowerShell from the SecuraIQ folder, then restart and click <strong>HardeningKitty audit</strong> above.</p>
                  <div class="hk-setup-cmd-row">
                    <code class="hk-setup-code" id="hkSetupCmd">.\\scripts\\use_hardeningkitty.cmd -Download</code>
                    <button type="button" class="btn-secondary" id="hkCopySetup">Copy</button>
                  </div>
                </details>
              </div>`
            : !auditDone
              ? `<p class="hint">Module is installed — run <strong>Audit</strong> to baseline CIS checks on this host.</p>`
              : `<p class="hint">Last audit imported ${lastAudit?.imported || 0} finding(s) · failed checks ${lastAudit?.failed || 0}.</p>`
        }
        <div class="hk-columns">
          <div>
            <p class="hint">Finding lists</p>
            <ul class="cc-list">${listHtml}</ul>
          </div>
          <div>
            <p class="hint">Recent runs</p>
            <ul class="cc-list">${runsHtml}</ul>
          </div>
        </div>
        <p class="hint hk-links">
          Official CIS Benchmarks:
          <a href="${escapeHtml(st.cis_downloads || "https://downloads.cisecurity.org/#/")}" target="_blank" rel="noopener">CIS Downloads</a>
          · Module:
          <a href="${escapeHtml(st.repo || "https://github.com/scipag/HardeningKitty")}" target="_blank" rel="noopener">HardeningKitty</a>
          · Or import an Audit report CSV under Vulnerabilities.
        </p>
        <div class="cc-action-row hk-actions">
          <label class="hint">List
            <select id="hkListSelect" class="composer-select">
              <option value="">Default list</option>
              ${lists
                .map(
                  (l) =>
                    `<option value="${escapeHtml(l.path)}">${escapeHtml(l.label || l.name)}</option>`
                )
                .join("")}
            </select>
          </label>
          <button type="button" class="btn-secondary" id="hkImportBtn">Import report CSV</button>
          <input type="file" id="hkImportFile" accept=".csv,text/csv" class="hidden" />
        </div>`;
      qs("hkCopySetup")?.addEventListener("click", async () => {
        const cmd = qs("hkSetupCmd")?.textContent || ".\\scripts\\use_hardeningkitty.cmd -Download";
        try {
          await navigator.clipboard.writeText(cmd);
          if (typeof notifyUser === "function") notifyUser("**Copied** setup command to clipboard.");
        } catch {
          if (typeof notifyUser === "function") notifyUser(`**Setup command:** \`${cmd}\``);
        }
      });
      qs("hkImportBtn")?.addEventListener("click", () => qs("hkImportFile")?.click());
      qs("hkImportFile")?.addEventListener("change", async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;
        const fd = new FormData();
        fd.append("file", file);
        try {
          const res = await fetch("/api/hardeningkitty/import", {
            method: "POST",
            headers: authHeaders(),
            body: fd,
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(data.detail || res.status);
          if (typeof notifyUser === "function") {
            notifyUser(`**HardeningKitty import:** ${data.imported || 0} findings`);
          }
          renderHardeningPanel();
          if (typeof loadCommandCenter === "function") loadCommandCenter();
        } catch (err) {
          if (typeof notifyUser === "function") notifyUser(`**Import failed:** ${err.message || err}`);
        }
        e.target.value = "";
      });
    } catch (err) {
      el.innerHTML = `<p class="hint">Couldn't load the hardening panel — try refreshing. <span class="hint-sub">(${escapeHtml(err.message)})</span></p>`;
    }
  }

  async function runHardeningKittyAudit() {
    const btn = qs("hkAuditBtn");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Queuing…";
    }
    const list = qs("hkListSelect")?.value || "";
    try {
      const res = await fetch("/api/hardeningkitty/audit", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ mode: "Audit", finding_list: list, import_findings: true }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (typeof notifyUser === "function") {
          notifyUser(
            `**HardeningKitty:** ${typeof data.detail === "string" ? data.detail : data.detail || res.status}`
          );
        }
      } else {
        const jobId = data.job && data.job.id;
        if (typeof notifyUser === "function") {
          notifyUser(`**HardeningKitty audit queued** · job \`${jobId || "?"}\``);
        }
        if (btn) btn.textContent = "Auditing…";
        if (jobId && typeof window.waitForJob === "function") {
          const job = await window.waitForJob(jobId, { timeoutMs: 600000, intervalMs: 2000 });
          const r = job?.result || {};
          if ((job?.status || "") === "done" && typeof notifyUser === "function") {
            notifyUser(
              `**HardeningKitty audit done** · score ${r.score ?? "—"} · failed ${r.failed || 0} · imported ${r.imported || 0}`
            );
          } else if ((job?.status || "") === "error" && typeof notifyUser === "function") {
            notifyUser(`**HardeningKitty failed:** ${job.error || "error"}`);
          } else if ((job?.status || "") === "timeout" && typeof notifyUser === "function") {
            notifyUser("**HardeningKitty** still running — watch Automation / live status.");
          }
        }
      }
    } catch (err) {
      if (typeof notifyUser === "function") notifyUser(`**HardeningKitty error:** ${err.message || err}`);
    }
    renderHardeningPanel();
    renderHkVulnPanel();
    if (typeof loadCommandCenter === "function") loadCommandCenter();
    if (typeof renderVulnsPage === "function" && window.__securaiqWorkspaceView === "vulns") {
      renderVulnSummaryBar();
    }
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Run HardeningKitty audit";
    }
  }
  window.runHardeningKittyAudit = runHardeningKittyAudit;

  async function renderFrameworksPage() {
    const body = qs("frameworksPageBody");
    if (!body) return;
    const [fwRes, dashRes, remRes, evRes] = await Promise.all([
      fetch("/api/frameworks", { headers: authHeaders() }),
      fetch("/api/dashboard", { headers: authHeaders() }),
      fetch("/api/gap/remediations", { headers: authHeaders() }),
      fetch("/api/evidence", { headers: authHeaders() }),
    ]);
    const fwData = await fwRes.json().catch(() => ({}));
    const dash = await dashRes.json().catch(() => ({}));
    const remData = await remRes.json().catch(() => ({}));
    const evData = await evRes.json().catch(() => ({}));
    const apiErrors = [];
    if (!fwRes.ok) apiErrors.push(`frameworks ${fwRes.status}`);
    if (!dashRes.ok) apiErrors.push(`dashboard ${dashRes.status}`);
    if (!remRes.ok) apiErrors.push(`remediations ${remRes.status}`);
    if (!evRes.ok) apiErrors.push(`evidence ${evRes.status}`);
    if (apiErrors.length && typeof notifyUser === "function") {
      notifyUser(`**Frameworks page:** ${apiErrors.join(" · ")}`);
    }
    const fws = fwData.frameworks || [];
    const rems = remData.remediations || [];
    const evidence = evData.evidence || [];
    const scored = {};
    (dash.frameworks || []).forEach((f) => {
      scored[f.framework_id] = f;
    });
    const statsById = {};
    (dash.framework_control_stats || []).forEach((s) => {
      statsById[s.framework_id] = s;
    });
    let totImpl = 0;
    let totPartial = 0;
    let totMissing = 0;
    let pctSum = 0;
    let pctN = 0;
    Object.values(statsById).forEach((st) => {
      const c = st.counts || {};
      totImpl += c.implemented || 0;
      totPartial += c.partial || 0;
      totMissing += c.missing || 0;
    });
    (dash.frameworks || []).forEach((f) => {
      if (f.compliance_percent != null) {
        pctSum += Number(f.compliance_percent) || 0;
        pctN += 1;
      }
    });
    const avgPct = pctN ? Math.round(pctSum / pctN) : Math.round(Number(dash.compliance_score) || 0);
    const openRems = rems.filter((r) => (r.status || "") !== "done").length;
    const riskScore = dash.security_index != null ? Math.round(Number(dash.security_index)) : "—";
    const maturity =
      avgPct >= 80 ? "Managed" : avgPct >= 50 ? "Defined" : avgPct > 0 ? "Initial" : "Ad hoc";
    const remByControl = {};
    rems.forEach((r) => {
      const cid = (r.control_id || "").toUpperCase();
      if (cid && !remByControl[cid]) remByControl[cid] = r;
    });
    const evByControl = {};
    evidence.forEach((e) => {
      const cid = (e.control_id || "").toUpperCase();
      if (!cid) return;
      if (!evByControl[cid]) evByControl[cid] = [];
      evByControl[cid].push(e);
    });

    async function openControlCenter(frameworkId, assessmentId) {
      const detailEl = qs("fwControlDetail");
      if (!detailEl) return;
      detailEl.innerHTML = `<p class="hint">Loading controls…</p>`;
      let aid = assessmentId;
      if (!aid) {
        const listRes = await fetch("/api/gap/assessments", { headers: authHeaders() });
        const list = (await listRes.json().catch(() => ({}))).assessments || [];
        const match = list.find((a) => a.framework_id === frameworkId);
        aid = match?.id;
      }
      if (!aid) {
        const catRes = await fetch(`/api/frameworks/${encodeURIComponent(frameworkId)}`, { headers: authHeaders() });
        const catalog = catRes.ok ? await catRes.json().catch(() => ({})) : {};
        const controls = catalog.controls || [];
        detailEl.innerHTML = `<p class="hint">No assessment for this framework yet — run gap analysis to score controls.</p>
          <button type="button" class="cc-action fw-run-gap" data-id="${escapeHtml(frameworkId)}">Run gap</button>
          ${
            controls.length
              ? `<div class="data-table-wrap" style="margin-top:1rem"><table class="data-table"><thead><tr><th>Control</th><th>Domain</th><th>Title</th></tr></thead><tbody>${controls
                  .map(
                    (c) =>
                      `<tr><td>${escapeHtml(c.id || c.control_id || "")}</td><td>${escapeHtml(c.domain || "")}</td><td>${escapeHtml(c.title || c.name || "")}</td></tr>`
                  )
                  .join("")}</tbody></table></div>`
              : ""
          }`;
        detailEl.querySelector(".fw-run-gap")?.addEventListener("click", () => {
          if (typeof openGap === "function") openGap(frameworkId);
        });
        return;
      }
      const res = await fetch(`/api/gap/assessments/${aid}`, { headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        detailEl.innerHTML = `<p class="hint">Could not load assessment (${res.status})</p>`;
        return;
      }
      let covLabel = "";
      try {
        const covRes = await fetch(`/api/gap/assessments/${aid}/coverage`, { headers: authHeaders() });
        const coverage = covRes.ok ? await covRes.json().catch(() => ({})) : {};
        if (coverage.coverage_percent != null) {
          covLabel = ` · evidence coverage ${Number(coverage.coverage_percent)}%`;
        }
      } catch {
        /* optional */
      }
      const rows = data.results || data.top_gaps || [];
      const counts = data.counts || {};
      detailEl.innerHTML = `
        <header class="fw-detail-head">
          <div>
            <h2>${escapeHtml(data.framework_name || frameworkId)}</h2>
            <p class="hint">${data.control_count || rows.length} controls · ${Number(
              data.compliance_percent || 0
            )}% · ${counts.implemented || 0} implemented · ${counts.partial || 0} partial · ${
              counts.missing || 0
            } missing${covLabel}</p>
          </div>
          <div class="cc-action-row">
            <button type="button" class="btn-secondary" id="fwExportAssessment">Export assessment</button>
            <button type="button" class="btn-secondary" id="fwExportAuditPack">Export audit pack</button>
            <button type="button" class="btn-secondary" id="fwDeleteAssessment" data-id="${escapeHtml(aid)}">Delete assessment</button>
            <button type="button" class="btn-secondary" id="fwDetailClose">Close</button>
          </div>
        </header>
        <div class="data-table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Control</th>
                <th>Evidence</th>
                <th>Owner</th>
                <th>Risk</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              ${
                rows.length
                  ? rows
                      .map((r) => {
                        const cid = r.control_id || "";
                        const rem = remByControl[(cid || "").toUpperCase()];
                        const evs = evByControl[(cid || "").toUpperCase()] || [];
                        const status = r.status || "missing";
                        const risk =
                          status === "missing" ? "high" : status === "partial" ? "medium" : "low";
                        return `<tr>
                          <td><strong>${escapeHtml(cid)}</strong>
                            <div class="hint">${escapeHtml(r.title || "")}</div></td>
                          <td>${
                            evs.length
                              ? escapeHtml(evs.map((e) => e.filename || e.file_id).join(", "))
                              : `<span class="hint">${escapeHtml(
                                  (r.matched_keywords || []).slice(0, 3).join(", ") || "None linked"
                                )}</span>`
                          }</td>
                          <td>${escapeHtml(rem?.owner || "Unassigned")}</td>
                          <td><span class="wq-badge pri-${risk}">${risk}</span></td>
                          <td><span class="wq-badge pri-${
                            status === "implemented" ? "low" : status === "partial" ? "medium" : "high"
                          }">${escapeHtml(status)}</span></td>
                          <td>
                            <button type="button" class="btn-secondary fw-ctrl-ask"
                              data-id="${escapeHtml(cid)}" data-title="${escapeHtml(r.title || "")}">Ask AI</button>
                            <button type="button" class="btn-secondary" data-workspace="evidence">Evidence</button>
                          </td>
                        </tr>`;
                      })
                      .join("")
                  : `<tr><td colspan="6" class="hint">No control results</td></tr>`
              }
            </tbody>
          </table>
        </div>`;
      qs("fwDetailClose")?.addEventListener("click", () => {
        detailEl.innerHTML = `<p class="hint">Select a framework to review controls.</p>`;
      });
      qs("fwExportAssessment")?.addEventListener("click", async () => {
        try {
          await downloadApiExport(`/api/gap/assessments/${aid}/export`, `securaiq-gap-${frameworkId}.md`);
          if (typeof notifyUser === "function") notifyUser("**Gap assessment exported** as Markdown.");
        } catch (err) {
          alert(err.message || "Export failed");
        }
      });
      qs("fwExportAuditPack")?.addEventListener("click", async () => {
        try {
          await downloadApiExport(
            `/api/gap/assessments/${aid}/audit-pack`,
            `securaiq-audit-pack-${frameworkId}.zip`
          );
          if (typeof notifyUser === "function") {
            notifyUser("**Audit pack ZIP exported** — matrix, evidence index, and accepted artifacts.");
          }
        } catch (err) {
          alert(err.message || "Audit pack failed");
        }
      });
      qs("fwDeleteAssessment")?.addEventListener("click", async () => {
        if (!confirm("Delete this assessment and all its remediation tasks? This cannot be undone.")) return;
        try {
          const res = await fetch(`/api/gap/assessments/${aid}`, { method: "DELETE", headers: authHeaders() });
          if (!res.ok) {
            const d = await res.json().catch(() => ({}));
            throw new Error(d.detail || `HTTP ${res.status}`);
          }
          if (typeof notifyUser === "function") notifyUser("**Assessment deleted.**");
          detailEl.innerHTML = `<p class="hint">Select a framework to review controls.</p>`;
          if (typeof renderFrameworksPage === "function") renderFrameworksPage();
          if (typeof loadCommandCenter === "function") loadCommandCenter();
        } catch (err) {
          if (typeof notifyUser === "function") notifyUser(`**Delete failed:** ${err.message || err}`);
          else alert(err.message || "Delete failed");
        }
      });
      detailEl.querySelectorAll(".fw-ctrl-ask").forEach((btn) => {
        btn.addEventListener("click", () => {
          if (typeof runNavPrompt === "function") {
            runNavPrompt(
              "ciso",
              `For control ${btn.getAttribute("data-id")} (${btn.getAttribute(
                "data-title"
              )}): list required evidence, owner role, residual risk, and a 14-day remediation plan.`
            );
          }
        });
      });
      detailEl.querySelectorAll("[data-workspace]").forEach((el) => {
        el.addEventListener("click", (e) => {
          e.preventDefault();
          showWorkspace(el.getAttribute("data-workspace"));
        });
      });
    }

    const setTxt = (id, val) => {
      const el = qs(id);
      if (el) el.textContent = String(val);
    };
    setTxt("fwHeroPct", `${avgPct}%`);
    setTxt("fwHeroMaturity", maturity);
    setTxt("fwStatImpl", totImpl);
    setTxt("fwStatPartial", totPartial);
    setTxt("fwStatMissing", totMissing);
    setTxt("fwStatRems", openRems);

    body.innerHTML = `
      ${
        apiErrors.length
          ? `<p class="hint" style="color:var(--danger,#b91c1c)">API issues: ${escapeHtml(apiErrors.join(" · "))}</p>`
          : ""
      }
      <div class="fw-grid">
        ${
          fws.length
            ? fws
                .map((f) => {
                  const s = scored[f.id];
                  const st = statsById[f.id] || {};
                  const c = st.counts || {};
                  const pct = s ? Number(s.compliance_percent || 0) : null;
                  const total =
                    st.controls_total ||
                    f.control_count ||
                    (c.implemented || 0) + (c.partial || 0) + (c.missing || 0);
                  return `<article class="fw-card ${pct != null ? "fw-card-scored" : ""}">
                    <header>
                      <h2>${escapeHtml(f.name)}</h2>
                      <span class="fw-card-pct">${pct != null ? `${pct}%` : "—"}</span>
                    </header>
                    <p class="hint">${escapeHtml(f.version || f.id || "")}</p>
                    <p class="fw-meta"><strong>${total || 0}</strong> controls ·
                      <strong>${c.implemented || 0}</strong> ok ·
                      <strong>${c.partial || 0}</strong> partial ·
                      <strong>${c.missing || 0}</strong> missing</p>
                    <div class="cc-bar"><i style="width:${pct != null ? pct : 0}%"></i></div>
                    <p class="fw-score">${pct != null ? "Live assessment score" : "Not assessed — run gap analysis"}</p>
                    <div class="cc-action-row">
                      <button type="button" class="btn-primary-cc fw-open-controls" data-id="${escapeHtml(
                        f.id
                      )}" data-aid="${escapeHtml(st.assessment_id || s?.id || "")}">Open controls</button>
                      <button type="button" class="btn-secondary fw-run-gap" data-id="${escapeHtml(f.id)}">Gap analysis</button>
                    </div>
                  </article>`;
                })
                .join("")
            : `<p class="hint">No frameworks loaded.</p>`
        }
      </div>`;
    body.querySelectorAll(".fw-open-controls").forEach((btn) => {
      btn.addEventListener("click", () =>
        openControlCenter(btn.getAttribute("data-id"), btn.getAttribute("data-aid") || "")
      );
    });
    body.querySelectorAll(".fw-run-gap").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (typeof openGap === "function") openGap(btn.getAttribute("data-id"));
      });
    });
  }
  window.renderFrameworksPage = renderFrameworksPage;

  function renderIntegrationsPage() {
    const body = qs("integrationsPageBody");
    if (!body) return;
    try {
      localStorage.setItem("securaiq.checklist.integrations", "1");
    } catch {
      /* ignore */
    }
    body.innerHTML = `
      <p class="hint">Orchestrate mature tools — Connect opens the real path in SecuraIQ (import, settings, webhooks). Planned items stay disabled until shipped.</p>
      <div class="integ-status-strip" id="integStatusStrip"><span class="hint">Checking connection status…</span></div>
      <section class="cc-panel" id="integMvpPanel">
        <header><h2>Recommended MVP</h2></header>
        <div id="integMvp" class="integ-grid"><p class="hint">Loading…</p></div>
      </section>
      <section class="cc-panel" style="margin-top:1rem">
        <header><h2>All integrations</h2></header>
        <p class="hint" id="integCounts"></p>
        <div id="integCatalog" class="integ-catalog integ-catalog-all"><p class="hint">Loading…</p></div>
      </section>
      <section class="cc-panel" style="margin-top:1rem">
        <header><h2>AI agents</h2></header>
        <p class="hint">Launch a role prompt in AI Workspace (authorized / lab scope).</p>
        <div id="integAgents" class="integ-chips"></div>
      </section>
      <section class="cc-panel" style="margin-top:1rem">
        <header><h2>Enterprise features</h2></header>
        <div id="integEnterprise" class="integ-grid"></div>
      </section>
      <div class="integ-grid" id="integQuick" style="margin-top:1rem"></div>
      <section class="cc-panel" style="margin-top:1.25rem" id="resetPanel">
        <header><h2>Reset workspace</h2></header>
        <p class="hint">Clear assets, vulns, risks, incidents, and related data for this user. Starts Mission Control from zero. Does not delete your login.</p>
        <label class="toggle"><input type="checkbox" id="resetClearRag" /> Also clear RAG knowledge index on reset</label>
        <div class="cc-action-row" style="margin-top:0.75rem">
          <button type="button" class="btn-secondary" id="workspaceResetBtn">Reset to empty</button>
        </div>
      </section>
      <section class="cc-panel" style="margin-top:1.25rem" id="webhookPanel">
        <header><h2>Outbound webhooks</h2></header>
        <p class="hint">Bridge to n8n / Temporal / Slack. Events: vuln.imported, remediation.created, *</p>
        <form id="webhookForm" class="inline-form" style="flex-wrap:wrap;gap:0.5rem">
          <input id="webhookName" placeholder="Name" required />
          <input id="webhookUrl" placeholder="https://…" required style="min-width:240px" />
          <button type="submit">Add webhook</button>
        </form>
        <ul id="webhookList" class="cc-list" style="margin-top:0.75rem"><li class="hint">No webhooks yet</li></ul>
        <button type="button" class="btn-secondary" id="webhookTest">Dispatch test event</button>
      </section>`;

    const statusClass = (s) => {
      const live = ["shipped", "import", "path", "path+import", "partial", "Available"].includes(s);
      return live ? "low" : "medium";
    };

    const actionBtn = (ua, idAttr) => {
      const a = ua || { kind: "planned", label: "Planned" };
      if (a.kind === "planned") {
        return `<button type="button" class="btn-secondary integ-connect" disabled title="Not shipped yet">${escapeHtml(
          a.label || "Planned"
        )}</button>`;
      }
      const attrs = [
        `data-kind="${escapeHtml(a.kind)}"`,
        a.target ? `data-target="${escapeHtml(a.target)}"` : "",
        a.focus ? `data-focus="${escapeHtml(a.focus)}"` : "",
        idAttr ? `data-id="${escapeHtml(idAttr)}"` : "",
      ]
        .filter(Boolean)
        .join(" ");
      return `<button type="button" class="cc-action integ-connect" ${attrs}>${escapeHtml(
        a.label || "Connect"
      )}</button>`;
    };

    function runConnect(btn) {
      const kind = btn.getAttribute("data-kind");
      const target = btn.getAttribute("data-target");
      const focus = btn.getAttribute("data-focus");
      if (kind === "workspace" && target) {
        showWorkspace(target);
        return;
      }
      if (kind === "tools") {
        if (typeof showView === "function") showView("chat");
        else if (typeof showWorkspace === "function") showWorkspace("chat");
        if (typeof window.openToolsPalette === "function") window.openToolsPalette(true);
        else if (typeof openToolsPalette === "function") openToolsPalette(true);
        return;
      }
      if (kind === "webhooks") {
        qs("webhookPanel")?.scrollIntoView({ behavior: "smooth" });
        qs("webhookUrl")?.focus();
        return;
      }
      if (kind === "settings") {
        qs("settingsBtn")?.click();
        const focusMap = {
          jira: "setJiraUrl",
          ai: "setOllamaUrl",
          tools: "setLocalToolsEnabled",
          keys: "apiKeyName",
          audit: "auditLogList",
          wazuh: "setWazuhUrl",
          openaudit: "setOaUrl",
          inventory: "setOaUrl",
          hardening: "setHkPath",
          hardeningkitty: "setHkPath",
          sonarqube: "setSonarUrl",
          sonar: "setSonarUrl",
          cis_downloads: "setHkPath",
          thehive: "setThUrl",
          cloud: "setAwsRegion",
          servicenow: "setSnUrl",
          comms: "setSlackWebhook",
          slack: "setSlackWebhook",
          teams: "setTeamsWebhook",
          smtp: "setSmtpHost",
          xdr: "setSophosClientId",
          sophos: "setSophosClientId",
          oidc: "setOidcIssuer",
          sso: "setOidcIssuer",
          github: "setGithubWebhookSecret",
          gitlab: "setGitlabWebhookSecret",
          taxii: "setTaxiiApiRoot",
          stix: "setTaxiiApiRoot",
          redis: "setRedisUrl",
          redis_realtime: "setRedisUrl",
          scim: "setScimEnabled",
          mfa: "setMfaRequiredAdmin",
          prefect: "setPrefectEnabled",
        };
        const panelMap = {
          cloud: "settingsCloud",
          thehive: "settingsTheHive",
          wazuh: "settingsWazuh",
          inventory: "settingsInventory",
          openaudit: "settingsInventory",
          hardening: "settingsHardening",
          hardeningkitty: "settingsHardening",
          sonarqube: "settingsSonar",
          sonar: "settingsSonar",
          cis_downloads: "settingsHardening",
          servicenow: "settingsServiceNow",
          comms: "settingsComms",
          slack: "settingsComms",
          teams: "settingsComms",
          smtp: "settingsComms",
          xdr: "settingsXdr",
          sophos: "settingsXdr",
          oidc: "settingsEnterprise",
          sso: "settingsEnterprise",
          scim: "settingsEnterprise",
          github: "settingsEnterprise",
          gitlab: "settingsEnterprise",
          taxii: "settingsEnterprise",
          stix: "settingsEnterprise",
          mfa: "settingsEnterprise",
          prefect: "settingsPrefect",
        };
        const targetId = focusMap[focus] || (focus ? `set${focus[0].toUpperCase()}${focus.slice(1)}` : null);
        if (targetId) {
          setTimeout(() => {
            const fieldEl = document.getElementById(targetId);
            const panel = focus ? document.getElementById(panelMap[focus] || "") : null;
            (panel || fieldEl)?.scrollIntoView?.({ behavior: "smooth", block: "center" });
            if (fieldEl && typeof fieldEl.focus === "function" && fieldEl.tagName !== "DIV") fieldEl.focus();
          }, 220);
        }
        return;
      }
      if (kind === "info" && typeof notifyUser === "function") {
        notifyUser(`**${btn.closest(".integ-card")?.querySelector("h2")?.textContent || "Integration"}** is available in this build — no extra connector required.`);
      }
    }

    function wireConnectButtons(root) {
      root?.querySelectorAll(".integ-connect:not([disabled])").forEach((btn) => {
        btn.addEventListener("click", () => runConnect(btn));
      });
    }

    async function loadStatusStrip() {
      const strip = qs("integStatusStrip");
      if (!strip) return;
      try {
        const [setRes, hookRes, ghRes, wzRes, thRes, cloudRes] = await Promise.all([
          fetch("/api/settings", { headers: authHeaders() }),
          fetch("/api/webhooks", { headers: authHeaders() }),
          fetch("/api/integrations/github/status", { headers: authHeaders() }),
          fetch("/api/siem/status", { headers: authHeaders() }),
          fetch("/api/thehive/status", { headers: authHeaders() }),
          fetch("/api/cloud/status", { headers: authHeaders() }),
        ]);
        const settings = await setRes.json().catch(() => ({}));
        const hooks = await hookRes.json().catch(() => ({}));
        const gh = await ghRes.json().catch(() => ({}));
        const wz = await wzRes.json().catch(() => ({}));
        const th = await thRes.json().catch(() => ({}));
        const cloud = await cloudRes.json().catch(() => ({}));
        const jiraOk = Boolean(settings.jira_base_url && settings.jira_api_token_set);
        const hookCount = (hooks.webhooks || []).length;
        const ghOk = Boolean(gh.configured);
        const backend = settings.model_backend || settings.MODEL_BACKEND || "local";
        const wzOk = Boolean(wz.configured);
        const thOk = Boolean(th.configured);
        const cloudOk = (cloud.configured_count || 0) > 0;
        strip.innerHTML = `
          <span class="integ-pill ${jiraOk ? "ok" : ""}">Jira: ${jiraOk ? "configured" : "not set"}</span>
          <span class="integ-pill ${settings.openaudit_base_url && settings.openaudit_password_set ? "ok" : ""}">Inventory: ${
            settings.openaudit_base_url && settings.openaudit_password_set ? "configured" : "not set"
          }</span>
          <span class="integ-pill ${ghOk ? "ok" : ""}">GitHub: ${ghOk ? "webhook ready" : "not set"}</span>
          <span class="integ-pill ${hookCount ? "ok" : ""}">Webhooks: ${hookCount}</span>
          <span class="integ-pill ${wzOk ? "ok" : ""}">SecuraIQ SIEM: ${wzOk ? "configured" : "not set"}</span>
          <span class="integ-pill ${thOk ? "ok" : ""}">TheHive: ${thOk ? "configured" : "not set"}</span>
          <span class="integ-pill ${cloudOk ? "ok" : ""}">Cloud: ${cloudOk ? `${cloud.configured_count} vendor(s)` : "not set"}</span>
          <span class="integ-pill ok">AI backend: ${escapeHtml(String(backend))}</span>
          <span class="integ-pill">Scanners: import via Vulns</span>`;
      } catch {
        strip.innerHTML = `<span class="hint">Status unavailable</span>`;
      }
    }

    async function loadCatalog() {
      try {
        const res = await fetch("/api/integrations/catalog", { headers: authHeaders() });
        const data = await res.json();
        const mvp = qs("integMvp");
        if (mvp) {
          mvp.innerHTML = (data.mvp || [])
            .map(
              (i) => `<article class="integ-card">
              <h2>${escapeHtml(i.tool)}</h2>
              <p class="hint">${escapeHtml(i.category)}</p>
              <span class="wq-badge pri-${statusClass(i.status)}">${escapeHtml(i.status)}</span>
              <div class="cc-action-row integ-card-actions">${actionBtn(i.ui_action)}</div>
            </article>`
            )
            .join("");
          wireConnectButtons(mvp);
        }
        const counts = qs("integCounts");
        if (counts && data.counts) {
          counts.textContent = `${data.counts.total} tools · ${data.counts.actionable} actionable · ${data.counts.planned} planned`;
        }
        const cat = qs("integCatalog");
        if (cat) {
          cat.innerHTML = (data.groups || [])
            .map((g) => {
              const cards = (g.items || [])
                .map(
                  (it) => `<article class="integ-card integ-card-sm">
                    <h2>${escapeHtml(it.name)}</h2>
                    <p class="hint">${escapeHtml(it.hint || g.label)}</p>
                    <span class="wq-badge pri-${statusClass(it.status)}">${escapeHtml(it.status)}</span>
                    <div class="cc-action-row integ-card-actions">${actionBtn(it.ui_action, it.id)}</div>
                  </article>`
                )
                .join("");
              return `<div class="integ-group"><h3>${escapeHtml(g.label)} (${(g.items || []).length})</h3><div class="integ-grid">${cards}</div></div>`;
            })
            .join("");
          wireConnectButtons(cat);
        }
        const agents = qs("integAgents");
        if (agents) {
          const list = data.agents || [];
          agents.innerHTML = list
            .map((a) => {
              if (typeof a === "string") {
                return `<button type="button" class="integ-chip integ-agent" data-mode="ciso" data-prompt="${escapeHtml(
                  `Act as ${a}: help with authorized security work in our workspace`
                )}"><strong>${escapeHtml(a)}</strong></button>`;
              }
              return `<button type="button" class="integ-chip integ-agent" data-mode="${escapeHtml(
                a.mode || "ciso"
              )}" data-prompt="${escapeHtml(a.prompt || a.name)}"><strong>${escapeHtml(
                a.name
              )}</strong></button>`;
            })
            .join("");
          agents.querySelectorAll(".integ-agent").forEach((btn) => {
            btn.addEventListener("click", () => {
              if (typeof runNavPrompt === "function") {
                runNavPrompt(btn.getAttribute("data-mode"), btn.getAttribute("data-prompt"));
              }
            });
          });
        }
        const ent = qs("integEnterprise");
        if (ent) {
          ent.innerHTML = (data.enterprise_features || [])
            .map(
              (f) => `<article class="integ-card integ-card-sm">
              <h2>${escapeHtml(f.name)}</h2>
              <span class="wq-badge pri-${statusClass(f.status)}">${escapeHtml(f.status)}</span>
              <div class="cc-action-row integ-card-actions">${actionBtn(f.ui_action, f.id)}</div>
            </article>`
            )
            .join("");
          wireConnectButtons(ent);
        }
        const quick = qs("integQuick");
        if (quick) {
          quick.innerHTML = `
            <article class="integ-card">
              <h2>Jira</h2>
              <p class="hint">Create issues from remediations</p>
              <span class="wq-badge pri-low">shipped</span>
              <div class="cc-action-row" style="margin-top:0.75rem">
                <button type="button" class="cc-action integ-connect" data-kind="settings" data-focus="jira">Configure</button>
              </div>
            </article>
            <article class="integ-card">
              <h2>Scanner import</h2>
              <p class="hint">Trivy, Semgrep, Grype, ZAP, Bandit, Checkov, Gitleaks, SecuraIQ Code</p>
              <span class="wq-badge pri-low">import</span>
              <div class="cc-action-row" style="margin-top:0.75rem">
                <button type="button" class="cc-action integ-connect" data-kind="workspace" data-target="vulns">Open vulns</button>
              </div>
            </article>
            <article class="integ-card">
              <h2>Webhooks / n8n</h2>
              <p class="hint">Starts empty — add a webhook below</p>
              <span class="wq-badge pri-low">shipped</span>
              <div class="cc-action-row" style="margin-top:0.75rem">
                <button type="button" class="cc-action integ-connect" data-kind="webhooks">Manage</button>
              </div>
            </article>
            <article class="integ-card">
              <h2>Threat intel</h2>
              <p class="hint">Watchlist + CISA KEV sync</p>
              <span class="wq-badge pri-low">shipped</span>
              <div class="cc-action-row" style="margin-top:0.75rem">
                <button type="button" class="cc-action integ-connect" data-kind="workspace" data-target="intel">Open intel</button>
              </div>
            </article>
            <article class="integ-card">
              <h2>Frameworks</h2>
              <p class="hint">ISO / NIST / CIS / SOC2 / PCI / HIPAA / GDPR / ASVS</p>
              <span class="wq-badge pri-low">shipped</span>
              <div class="cc-action-row" style="margin-top:0.75rem">
                <button type="button" class="cc-action integ-connect" data-kind="workspace" data-target="frameworks">Open frameworks</button>
              </div>
            </article>
            <article class="integ-card">
              <h2>AI Router</h2>
              <p class="hint">Ollama, OpenRouter, Groq, OpenAI…</p>
              <span class="wq-badge pri-low">shipped</span>
              <div class="cc-action-row" style="margin-top:0.75rem">
                <button type="button" class="cc-action integ-connect" data-kind="settings" data-focus="ai">AI settings</button>
              </div>
            </article>`;
          wireConnectButtons(quick);
        }
      } catch (err) {
        const msg = `<p class="hint">Couldn't load the catalog — try refreshing. <span class="hint-sub">(${escapeHtml(err.message || String(err))})</span></p>`;
        // Real bug found in audit: only integMvp was updated on failure, so
        // integCatalog/integAgents/integEnterprise stayed stuck on "Loading…"
        // forever with no indication anything went wrong.
        ["integMvp", "integCatalog", "integAgents", "integEnterprise"].forEach((id) => {
          const el = qs(id);
          if (el) el.innerHTML = msg;
        });
      }
    }
    loadCatalog();
    loadStatusStrip();
    loadVulnSampleButtons();

    qs("workspaceResetBtn")?.addEventListener("click", async () => {
      if (!confirm("Reset this workspace to empty? This cannot be undone.")) return;
      try {
        const reqRes = await fetch("/api/workspace/reset/request-code", {
          method: "POST",
          headers: authHeaders({ "Content-Type": "application/json" }),
        });
        const reqData = await reqRes.json().catch(() => ({}));
        if (!reqRes.ok) {
          if (typeof notifyUser === "function")
            notifyUser(`**Reset failed:** ${reqData.detail || reqRes.status}`);
          return;
        }
        // Local open mode returns confirm_code so reset is one dialog; auth mode uses Notifications.
        let code = (reqData.confirm_code || "").trim();
        if (!code) {
          code = (
            prompt(
              "A confirmation code was sent to Notifications (bell). Enter it to confirm the reset:"
            ) || ""
          ).trim();
        }
        if (!code) return;

        const res = await fetch("/api/workspace/reset", {
          method: "POST",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({
            confirm: true,
            confirm_code: code,
            clear_rag: Boolean(qs("resetClearRag")?.checked),
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          if (typeof notifyUser === "function") notifyUser(`**Reset failed:** ${data.detail || res.status}`);
          return;
        }
        try {
          localStorage.removeItem("securaiq.kpi.snap");
          localStorage.removeItem("securaiq.chats.v1");
          localStorage.removeItem("securaiq.checklist.integrations");
        } catch {
          /* ignore */
        }
        if (typeof notifyUser === "function") {
          notifyUser("**Workspace reset** — every dashboard starts from zero.");
        }
        location.reload();
      } catch (err) {
        if (typeof notifyUser === "function") notifyUser(`**Reset failed:** ${err.message || err}`);
      }
    });

    async function loadHooks() {
      const res = await fetch("/api/webhooks", { headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      const list = qs("webhookList");
      const hooks = data.webhooks || [];
      if (!list) return;
      list.innerHTML = hooks.length
        ? hooks
            .map(
              (h) =>
                `<li><strong>${escapeHtml(h.name)}</strong> <span class="hint">${escapeHtml(h.url)}</span>
                <button type="button" class="btn-secondary ws-del-hook" data-id="${escapeHtml(h.id)}">Remove</button></li>`
            )
            .join("")
        : `<li class="hint">No webhooks yet</li>`;
      list.querySelectorAll(".ws-del-hook").forEach((btn) => {
        btn.addEventListener("click", async () => {
          await fetch(`/api/webhooks/${btn.getAttribute("data-id")}`, { method: "DELETE", headers: authHeaders() });
          loadHooks();
          loadStatusStrip();
        });
      });
      loadStatusStrip();
    }
    qs("webhookForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      await fetch("/api/webhooks", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          name: qs("webhookName")?.value?.trim(),
          url: qs("webhookUrl")?.value?.trim(),
          events: ["*"],
        }),
      });
      qs("webhookName").value = "";
      qs("webhookUrl").value = "";
      loadHooks();
    });
    qs("webhookTest")?.addEventListener("click", async () => {
      const res = await fetch("/api/webhooks/dispatch", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ event: "test", payload: { message: "SecuraIQ webhook test" } }),
      });
      const data = await res.json().catch(() => ({}));
      if (typeof notifyUser === "function") notifyUser(`**Webhooks:** sent ${data.sent ?? 0}`);
    });
    loadHooks();
  }

  async function renderGraphPage() {
    const body = qs("graphPageBody");
    if (!body) return;
    body.innerHTML = `<p class="hint">Loading correlation graph…</p>`;
    const focusQ = (window.__securaiqGraphFocus || "").trim();
    window.__securaiqGraphFocus = "";
    let data = {};
    let linksData = {};
    try {
      const [gRes, lRes] = await Promise.all([
        focusQ
          ? fetch(`/api/graph/correlate?q=${encodeURIComponent(focusQ)}`, { headers: authHeaders() })
          : fetch("/api/graph", { headers: authHeaders() }),
        fetch("/api/graph/links", { headers: authHeaders() }),
      ]);
      data = await gRes.json().catch(() => ({}));
      linksData = await lRes.json().catch(() => ({}));
      if (!gRes.ok) {
        body.innerHTML = `<p class="hint">${escapeHtml(data.detail || "Graph unavailable")}</p>`;
        return;
      }
    } catch (err) {
      body.innerHTML = `<p class="hint">Could not load correlation graph: ${escapeHtml(err.message || String(err))}</p>`;
      return;
    }
    const counts = data.counts || {};
    const byType = counts.by_type || {};
    const nodes = data.nodes || [];
    const edges = data.edges || [];
    const links = linksData.links || [];
    const hotspots = data.hotspots || [];
    const doctrine =
      data.doctrine ||
      "Correlation joins VAPT, XDR, incidents, and GRC on shared assets — one picture, not five tabs.";
    body.innerHTML = `
      <p class="hint">${escapeHtml(doctrine)}</p>
      ${
        focusQ
          ? `<p class="hint">Focused on <strong>${escapeHtml(focusQ)}</strong> · <button type="button" class="btn-secondary" id="graphClearFocus">Show full graph</button></p>`
          : ""
      }
      <div class="asset-breakdown-grid" style="margin-bottom:1rem">
        ${Object.entries(byType)
          .map(([k, v]) => `<div class="ab-tile"><span>${escapeHtml(k)}</span><strong>${v}</strong></div>`)
          .join("")}
      </div>
      <p class="hint">${counts.nodes || nodes.length || 0} nodes · ${counts.edges || edges.length || 0} edges · ${
        links.length
      } manual links</p>
      <section class="cc-panel" style="margin-bottom:1rem">
        <header style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">
          <h2 style="margin:0">Hotspots (multi-discipline)</h2>
          <button type="button" class="btn-secondary" id="graphRebuild">Rebuild auto-links</button>
        </header>
        <ul class="cc-list" id="graphHotspots">${
          hotspots.length
            ? hotspots
                .map(
                  (h) =>
                    `<li class="cc-clickable" data-corr-focus="${escapeHtml(h.label || "")}"><strong>${escapeHtml(
                      h.label || ""
                    )}</strong> <span class="hint">${escapeHtml(h.why || "")}</span></li>`
                )
                .join("")
            : `<li class="hint">No hotspots yet — need findings on the same asset name across scanners, XDR, and incidents.</li>`
        }</ul>
      </section>
      <div class="graph-path" aria-label="Attack surface path">
        <span>Repo</span><i></i><span>Container</span><i></i><span>Image</span><i></i><span>Cloud</span><i></i><span>Server</span><i></i><span>Vuln</span><i></i><span>Incident</span><i></i><span>Compliance</span>
      </div>
      <div class="ws-grid-2">
        <section class="cc-panel">
          <header><h2>Nodes</h2></header>
          <ul class="cc-list">${nodes
            .slice(0, 60)
            .map(
              (n) =>
                `<li><strong>${escapeHtml(n.type)}</strong> ${escapeHtml(n.label)}
                <span class="hint">${escapeHtml(JSON.stringify(n.meta || {}).slice(0, 60))}</span></li>`
            )
            .join("")}</ul>
        </section>
        <section class="cc-panel">
          <header><h2>Relationships</h2></header>
          <ul class="cc-list">${edges
            .slice(0, 40)
            .map(
              (e) =>
                `<li><code>${escapeHtml(e.from)}</code> —${escapeHtml(e.relation)}→ <code>${escapeHtml(
                  e.to
                )}</code></li>`
            )
            .join("")}</ul>
          <button type="button" class="cc-action" id="graphAskAi" style="margin-top:0.75rem">Ask AI to explain top attack paths</button>
        </section>
      </div>
      <section class="cc-panel" style="margin-top:1rem">
        <header><h2>Add entity link</h2></header>
        <form id="graphLinkForm" class="inline-form" style="flex-wrap:wrap;gap:0.5rem">
          <input id="glSrcType" placeholder="src type (asset)" required />
          <input id="glSrcId" placeholder="src id" required />
          <input id="glRel" placeholder="relation" value="related" />
          <input id="glDstType" placeholder="dst type (vuln)" required />
          <input id="glDstId" placeholder="dst id" required />
          <button type="submit">Link</button>
        </form>
        <ul class="cc-list" style="margin-top:0.75rem">${
          links.length
            ? links
                .slice(0, 30)
                .map(
                  (l) =>
                    `<li><code>${escapeHtml(l.src_type)}:${escapeHtml(l.src_id)}</code> —${escapeHtml(
                      l.relation || "related"
                    )}→ <code>${escapeHtml(l.dst_type)}:${escapeHtml(l.dst_id)}</code></li>`
                )
                .join("")
            : `<li class="hint">No manual links yet</li>`
        }</ul>
      </section>
      <form id="graphFocusForm" class="inline-form" style="margin-top:1rem;gap:0.5rem">
        <input id="graphFocusQ" placeholder="Focus asset / CVE / host…" value="${escapeHtml(focusQ)}" />
        <button type="submit">Correlate</button>
      </form>`;
    qs("graphClearFocus")?.addEventListener("click", () => {
      window.__securaiqGraphFocus = "";
      renderGraphPage();
    });
    qs("graphHotspots")?.querySelectorAll("[data-corr-focus]").forEach((el) => {
      el.addEventListener("click", () => {
        window.__securaiqGraphFocus = el.getAttribute("data-corr-focus") || "";
        renderGraphPage();
      });
    });
    qs("graphRebuild")?.addEventListener("click", async () => {
      const res = await fetch("/api/graph/rebuild", { method: "POST", headers: authHeaders() });
      const d = await res.json().catch(() => ({}));
      if (typeof notifyUser === "function") notifyUser(`**Graph:** persisted ${d.links_created ?? 0} auto-links`);
      renderGraphPage();
    });
    qs("graphFocusForm")?.addEventListener("submit", (e) => {
      e.preventDefault();
      window.__securaiqGraphFocus = (qs("graphFocusQ")?.value || "").trim();
      renderGraphPage();
    });
    qs("graphAskAi")?.addEventListener("click", () => {
      if (typeof runNavPrompt === "function") {
        runNavPrompt(
          "threat_hunt",
          "Using our knowledge graph hotspots, explain the top correlated attack paths across vulns, XDR detections, incidents, and control gaps — cite asset names."
        );
      }
    });
    qs("graphLinkForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const res = await fetch("/api/graph/links", {
          method: "POST",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({
            src_type: qs("glSrcType")?.value?.trim(),
            src_id: qs("glSrcId")?.value?.trim(),
            relation: qs("glRel")?.value?.trim() || "related",
            dst_type: qs("glDstType")?.value?.trim(),
            dst_id: qs("glDstId")?.value?.trim(),
          }),
        });
        const out = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(out.detail || res.status);
        renderGraphPage();
      } catch (err) {
        alert(err.message || "Link failed");
      }
    });
  }

  async function renderBillingPage() {
    const body = qs("billingPageBody");
    if (!body) return;
    body.innerHTML = `<p class="hint">Loading billing…</p>`;
    let dash = {};
    let plat = {};
    let usage = {};
    let plans = [];
    // Real bug found in audit: a failed /api/dashboard fetch was silently
    // swallowed and the page rendered zeroed-out defaults (0 assets, 0 risks,
    // "Community" plan) that look identical to a genuinely empty/local
    // workspace. Track failure explicitly and say so instead.
    let loadFailed = false;
    try {
      const [dRes, healthRes, platRes, usageRes, plansRes] = await Promise.all([
        fetch("/api/dashboard", { headers: authHeaders() }),
        fetch("/api/health").catch(() => null),
        fetch("/api/platform/status", { headers: authHeaders() }).catch(() => null),
        fetch("/api/billing/usage", { headers: authHeaders() }).catch(() => null),
        fetch("/api/billing/plans").catch(() => null),
      ]);
      if (!dRes.ok) loadFailed = true;
      dash = await dRes.json().catch(() => ({}));
      if (healthRes && healthRes.ok) plat = await healthRes.json().catch(() => ({}));
      const platStatus = platRes && platRes.ok ? await platRes.json().catch(() => ({})) : {};
      plat = { ...plat, ...platStatus };
      usage = usageRes && usageRes.ok ? await usageRes.json().catch(() => ({})) : {};
      const plansData = plansRes && plansRes.ok ? await plansRes.json().catch(() => ({})) : {};
      plans = Object.entries(plansData.plans || {}).map(([id, p]) => ({ id, ...p }));
    } catch (err) {
      loadFailed = true;
    }
    const limit = usage.messages_limit == null ? "unlimited" : usage.messages_limit;
    const planCards = plans.length
      ? plans
          .map(
            (p) => `<article class="cc-panel integ-card-sm">
              <h3>${escapeHtml(p.label || p.id)}</h3>
              <p class="hint">${p.price_usd == null ? "Contact sales" : p.price_usd === 0 ? "Free" : `$${p.price_usd}/mo`}</p>
              <p>${p.messages_per_month == null ? "Unlimited messages" : `${p.messages_per_month} messages/mo`}</p>
              ${
                p.id !== "free" && p.id !== (usage.plan || "free")
                  ? `<button type="button" class="btn-secondary billing-upgrade" data-plan="${escapeHtml(p.id)}">Upgrade</button>`
                  : p.id === (usage.plan || "free")
                    ? `<span class="hint">Current plan</span>`
                    : ""
              }
            </article>`
          )
          .join("")
      : `<p class="hint">Community / local — self-hosted</p>`;
    body.innerHTML = `
      ${
        loadFailed
          ? `<p class="hint" style="color:#c0392b">Could not load billing/usage data — showing partial or default values, not a confirmed state. Reload to retry.</p>`
          : ""
      }
      <div class="billing-grid">
        <section class="cc-panel">
          <header><h2>Subscription</h2></header>
          <p><strong>${escapeHtml(usage.plan_label || usage.plan || "Community")}</strong></p>
          <p class="hint">${usage.messages_used_this_month ?? 0} / ${escapeHtml(String(limit))} messages this month
            ${usage.enforcement_enabled ? "" : " (soft limit)"}</p>
          <div class="integ-grid" style="margin-top:1rem">${planCards}</div>
        </section>
        <section class="cc-panel">
          <header><h2>Workspace usage</h2></header>
          <ul class="cc-list">
            <li>Assets — <strong>${dash.assets_total || 0}</strong></li>
            <li>Open risks — <strong>${dash.risks_open || 0}</strong></li>
            <li>Open vulns — <strong>${dash.vulnerabilities_open || 0}</strong></li>
            <li>Remediations — <strong>${dash.remediations_open || 0}</strong></li>
            <li>Gap assessments — <strong>${dash.assessment_count || 0}</strong></li>
            <li>Playbooks — <strong>${dash.playbooks_total || 0}</strong></li>
          </ul>
        </section>
        <section class="cc-panel">
          <header><h2>Platform</h2></header>
          <p class="hint">${escapeHtml(plat.status || "Local · no cloud billing")}</p>
          <ul class="cc-list">
            <li>Backend — ${escapeHtml(String(plat.backend || "—"))}</li>
            <li>Model — ${escapeHtml(String(plat.model || "—"))}</li>
            <li>RAG docs — ${escapeHtml(String(plat.rag_documents ?? "—"))}</li>
            <li>Vector store — ${escapeHtml(String(plat.vector_store || "—"))}</li>
            <li>Scanners — ${escapeHtml(String((plat.scanners || []).length || "—"))} import adapters</li>
            <li>Intel feeds — ${escapeHtml(String((plat.intel_feeds || []).length || "—"))} wired</li>
          </ul>
        </section>
        <section class="cc-panel">
          <header><h2>Invoices</h2></header>
          <p class="hint">Stripe checkout when <code>STRIPE_SECRET_KEY</code> is configured. Local mode has no invoices.</p>
        </section>
      </div>`;
    body.querySelectorAll(".billing-upgrade").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const plan = btn.getAttribute("data-plan");
        btn.disabled = true;
        try {
          const res = await fetch("/api/billing/checkout", {
            method: "POST",
            headers: authHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify({
              plan,
              success_url: `${window.location.origin}/?billing=success`,
              cancel_url: `${window.location.origin}/?billing=cancel`,
            }),
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
          if (data.url) window.location.href = data.url;
          else if (typeof notifyUser === "function") notifyUser("**Checkout session created.**");
        } catch (err) {
          alert(err.message || "Checkout unavailable");
        } finally {
          btn.disabled = false;
        }
      });
    });
  }

  async function loadVulnSampleButtons() {
    return;
  }

  async function importLabSample(_sampleId) {
    alert("Lab samples removed. Use Live scan (Tools + Auth) or Import with your scanner export.");
  }

  function renderAutomationPage() {
    const body = qs("automationPageBody");
    if (!body) return;
    body.innerHTML = `<p class="hint">Loading jobs…</p>`;
    refreshAutomationPage();
  }

  async function refreshAutomationPage() {
    const body = qs("automationPageBody");
    if (!body) return;
    let jobs = [];
    let prefect = {};
    try {
      const res = await fetch("/api/jobs?limit=40", { headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      jobs = data.jobs || [];
      prefect = data.prefect || {};
      if (!res.ok) throw new Error(data.detail || `Jobs failed (${res.status})`);
    } catch (err) {
      body.innerHTML = `<p class="hint">Could not load jobs: ${escapeHtml(err.message || String(err))}</p>`;
      return;
    }
    if (!prefect.installed && !prefect.ready) {
      try {
        const pr = await fetch("/api/prefect/status", { headers: authHeaders() });
        prefect = (await pr.json().catch(() => ({}))) || prefect;
      } catch {
        /* ignore */
      }
    }
    const engineDefault = prefect.ready ? "prefect" : "local";
    const fmtWhen = (ts) => {
      if (ts == null || ts === "") return "-";
      const n = Number(ts);
      const d = Number.isFinite(n) && n > 1e11 ? new Date(n) : Number.isFinite(n) ? new Date(n * 1000) : new Date(ts);
      return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
    };
    const jobRows =
      jobs.length > 0
        ? jobs
            .map((j) => {
              const st = String(j.status || "unknown").toLowerCase();
              const eng = (j.payload && j.payload._engine) || (j.result && j.result.engine) || "-";
              const summary =
                j.error ||
                (j.result && (j.result.path || j.result.count != null || j.result.duration_sec != null)
                  ? JSON.stringify(j.result).slice(0, 120)
                  : "");
              return `<li data-job-id="${escapeHtml(j.id)}">
                  <div>
                    <strong>${escapeHtml(j.kind || "?")}</strong>
                    <span class="hint">${escapeHtml(eng)} · ${escapeHtml(fmtWhen(j.created_at))}</span>
                    ${summary ? `<span class="hint">${escapeHtml(String(summary).slice(0, 140))}</span>` : ""}
                  </div>
                  <span class="auto-job-status status-${escapeHtml(st)}">${escapeHtml(st)}</span>
                  <span class="hint">${escapeHtml(fmtWhen(j.finished_at || j.started_at))}</span>
                </li>`;
            })
            .join("")
        : `<li class="hint">No runs yet - enqueue KEV sync, XDR sync, or a board report below.</li>`;
    const logLines = jobs
      .slice(0, 12)
      .map((j) => {
        const st = j.status || "?";
        const when = fmtWhen(j.finished_at || j.started_at || j.created_at);
        return `<div class="auto-log-line"><code>${escapeHtml(when)}</code> <strong>${escapeHtml(
          j.kind || ""
        )}</strong> ${escapeHtml(st)}${j.error ? ` - ${escapeHtml(String(j.error).slice(0, 80))}` : ""}</div>`;
      })
      .join("");
    body.innerHTML = `
      <section class="cc-panel auto-flow-panel">
        <header><h2>Golden-path workflow</h2>
          <p class="hint">Visual pipeline for authorized scan → decision → ticket → verify. Jobs below power the automation spine.</p>
        </header>
        <div class="auto-flow" role="list">
          ${["Trigger", "Scan", "AI triage", "Risk", "Approval", "Ticket", "Notify", "Close"]
            .map(
              (step, i) =>
                `<div class="auto-flow-step" role="listitem"><span>${i + 1}</span><strong>${step}</strong></div>${
                  i < 7 ? '<span class="auto-flow-arrow" aria-hidden="true">→</span>' : ""
                }`
            )
            .join("")}
        </div>
      </section>
      <section class="cc-panel">
        <header><h2>Prefect</h2>
          <p class="hint">${escapeHtml(prefect.hint || "Optional job orchestrator")}</p>
        </header>
        <p>
          <span class="auto-job-status status-${prefect.ready ? "done" : prefect.installed ? "partial" : "planned"}">
            ${prefect.ready ? "ready" : prefect.installed ? "installed" : "not installed"}
          </span>
          ${prefect.version ? `<span class="hint">v${escapeHtml(prefect.version)}</span>` : ""}
          ${prefect.api_url ? `<span class="hint">${escapeHtml(prefect.api_url)}</span>` : ""}
        </p>
        <div class="cc-action-row auto-run-row">
          <label class="hint">Engine
            <select id="autoJobEngine" class="composer-select">
              <option value="auto">auto (${escapeHtml(engineDefault)})</option>
              <option value="local">local</option>
              <option value="prefect" ${prefect.installed ? "" : "disabled"}>prefect</option>
            </select>
          </label>
          <button type="button" class="btn-primary-cc" data-job-kind="kev_sync">Run KEV sync</button>
          <button type="button" class="btn-secondary" data-job-kind="xdr_sync">Run XDR sync</button>
          <button type="button" class="btn-secondary" data-job-kind="wazuh_sync">Run SecuraIQ SIEM sync</button>
          <button type="button" class="btn-secondary" data-job-kind="thehive_sync">Run TheHive sync</button>
          <button type="button" class="btn-secondary" data-job-kind="cloud_posture_sync">Run cloud posture sync</button>
          <button type="button" class="btn-secondary" data-job-kind="openaudit_sync">Run inventory sync</button>
          <button type="button" class="btn-secondary" data-job-kind="hardeningkitty_audit">Run HardeningKitty audit</button>
          <button type="button" class="btn-secondary" data-job-kind="report_export">Export board PDF</button>
        </div>
      </section>
      <div class="auto-grid">
        <section class="cc-panel">
          <header><h2>Jobs</h2></header>
          <ul class="auto-job-list">${jobRows}</ul>
        </section>
        <section class="cc-panel">
          <header><h2>Triggers &amp; webhooks</h2></header>
          <p class="hint">Wire scanner webhooks and chatops under Integrations. Prefect wraps the same handlers when enabled.</p>
          <div class="cc-action-row">
            <button type="button" class="cc-action" data-workspace="integrations">Open integrations</button>
            <button type="button" class="btn-secondary" data-workspace="reports">Reports</button>
          </div>
        </section>
        <section class="cc-panel">
          <header><h2>Execution logs</h2></header>
          <div class="auto-log">
            ${logLines || `<p class="hint">No automated runs yet - enqueue a job above.</p>`}
          </div>
        </section>
      </div>`;
    body.querySelectorAll("[data-workspace]").forEach((el) => {
      el.addEventListener("click", () => showWorkspace(el.getAttribute("data-workspace")));
    });
    body.querySelectorAll("[data-job-kind]").forEach((btn) => {
      btn.addEventListener("click", () => enqueueAutomationJob(btn.getAttribute("data-job-kind")));
    });
  }

  async function enqueueAutomationJob(kind) {
    if (!kind) return;
    const engine = qs("autoJobEngine")?.value || "auto";
    try {
      const res = await fetch("/api/jobs", {
        method: "POST",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ kind, engine, payload: {} }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(typeof data.detail === "string" ? data.detail : data.detail?.[0]?.msg || `Enqueue failed (${res.status})`);
        return;
      }
      if (typeof notifyUser === "function") {
        notifyUser(`**Job queued:** \`${kind}\` (${engine}) · id \`${data.id || "?"}\``);
      }
      setTimeout(() => refreshAutomationPage(), 600);
      setTimeout(() => refreshAutomationPage(), 2500);
    } catch (err) {
      alert(err.message || "Enqueue failed");
    }
  }

  function wireAutomationControls() {
    if (window.__securaiqAutoWired) return;
    window.__securaiqAutoWired = true;
    qs("automationAskDesign")?.addEventListener("click", () => {
      const btn = qs("automationAskDesign");
      const mode = btn?.getAttribute("data-mode") || "ciso";
      const prompt = btn?.getAttribute("data-prompt") || "";
      if (typeof window.runNavPrompt === "function") window.runNavPrompt(mode, prompt, { stay: true });
    });
    qs("automationRefreshJobs")?.addEventListener("click", () => refreshAutomationPage());
  }
  wireAutomationControls();
  window.refreshAutomationPage = refreshAutomationPage;

  function wireWorkspaceNav() {
    if (window.__securaiqWsNavWired) return;
    window.__securaiqWsNavWired = true;
    document.querySelectorAll("[data-workspace]").forEach((el) => {
      el.addEventListener("click", (e) => {
        e.preventDefault();
        showWorkspace(el.getAttribute("data-workspace"));
      });
    });
    // notifBtn now opens the real notifications panel (wired in app.js).
    // "Open SOC" inside that panel still uses the generic [data-workspace] handler above.

    document.querySelectorAll(".ai-tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        const wsTab = tab.getAttribute("data-workspace-tab");
        if (wsTab) {
          showWorkspace(wsTab);
          return;
        }
        if (tab.hasAttribute("data-open-palette")) {
          if (typeof showView === "function") showView("chat");
          if (typeof window.openAiTab === "function") window.openAiTab("tools");
          if (typeof window.openToolsPalette === "function") window.openToolsPalette(true);
          return;
        }
        const name = tab.getAttribute("data-ai-tab");
        if (typeof window.openAiTab === "function") window.openAiTab(name);
        else {
          document.querySelectorAll(".ai-tab").forEach((t) => t.classList.remove("active"));
          tab.classList.add("active");
          document.querySelectorAll(".ai-tab-panel").forEach((p) => p.classList.add("hidden"));
          qs(`aiTab-${name}`)?.classList.remove("hidden");
          if (name === "files") refreshAiFilesTab();
          if (name === "tools") refreshAiToolsTab();
          if (name === "memory") refreshAiMemoryTab();
          if (name === "tasks") refreshAiTasksTab();
        }
      });
    });
  }

  async function refreshAiTasksTab() {
    const el = qs("aiTab-tasks");
    if (!el) return;
    const res = await fetch("/api/dashboard", { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    const queue = data.work_queue || [];
    el.innerHTML = `<div class="saas-tab-head"><h2>AI work queue</h2></div>`;
    if (typeof window.renderWorkQueue === "function") {
      const host = document.createElement("div");
      host.id = "ccWorkQueue";
      el.appendChild(host);
      window.renderWorkQueue(queue);
    } else {
      el.innerHTML += `<ul class="cc-list">${queue
        .map((w) => `<li><strong>${escapeHtml(w.priority)}</strong> ${escapeHtml(w.title)}</li>`)
        .join("")}</ul>`;
    }
  }
  window.refreshAiTasksTab = refreshAiTasksTab;

  async function refreshAiFilesTab() {
    const el = qs("aiTab-files");
    if (!el) return;
    const res = await fetch("/api/files", { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    const files = data.files || data.items || [];
    el.innerHTML = `
      <div class="saas-tab-head">
        <h2>Workspace files</h2>
        <button type="button" class="btn-secondary" id="aiFilesUpload">Upload</button>
      </div>
      ${
        files.length
          ? `<ul class="cc-list">${files
              .map(
                (f) =>
                  `<li><strong>${escapeHtml(f.filename || f.name || f.id)}</strong>
                  <span class="hint">${escapeHtml(String(f.size_bytes || f.size || ""))}</span></li>`
              )
              .join("")}</ul>`
          : `<p class="hint">No uploaded files — use Upload to feed RAG / evidence.</p>`
      }
      <button type="button" class="cc-action" id="aiFilesAsk" style="margin-top:1rem">Ask AI about attached evidence</button>`;
    qs("aiFilesUpload")?.addEventListener("click", () => qs("fileUploadInput")?.click());
    qs("aiFilesAsk")?.addEventListener("click", () => {
      if (typeof runNavPrompt === "function")
        runNavPrompt("ciso", "Summarize uploaded evidence and what controls it supports");
    });
  }
  window.refreshAiFilesTab = refreshAiFilesTab;

  async function refreshAiToolsTab() {
    const el = qs("aiTab-tools");
    if (!el) return;
    const res = await fetch("/api/tools");
    const data = await res.json();
    const selected = typeof window.getSelectedTools === "function" ? window.getSelectedTools() : [];
    const renderGroup = (origin, label, hint) => {
      const tools = (data.tools || []).filter(
        (t) => (t.origin === "third_party" ? "third_party" : "securaiq") === origin
      );
      if (!tools.length) return "";
      return `<section class="tools-origin tools-origin-${origin}">
        <header class="tools-origin-head">
          <strong>${escapeHtml(label)}</strong>
          <span class="hint">${escapeHtml(hint)}</span>
        </header>
        <div class="tools-cat-grid" style="margin:0.5rem 0 1rem">
          ${tools
            .map((t) => {
              const status = !t.available
                ? t.origin === "third_party"
                  ? t.kind === "external"
                    ? "missing"
                    : "API off"
                  : "off"
                : t.heavy
                  ? "heavy"
                  : "ready";
              const provider =
                t.origin === "third_party" && t.provider ? ` · ${escapeHtml(t.provider)}` : "";
              return `<button type="button" class="tool-pick tool-origin-${escapeHtml(
                t.origin || "securaiq"
              )} ${t.available ? "" : "unavailable"} ${
                selected.includes(t.id) ? "selected" : ""
              }" data-id="${escapeHtml(t.id)}" ${t.available ? "" : "disabled"}>
              <span><strong>${escapeHtml(t.name || t.id)}</strong>
              <small>${escapeHtml(status)}${provider}</small></span>
            </button>`;
            })
            .join("")}
        </div>
      </section>`;
    };
    el.innerHTML = `
      <div class="saas-tab-head">
        <h2>Cyber tools suite</h2>
        <button type="button" class="btn-primary-cc" id="aiToolsOpenPalette">Open palette</button>
      </div>
      <p class="hint">SecuraIQ ${data.securaiq_available || 0}/${data.securaiq_count || 0} ready · third-party ${
        data.third_party_available || 0
      }/${data.third_party_count || 0} ready — Auth + owned target, then Run.</p>
      ${renderGroup("securaiq", "SecuraIQ tools", "Built-in scanners — no install")}
      ${renderGroup("third_party", "Third-party tools & APIs", "PATH binaries or vendor APIs")}
      <div class="cc-action-row">
        <button type="button" class="cc-action" id="aiToolsRun">Run selected</button>
        <button type="button" class="cc-action" id="aiToolsChat">Chat with selected</button>
        <button type="button" class="btn-secondary" id="aiToolsClear">Clear</button>
      </div>`;
    el.querySelectorAll(".tool-pick").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (btn.classList.contains("unavailable")) return;
        const id = btn.getAttribute("data-id");
        let cur = typeof window.getSelectedTools === "function" ? window.getSelectedTools() : [];
        if (cur.includes(id)) cur = cur.filter((x) => x !== id);
        else cur = cur.concat(id);
        if (typeof window.setSelectedTools === "function") window.setSelectedTools(cur);
        btn.classList.toggle("selected", cur.includes(id));
      });
    });
    qs("aiToolsOpenPalette")?.addEventListener("click", () => {
      if (typeof window.openToolsPalette === "function") window.openToolsPalette(true);
    });
    qs("aiToolsRun")?.addEventListener("click", () => {
      if (typeof window.runSelectedTools === "function") window.runSelectedTools();
    });
    qs("aiToolsChat")?.addEventListener("click", () => {
      const tools = typeof window.getSelectedTools === "function" ? window.getSelectedTools() : [];
      if (typeof window.openAiTab === "function") window.openAiTab("chat");
      if (typeof runNavPrompt === "function") {
        runNavPrompt(
          "assess",
          tools.length
            ? `Use tools ${tools.join(", ")} on the authorized/lab target and summarize findings with remediations.`
            : "Recommend which SecuraIQ tools vs third-party tools to run for a typical authorized web app assessment."
        );
      }
    });
    qs("aiToolsClear")?.addEventListener("click", () => {
      if (typeof window.setSelectedTools === "function") window.setSelectedTools([]);
      refreshAiToolsTab();
    });
  }
  window.refreshAiToolsTab = refreshAiToolsTab;

  async function refreshAiMemoryTab() {
    const el = qs("aiTab-memory");
    if (!el) return;
    const eng = qs("engagementSelect")?.value;
    if (!eng) {
      el.innerHTML = `<p class="hint">Select or create a Project/engagement to store memories. Memories are injected into AI chat context automatically.</p>
        <button type="button" class="cc-action" id="aiMemNew">Create engagement</button>`;
      qs("aiMemNew")?.addEventListener("click", () => qs("newEngagementBtn")?.click());
      return;
    }
    const res = await fetch(`/api/engagements/${eng}/memories`, { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    const mems = data.memories || data.items || [];
    el.innerHTML = `
      <div class="saas-tab-head"><h2>Engagement memory</h2></div>
      <ul class="cc-list">${
        mems.length
          ? mems
              .map((m) => `<li><strong>${escapeHtml(m.key)}</strong> — ${escapeHtml(m.value)}</li>`)
              .join("")
          : `<li class="hint">No memories yet</li>`
      }</ul>
      <form id="aiMemForm" class="inline-form" style="margin-top:0.75rem">
        <input id="aiMemKey" placeholder="key (e.g. scope)" required />
        <input id="aiMemVal" placeholder="value" required />
        <button type="submit">Save</button>
      </form>`;
    qs("aiMemForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      await fetch(`/api/engagements/${eng}/memories`, {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          key: qs("aiMemKey")?.value?.trim(),
          value: qs("aiMemVal")?.value?.trim(),
        }),
      });
      refreshAiMemoryTab();
    });
  }
  window.refreshAiMemoryTab = refreshAiMemoryTab;

  // Upgrade global search to API results panel
  if (!window.__securaiqSearchWired) {
    window.__securaiqSearchWired = true;
    const searchEl = qs("globalSearch");
    const resultsEl = qs("searchResults");
    const route = {
      asset: "assets",
      risk: "risks",
      vuln: "vulns",
      remediation: "remediations",
      playbook: "playbooks",
      campaign: "campaigns",
      incident: "soc",
      intel: "intel",
    };

    function hideSearchResults() {
      resultsEl?.classList.add("hidden");
      if (resultsEl) resultsEl.innerHTML = "";
    }

    async function runGlobalSearch(q) {
      if (!q || !resultsEl) return;
      const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`, { headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      const results = data.results || [];
      if (!results.length) {
        resultsEl.innerHTML = `<button type="button" class="search-hit" data-ask="1">No register hits — ask AI about “${escapeHtml(
          q
        )}”</button>`;
        resultsEl.classList.remove("hidden");
        resultsEl.querySelector("[data-ask]")?.addEventListener("click", () => {
          hideSearchResults();
          if (typeof runNavPrompt === "function") runNavPrompt("default", `Find and explain: ${q}`);
        });
        return;
      }
      resultsEl.innerHTML = results
        .slice(0, 12)
        .map(
          (r) =>
            `<button type="button" class="search-hit" data-kind="${escapeHtml(r.kind || "")}">
              <span class="search-kind">${escapeHtml(r.kind || "")}</span>
              <strong>${escapeHtml(r.title || r.name || r.id || "")}</strong>
              <span class="hint">${escapeHtml(r.meta || r.subtitle || r.summary || "")}</span>
            </button>`
        )
        .join("");
      resultsEl.classList.remove("hidden");
      resultsEl.querySelectorAll(".search-hit").forEach((btn) => {
        btn.addEventListener("click", () => {
          const kind = btn.getAttribute("data-kind");
          hideSearchResults();
          showWorkspace(route[kind] || "command");
        });
      });
    }

    if (searchEl) {
      searchEl.addEventListener("keydown", async (e) => {
        if (e.key === "Escape") {
          hideSearchResults();
          return;
        }
        if (e.key !== "Enter") return;
        e.preventDefault();
        e.stopImmediatePropagation();
        await runGlobalSearch(searchEl.value.trim());
      });
      searchEl.addEventListener("input", () => {
        if (!searchEl.value.trim()) hideSearchResults();
      });
      document.addEventListener("click", (e) => {
        if (!e.target.closest?.(".topbar-search-wrap")) hideSearchResults();
      });
    }
  }

  function rewireModuleButtons() {
    if (window.__securaiqRewireDone) return;
    window.__securaiqRewireDone = true;
    const map = {
      assetBtn: "assets",
      riskBtn: "risks",
      vulnBtn: "vulns",
      remBtn: "remediations",
      playbookBtn: "playbooks",
      campaignBtn: "campaigns",
      reportsBtn: "reports",
      navEvidence: "evidence",
      orgsBtn: "orgs",
      frameworksBtn: "frameworks",
      dashboardBtn: "command",
    };
    Object.entries(map).forEach(([id, view]) => {
      const el = qs(id);
      if (!el) return;
      el.addEventListener(
        "click",
        (e) => {
          e.preventDefault();
          e.stopImmediatePropagation();
          if (view === "command") {
            if (typeof showView === "function") showView("command");
            else showWorkspace("command");
          } else showWorkspace(view);
        },
        true
      );
    });

    const openers = [
      ["hkAuditBtn", () => runHardeningKittyAudit()],
      ["oaSyncBtn", () => syncInventory()],
      ["assetsLanRefresh", () => refreshLanAssets()],
      [
        "softwareLocalRefreshBtn",
        async () => {
          if (typeof window.refreshLocalWindowsHost === "function") {
            await window.refreshLocalWindowsHost(true);
            renderSoftwarePage({ quiet: true });
          }
        },
      ],
      [
        "softwareSyncAllBtn",
        async () => {
          if (typeof window.syncAllAndRebuildSoftware === "function") {
            await window.syncAllAndRebuildSoftware({});
          }
        },
      ],
      [
        "softwareOpenExport",
        () =>
          typeof downloadMd === "function" &&
          downloadMd("/api/software/export?format=md", "securaiq-software.md"),
      ],
      [
        "softwareRebuildBtn",
        async () => {
          const el = qs("softwarePageBody");
          if (el) el.innerHTML = `<p class="hint">Rebuilding inventory…</p>`;
          try {
            const res = await fetch("/api/software/rebuild", { method: "POST", headers: authHeaders() });
            if (!res.ok) throw new Error(await readApiError(res));
            const body = await res.json().catch(() => ({}));
            renderSoftwarePage();
            if (typeof loadCommandCenter === "function") loadCommandCenter();
            if (typeof notifyUser === "function") notifyUser("**Software inventory rebuilt.**");
          } catch (err) {
            if (el) {
              el.innerHTML = `<div class="sw-empty-state"><p class="hint">Rebuild failed: ${escapeHtml(err.message || String(err))}</p>
                <div class="cc-action-row"><button type="button" class="btn-secondary" id="softwareRetryRebuild">Retry</button></div></div>`;
              qs("softwareRetryRebuild")?.addEventListener("click", () => {
                const btn = qs("softwareRebuildBtn");
                if (btn) btn.click();
              });
            }
          }
        },
      ],
      ["assetsOpenCreate", () => typeof openAsset === "function" && openAsset()],
      ["risksOpenCreate", () => typeof openRisk === "function" && openRisk()],
      ["vulnsOpenImport", () => typeof openVuln === "function" && openVuln()],
      ["mcImportScanners", () => showWorkspace("vulns")],
      [
        "vulnsOpenExport",
        () => typeof downloadMd === "function" && downloadMd("/api/vulnerabilities/export", "securaiq-vulns.md"),
      ],
      ["remsOpenGap", () => typeof openGap === "function" && openGap()],
      ["playbooksOpenCreate", () => typeof openPlaybook === "function" && openPlaybook()],
      ["campaignsOpenCreate", () => typeof openCampaign === "function" && openCampaign()],
      ["evidenceUploadBtn", () => qs("fileUploadInput")?.click()],
      ["frameworksRunGap", () => typeof openGap === "function" && openGap()],
    ];
    openers.forEach(([id, fn]) => {
      const el = qs(id);
      if (el) el.addEventListener("click", fn);
    });
    document.querySelectorAll("[data-action='live-scan'], [data-action='new-scan']").forEach((el) => {
      if (el.dataset.liveScanWired) return;
      el.dataset.liveScanWired = "1";
      el.addEventListener("click", (e) => {
        e.preventDefault();
        const action = el.getAttribute("data-action");
        if (action === "new-scan" && typeof window.openNewScanModal === "function") {
          window.openNewScanModal();
        } else if (typeof window.startLiveScan === "function") {
          window.startLiveScan();
        }
      });
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    wireWorkspaceNav();
    rewireModuleButtons();
  });
  // Scripts load at end of body — wire once immediately; DOMContentLoaded is a no-op if already fired
  if (document.readyState === "loading") {
    /* wait for DOMContentLoaded */
  } else {
    wireWorkspaceNav();
    rewireModuleButtons();
  }

  // Realtime: refresh whichever workspace view is open
  window.__securaiqRefreshActiveView = (data, flags) => {
    const view = window.__securaiqWorkspaceView || "";
    if (!view || view === "chat") return;
    const force = !!(flags && (flags.pushRefresh || flags.jobsChanged || flags.kpisChanged));
    const delay = force ? 220 : 4000;
    clearTimeout(window.__securaiqViewRtTimer);
    window.__securaiqViewRtTimer = setTimeout(() => {
      // Hunt live owns SOC table refresh — avoid full SOC rebuild every tick
      if (view === "soc" && window.__securaiqHuntLive && typeof window.__securaiqRunLiveHunt === "function") {
        if (flags && flags.pushType === "hunt") window.__securaiqRunLiveHunt();
        else if (force && flags && flags.pushType && flags.pushType !== "hunt") {
          if (typeof renderSocPage === "function") renderSocPage();
        }
        return;
      }
      const runners = {
        command: () => typeof loadCommandCenter === "function" && loadCommandCenter(),
        assets: () => typeof renderAssetsPage === "function" && renderAssetsPage({ quiet: true }),
        software: () => typeof renderSoftwarePage === "function" && renderSoftwarePage({ quiet: true }),
        risks: () => typeof renderRisksPage === "function" && renderRisksPage(),
        vulns: () => typeof renderVulnsPage === "function" && renderVulnsPage({ quiet: true }),
        remediations: () => typeof renderRemsPage === "function" && renderRemsPage(),
        playbooks: () => typeof renderPlaybooksPage === "function" && renderPlaybooksPage(),
        campaigns: () => typeof renderCampaignsPage === "function" && renderCampaignsPage(),
        intel: () =>
          !window.__securaiqIntelLookupBusy &&
          typeof renderIntelPage === "function" &&
          renderIntelPage(),
        reports: () => typeof renderReportsPage === "function" && renderReportsPage(),
        soc: () => typeof renderSocPage === "function" && renderSocPage(),
        evidence: () => typeof renderEvidencePage === "function" && renderEvidencePage(),
        frameworks: () => {
          if (typeof renderHardeningPanel === "function") renderHardeningPanel();
          if (typeof renderFrameworksPage === "function") renderFrameworksPage();
        },
        automation: () => typeof refreshAutomationPage === "function" && refreshAutomationPage(),
        graph: () => typeof renderGraphPage === "function" && renderGraphPage(),
        integrations: () => typeof renderIntegrationsPage === "function" && renderIntegrationsPage(),
        orgs: () => typeof renderOrgsPage === "function" && renderOrgsPage(),
        billing: () => typeof renderBillingPage === "function" && renderBillingPage(),
      };
      const fn = runners[view];
      if (fn) fn();
    }, delay);
  };

  // Realtime job pulse → refresh active panels without full page reload
  window.__securaiqOnJobPulse = (data) => {
    const view = window.__securaiqWorkspaceView || "";
    const kinds = new Set((data.jobs_recent || []).map((j) => j.kind));
    const ALL_TOOL_JOBS = new Set([
      "software_sync_all",
      "wazuh_sync",
      "xdr_sync",
      "openaudit_sync",
      "lan_inventory_audit",
      "cloud_posture_sync",
      "sonarqube_sync",
      "hardeningkitty_audit",
      "scan_execute",
      "combo_assessment",
      "thehive_sync",
      "kev_sync",
      "report_export",
    ]);
    if ([...kinds].some((k) => ALL_TOOL_JOBS.has(k))) {
      if (view === "software" && typeof renderSoftwarePage === "function") renderSoftwarePage({ quiet: true });
      if (view === "assets" && typeof renderAssetsPage === "function") renderAssetsPage({ quiet: true });
      if (view === "vulns" && typeof renderVulnsPage === "function") renderVulnsPage({ quiet: true });
      if (view === "soc" && typeof renderSocPage === "function") renderSocPage();
      if (view === "frameworks") {
        if (typeof renderHardeningPanel === "function") renderHardeningPanel();
        if (typeof renderFrameworksPage === "function") renderFrameworksPage();
      }
      if (view === "intel" && !window.__securaiqIntelLookupBusy && typeof renderIntelPage === "function") {
        renderIntelPage();
      }
      if (typeof loadCommandCenter === "function") loadCommandCenter();
      if (typeof syncLiveWorkspace === "function") syncLiveWorkspace({ pushType: "tool" });
    }
    if (view === "assets" && (kinds.has("openaudit_sync") || kinds.has("scan_execute") || data.inventory)) {
      renderAssetsPage({ quiet: true });
    }
    if (view === "intel" && (kinds.has("kev_sync") || data.intel) && !window.__securaiqIntelLookupBusy) {
      renderIntelPage();
    }
    if (kinds.has("kev_sync") && typeof refreshIntelStrip === "function") {
      refreshIntelStrip();
    }
    if (kinds.has("scan_execute") || kinds.has("combo_assessment")) {
      if (typeof loadAssets === "function") loadAssets();
      if (typeof loadVulns === "function") loadVulns();
      if (typeof loadCommandCenter === "function") loadCommandCenter();
      if (view === "vulns" && typeof renderVulnsPage === "function") renderVulnsPage();
      if (view === "reports" && typeof renderReportsPage === "function") renderReportsPage();
    }
    if (view === "frameworks" && (kinds.has("hardeningkitty_audit") || data.hardeningkitty)) {
      renderHardeningPanel();
    }
    if (view === "soc" && (kinds.has("wazuh_sync") || kinds.has("xdr_sync") || kinds.has("thehive_sync"))) {
      if (typeof renderSocPage === "function") renderSocPage();
    }
    if (view === "vulns" && (kinds.has("hardeningkitty_audit") || kinds.has("cloud_posture_sync") || kinds.has("sonarqube_sync"))) {
      if (typeof renderVulnsPage === "function") renderVulnsPage();
      if (kinds.has("sonarqube_sync") && typeof renderSonarPanel === "function") renderSonarPanel();
    }
    if (view === "intel" && kinds.has("kev_sync") && !window.__securaiqIntelLookupBusy) {
      if (typeof renderIntelPage === "function") renderIntelPage();
    }
    if (view === "automation") {
      if (typeof refreshAutomationPage === "function") refreshAutomationPage();
    }
  };
  window.__securaiqOnPushPulse = (data, flags) => {
    const view = window.__securaiqWorkspaceView || "";
    const t = (flags && flags.pushType) || (data.push && data.push.type) || "";
    const live = window.REALTIME_LIVE_TYPES;
    if (live && live.has(t) && typeof syncLiveWorkspace === "function") {
      clearTimeout(window.__securaiqPushSyncTimer);
      window.__securaiqPushSyncTimer = setTimeout(() => syncLiveWorkspace({ pushType: t, push: data.push }), 200);
    }
    if (view === "soc" && t === "hunt" && typeof window.__securaiqRunLiveHunt === "function") {
      window.__securaiqRunLiveHunt();
      return;
    }
    // Broad push → let universal refresher handle; keep a fast path for SOC/vulns
    if (view === "soc" && (t === "xdr" || t === "xdr_batch" || t === "incident" || t === "job" || t === "siem" || t === "thehive" || t === "tool")) {
      clearTimeout(window.__securaiqSocRtTimer);
      window.__securaiqSocRtTimer = setTimeout(() => {
        if (typeof renderSocPage === "function") renderSocPage();
      }, 500);
    }
    if (view === "intel" && (t === "intel_watch" || t === "intel" || t === "job") && !window.__securaiqIntelLookupBusy) {
      clearTimeout(window.__securaiqIntelRtTimer);
      window.__securaiqIntelRtTimer = setTimeout(() => {
        if (typeof renderIntelPage === "function") renderIntelPage();
        if (typeof refreshIntelStrip === "function") refreshIntelStrip();
      }, 200);
    }
    if ((t === "intel" || t === "intel_watch") && typeof refreshIntelStrip === "function") {
      refreshIntelStrip();
    }
    if (view === "vulns" && (t === "vuln" || t === "vuln_batch" || t === "xdr_batch" || t === "cloud" || t === "scan" || t === "tool" || t === "hardening")) {
      clearTimeout(window.__securaiqVulnRtTimer);
      window.__securaiqVulnRtTimer = setTimeout(() => {
        if (typeof renderVulnsPage === "function") renderVulnsPage();
      }, 500);
    }
    if (t === "inventory") {
      const p = data.push || data;
      if (typeof pulseInventoryFromPush === "function") pulseInventoryFromPush(p);
    }
    if (view === "assets" && (t === "asset" || t === "inventory" || t === "scan" || t === "software_inventory")) {
      clearTimeout(window.__securaiqAssetRtTimer);
      window.__securaiqAssetRtTimer = setTimeout(() => {
        if (typeof loadAssets === "function") loadAssets();
        renderAssetsPage({ quiet: true });
      }, 200);
    }
    if (
      view === "software" &&
      typeof isSoftwarePushType === "function" &&
      isSoftwarePushType(t)
    ) {
      clearTimeout(window.__securaiqSwRtTimer);
      window.__securaiqSwRtTimer = setTimeout(() => {
        if (typeof refreshSoftwareFromPush === "function") {
          refreshSoftwareFromPush(data.push || data, { partial: true });
        }
      }, 180);
      return;
    }
    if (
      view === "software" &&
      (t === "software_inventory" || t === "scan" || t === "job" || t === "xdr_batch" || t === "vuln_batch" || t === "tool")
    ) {
      clearTimeout(window.__securaiqSwRtTimer);
      window.__securaiqSwRtTimer = setTimeout(() => {
        if (typeof refreshSoftwareFromPush === "function") {
          refreshSoftwareFromPush(data.push || data, { partial: true, summaryOnly: _softwareView === "servers" });
        } else if (typeof renderSoftwarePage === "function") {
          renderSoftwarePage({ quiet: true });
        }
      }, 300);
    }
    if (view === "assets" && t === "software_inventory") {
      clearTimeout(window.__securaiqAssetSwTimer);
      window.__securaiqAssetSwTimer = setTimeout(() => renderAssetsPage({ quiet: true }), 200);
    }
    if (
      typeof isSoftwarePushType === "function" &&
      isSoftwarePushType(t) &&
      typeof window.refreshSoftwareFromPush === "function"
    ) {
      window.refreshSoftwareFromPush(data.push || data, { partial: true, skipPulse: true });
      if (typeof setSoftwareSyncLive === "function") setSoftwareSyncLive("Live", true);
    }
    if (t === "scan" || t === "combo" || t === "asset" || t === "vuln" || t === "vuln_batch" || t === "tool") {
      clearTimeout(window.__securaiqScanRtTimer);
      window.__securaiqScanRtTimer = setTimeout(() => {
        if (typeof syncLiveWorkspace === "function") syncLiveWorkspace({ pushType: t });
        if (typeof pulseVaScanFromPush === "function") {
          const p = data.push || {};
          pulseVaScanFromPush({ type: t, status: p.status, step: p.step, findings: p.findings, summary: p.summary });
        }
      }, 200);
    }
    if (t === "tool_progress" && typeof pulseToolProgress === "function") {
      pulseToolProgress(data.push);
    }
    if (view === "risks" && t === "risk") {
      clearTimeout(window.__securaiqRiskRtTimer);
      window.__securaiqRiskRtTimer = setTimeout(() => renderRisksPage(), 500);
    }
    if (view === "remediations" && t === "remediation") {
      clearTimeout(window.__securaiqRemRtTimer);
      window.__securaiqRemRtTimer = setTimeout(() => renderRemsPage(), 500);
    }
    if (view === "playbooks" && t === "playbook") {
      clearTimeout(window.__securaiqPbRtTimer);
      window.__securaiqPbRtTimer = setTimeout(() => renderPlaybooksPage(), 500);
    }
    if (view === "campaigns" && t === "campaign") {
      clearTimeout(window.__securaiqCampRtTimer);
      window.__securaiqCampRtTimer = setTimeout(() => renderCampaignsPage(), 500);
    }
    if (view === "intel" && (t === "intel_watch" || t === "intel" || t === "job") && !window.__securaiqIntelLookupBusy) {
      clearTimeout(window.__securaiqIntelRtTimer);
      window.__securaiqIntelRtTimer = setTimeout(() => {
        if (typeof renderIntelPage === "function") renderIntelPage();
      }, 500);
    }
    if (view === "frameworks" && (t === "gap" || t === "remediation" || t === "evidence" || t === "hardening" || t === "tool")) {
      clearTimeout(window.__securaiqFwRtTimer);
      window.__securaiqFwRtTimer = setTimeout(() => {
        if (typeof renderFrameworksPage === "function") renderFrameworksPage();
        if (typeof renderHardeningPanel === "function") renderHardeningPanel();
      }, 400);
    }
    if (view === "integrations" && (t === "tool" || t === "inventory" || t === "siem")) {
      clearTimeout(window.__securaiqIntegRtTimer);
      window.__securaiqIntegRtTimer = setTimeout(() => {
        if (typeof renderIntegrationsPage === "function") renderIntegrationsPage();
      }, 400);
    }
    if (t === "notification" && typeof refreshNotifBadge === "function") {
      refreshNotifBadge();
    }
  };
  window.addEventListener("securaiq:realtime", (e) => {
    const detail = e.detail || {};
    if (!detail.jobsChanged && !detail.kpisChanged && !detail.pushRefresh && !detail.heartbeat) return;
    const hkHint = qs("hkPanelBody");
    if (hkHint && detail.hardeningkitty && window.__securaiqWorkspaceView === "frameworks") {
      const chip = hkHint.querySelector(".auto-job-status");
      if (chip && detail.hardeningkitty.installed) {
        chip.className = "auto-job-status status-done";
        chip.textContent = "installed";
      }
    }
  });
})();
