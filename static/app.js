const chatEl = document.getElementById("chat");
const inputEl = document.getElementById("input");
const sendBtn = document.getElementById("send");
const backendEl = document.getElementById("backend");
const modeEl = document.getElementById("mode");
const modelEl = document.getElementById("model");
const pullBtn = document.getElementById("pullModel");
const ingestBtn = document.getElementById("ingestRag");
const preloadBtn = document.getElementById("preloadModel");
const trainBtn = document.getElementById("trainUnsloth");
const settingsBtn = document.getElementById("settingsBtn");
const topSettingsBtn = document.getElementById("topSettingsBtn");
const hermesNewSessionBtn = document.getElementById("hermesNewSession");
const settingsModal = document.getElementById("settingsModal");
const settingsForm = document.getElementById("settingsForm");

// Migrate legacy HackGPT localStorage keys once after brand rename
(function migrateSecuraIqStorage() {
  try {
    const pairs = [
      ["hackgpt.auth.token", "securaiq.auth.token"],
      ["hackgpt.theme", "securaiq.theme"],
      ["hackgpt.chats.v1", "securaiq.chats.v1"],
      ["hackgpt.kpi.snap", "securaiq.kpi.snap"],
      ["hackgpt.checklist.integrations", "securaiq.checklist.integrations"],
    ];
    for (const [from, to] of pairs) {
      if (!localStorage.getItem(to)) {
        const v = localStorage.getItem(from);
        if (v != null) localStorage.setItem(to, v);
      }
    }
  } catch (_) {
    /* ignore */
  }
})();
const settingsTrainBtn = document.getElementById("settingsTrainBtn");
const hermesRefreshStatusBtn = document.getElementById("hermesRefreshStatus");
const finetuneHint = document.getElementById("finetuneHint");
const lanTipEl = document.getElementById("lanTip");
const menuToggle = document.getElementById("menuToggle");
const sidebarEl = document.getElementById("sidebar");
const sidebarBackdrop = document.getElementById("sidebarBackdrop");
const controlsEl = document.getElementById("controls");
const quickEl = document.getElementById("quickPrompts");
const emptyStateEl = document.getElementById("emptyState");
const newChatBtn = document.getElementById("newChatBtn");
const chatListEl = document.getElementById("chatList");
const topbarChatTitleEl = document.getElementById("topbarChatTitle");
const topbarModeEl = document.getElementById("topbarMode");
const themeToggleBtn = document.getElementById("themeToggle");
const themeToggleTopBtn = document.getElementById("themeToggleTop");
const themeToggleLabel = document.getElementById("themeToggleLabel");
const metaThemeColor = document.getElementById("metaThemeColor");
const ragEl = document.getElementById("useRag");
const webSearchEl = document.getElementById("useWebSearch");
const netAssessEl = document.getElementById("useNetAssess");
const localToolsEl = document.getElementById("useLocalTools");
const authorizedTargetEl = document.getElementById("authorizedTarget");
const targetIpEl = document.getElementById("targetIp");
const scanTargetIpEl = document.getElementById("scanTargetIp");
const scanAuthorizedEl = document.getElementById("scanAuthorized");

function syncScanTargetFields(fromScanBar) {
  if (fromScanBar) {
    if (scanTargetIpEl && targetIpEl) targetIpEl.value = scanTargetIpEl.value;
    if (scanAuthorizedEl && authorizedTargetEl) authorizedTargetEl.checked = scanAuthorizedEl.checked;
  } else {
    if (scanTargetIpEl && targetIpEl) scanTargetIpEl.value = targetIpEl.value || "";
    if (scanAuthorizedEl && authorizedTargetEl) scanAuthorizedEl.checked = !!authorizedTargetEl.checked;
  }
}

function getScanTarget() {
  syncScanTargetFields(true);
  return (scanTargetIpEl?.value || targetIpEl?.value || "").trim();
}

function getScanAuthorized() {
  syncScanTargetFields(true);
  if (scanAuthorizedEl) return !!scanAuthorizedEl.checked;
  return !!(authorizedTargetEl && authorizedTargetEl.checked);
}

function setScanTarget(path, authorized) {
  const t = (path || "").trim();
  if (scanTargetIpEl) scanTargetIpEl.value = t;
  if (targetIpEl) targetIpEl.value = t;
  if (typeof authorized === "boolean") {
    if (scanAuthorizedEl) scanAuthorizedEl.checked = authorized;
    if (authorizedTargetEl) authorizedTargetEl.checked = authorized;
  }
  syncScanTargetFields(true);
}

window.getScanTarget = getScanTarget;
window.getScanAuthorized = getScanAuthorized;
window.setScanTarget = setScanTarget;
const toolsStatusEl = document.getElementById("toolsStatus");
const statusEl = document.getElementById("status");
const liveBarEl = document.getElementById("liveBar");
const livePhaseEl = document.getElementById("livePhase");
const liveMetaEl = document.getElementById("liveMeta");
const liveActivityEl = document.getElementById("liveActivity");
const engagementSelectEl = document.getElementById("engagementSelect");
const newEngagementBtn = document.getElementById("newEngagementBtn");
const authBtn = document.getElementById("authBtn");
const authModal = document.getElementById("authModal");
const authForm = document.getElementById("authForm");
const uploadBtn = document.getElementById("uploadBtn");
const fileUploadInput = document.getElementById("fileUploadInput");
const exportMdBtn = document.getElementById("exportMdBtn");
const emptyLeadEl = document.getElementById("emptyLead");
const toolsPaletteEl = document.getElementById("toolsPalette");
const toolsPaletteGridEl = document.getElementById("toolsPaletteGrid");
const toolsPaletteOutEl = document.getElementById("toolsPaletteOut");

/** Selected cyber tool ids for chat + /api/tools/run */
let selectedTools = [];
let toolsCatalogCache = [];
window.getSelectedTools = () => selectedTools.slice();
window.setSelectedTools = (ids) => {
  selectedTools = Array.isArray(ids) ? ids.filter(Boolean) : [];
  syncToolsPaletteSelection();
  updateToolsChipState();
};

/** Integrated VA — one tool replaces the old multi-scanner PT pack. */
const LIVE_SCAN_DEFAULT_TOOLS = ["combo_assessment"];

async function openNewScanModal() {
  const modal = document.getElementById("newScanModal");
  if (!modal) {
    return startLiveScan();
  }
  modal.classList.remove("hidden");
  const progress = document.getElementById("newScanProgress");
  if (progress) progress.classList.add("hidden");
  const form = document.getElementById("newScanForm");
  if (form) form.classList.remove("hidden");
  const target = document.getElementById("newScanTarget");
  const scopeEl = document.getElementById("newScanScope");
  const authEl = document.getElementById("newScanAuthorized");
  if (authEl) authEl.checked = true;
  const existing = typeof getScanTarget === "function" ? getScanTarget() : "";
  if (target && existing) target.value = existing;
  if (target && !target.value) {
    try {
      const plat = await fetch("/api/platform", { headers: authHeaders() });
      if (plat.ok) {
        const p = await plat.json();
        const urls = p.lan_urls || [];
        const share = String(p.share_url || urls[0] || "");
        let host = "";
        try {
          host = new URL(share).hostname;
        } catch {
          host = share.replace(/^https?:\/\//i, "").split(":")[0];
        }
        if (host && !host.startsWith("127.")) target.value = host;
      }
    } catch {
      /* ignore */
    }
  }
  // Seed scope from Target so Start scan does not fail on empty scope.
  if (scopeEl && target?.value?.trim() && !String(scopeEl.value || "").trim()) {
    scopeEl.value = target.value.trim();
  }
  target?.focus();
  wireNewScanTargetScopeOnce();
  try {
    const res = await fetch("/api/scans/scanners", { headers: authHeaders() });
    if (res.ok) {
      const data = await res.json();
      const sel = document.getElementById("newScanScanner");
      if (sel && Array.isArray(data.scanners)) {
        const enabled = data.scanners.filter((s) => s.engine_enabled);
        const opts = [
          '<option value="combo">Combo workflow (scan → evidence → AI → triage)</option>',
          '<option value="all">All available scanners</option>',
          ...enabled.map((s) => {
            const builtIn = s.origin === "securaiq" || s.id === "zap" || s.id === "securaiq";
            const label = s.available
              ? s.name
              : builtIn
                ? `${s.name} (built-in)`
                : `${s.name} (not installed)`;
            const dis = s.available || builtIn ? "" : " disabled";
            return `<option value="${s.id}"${dis}>${label}</option>`;
          }),
        ];
        sel.innerHTML = opts.join("");
        // Prefer combo workflow; fall back to nmap / securaiq.
        const preferCombo = true;
        if (preferCombo) {
          sel.value = "combo";
          const vulnProf = document.querySelector('input[name="scanProfile"][value="vulnerability"]');
          if (vulnProf) vulnProf.checked = true;
        } else {
          const prefer =
            enabled.find((s) => s.id === "nmap" && s.available) ||
            enabled.find((s) => s.id === "securaiq" && s.available) ||
            enabled.find((s) => s.available);
          sel.value = prefer ? prefer.id : "all";
        }
        const hint = document.getElementById("newScanScannerHint");
        const prof =
          document.querySelector('input[name="scanProfile"]:checked')?.value || "vulnerability";
        if (hint) {
          if (sel.value === "combo") {
            refreshComboScannerHint(prof);
          } else {
            const nmap = enabled.find((s) => s.id === "nmap");
            if (nmap && !nmap.available && /npcap/i.test(String(nmap.detail || ""))) {
              hint.textContent =
                "Nmap is installed but needs Npcap (https://npcap.com) before live scans work. Use SecuraIQ builtin until then.";
            } else if (nmap && !nmap.available) {
              hint.textContent = String(nmap.detail || "Nmap not available — using SecuraIQ builtin.");
            } else {
              hint.textContent = "";
            }
          }
        }
        if (!window.__securaiqComboHintBound) {
          window.__securaiqComboHintBound = true;
          sel?.addEventListener("change", () => {
            const p = document.querySelector('input[name="scanProfile"]:checked')?.value || "discovery";
            refreshComboScannerHint(p);
          });
          document.querySelectorAll('input[name="scanProfile"]').forEach((el) => {
            el.addEventListener("change", () => {
              if (document.getElementById("newScanScanner")?.value === "combo") {
                refreshComboScannerHint(el.value);
              }
            });
          });
        }
      }
    }
  } catch (_) {
    /* keep HTML defaults */
  }
}
window.openNewScanModal = openNewScanModal;

function wireNewScanTargetScopeOnce() {
  if (window.__securaiqNewScanScopeWired) return;
  window.__securaiqNewScanScopeWired = true;
  const target = document.getElementById("newScanTarget");
  const scopeEl = document.getElementById("newScanScope");
  if (!target || !scopeEl) return;
  const syncScopeFromTarget = () => {
    const t = (target.value || "").trim();
    if (!t) return;
    const scopeEmpty = !String(scopeEl.value || "").trim();
    // Keep scope in sync when it was empty or still equal to the previous target seed.
    if (scopeEmpty || scopeEl.dataset.seededFrom === scopeEl.dataset.lastTarget) {
      scopeEl.value = t;
      scopeEl.dataset.seededFrom = t;
    }
    scopeEl.dataset.lastTarget = t;
  };
  target.addEventListener("change", syncScopeFromTarget);
  target.addEventListener("blur", syncScopeFromTarget);
}

async function startLiveScan() {
  showView("chat");
  if (typeof openAiTab === "function") openAiTab("chat");
  if (authorizedTargetEl) authorizedTargetEl.checked = true;
  if (scanAuthorizedEl) scanAuthorizedEl.checked = true;
  if (localToolsEl) localToolsEl.checked = true;
  selectedTools = LIVE_SCAN_DEFAULT_TOOLS.slice();
  const engineSel = document.getElementById("toolsEngineScanner");
  if (engineSel) engineSel.value = "combo";
  openToolsPalette(true);
  syncScanTargetFields(false);
  await renderToolsPalette();
  syncToolsPaletteSelection();
  updateToolsChipState();
  const hint = document.getElementById("toolsPaletteHint");
  if (hint) {
    hint.textContent = "Tools hub · engine scan + PT pack + SIEM/inventory from one place";
  }
  const focusEl = scanTargetIpEl || targetIpEl;
  focusEl?.focus();
}
window.startLiveScan = startLiveScan;

function toolsHubTargetAuth() {
  syncScanTargetFields(true);
  return { target: getScanTarget(), authorized: getScanAuthorized() };
}

async function queueEngineScanFromTools(opts = {}) {
  const { target, authorized } = toolsHubTargetAuth();
  const scanner =
    opts.scanner || document.getElementById("toolsEngineScanner")?.value || "combo";
  const profile =
    opts.profile || document.getElementById("toolsEngineProfile")?.value || "discovery";
  if (scanner === "none") {
    return { skipped: true, reason: "engine_off" };
  }
  if (!target) {
    throw new Error("Set a Target (owned IP/host or local path) before running Integrated VA.");
  }
  if (!authorized) {
    throw new Error("Check Auth before running Integrated VA on this target.");
  }
  if (authorizedTargetEl) authorizedTargetEl.checked = true;
  if (targetIpEl) targetIpEl.value = target;
  const scopeRaw = document.getElementById("newScanScope")?.value || "";
  let scope = scopeRaw
    .split(/[\n,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (!scope.length) scope = [target];
  if (scanner === "combo") {
    const pack = await submitComboAssessment({
      target,
      authorized,
      profile,
      scopeRaw: scope.join("\n"),
      openModal: false,
    });
    if (toolsPaletteOutEl) {
      toolsPaletteOutEl.classList.remove("hidden");
      toolsPaletteOutEl.textContent = `Integrated VA complete · findings=${pack.findings_count ?? "—"}`;
    }
    return { ok: true, combo: pack, scan_ids: pack.scan_ids || [] };
  }
  const body = {
    target,
    scanner,
    profile,
    authorized: true,
    scope,
    engagement_id: engagementSelectEl?.value || null,
  };
  const res = await fetch("/api/scans", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    let detail = data.detail || `HTTP ${res.status}`;
    if (typeof detail !== "string") detail = JSON.stringify(detail);
    throw new Error(detail);
  }
  const scanIds = Array.isArray(data.scans)
    ? data.scans.map((s) => s.scan_id).filter(Boolean)
    : data.scan_id
      ? [data.scan_id]
      : [];
  if (!scanIds.length) throw new Error("No scan_id returned");
  if (toolsPaletteOutEl) {
    toolsPaletteOutEl.classList.remove("hidden");
    toolsPaletteOutEl.textContent = `Engine scan queued (${scanner}/${profile}): ${scanIds.join(", ")}`;
  }
  if (typeof setLiveState === "function") {
    setLiveState(
      "live-busy",
      data.scanner === "all" ? `${scanIds.length} scanners queued` : "Scan queued",
      scanIds[0]
    );
  }
  if (opts.poll !== false && typeof pollScansUntilDone === "function") {
    scanIds.forEach((id) => watchScanRealtime(id));
    await pollScansUntilDone(scanIds);
  }
  return { ok: true, scan_ids: scanIds, data };
}
window.queueEngineScanFromTools = queueEngineScanFromTools;

async function syncXdrFromTools() {
  const res = await fetch("/api/xdr/sync", { method: "POST", headers: authHeaders() });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    let detail = data.detail || `HTTP ${res.status}`;
    if (typeof detail !== "string") detail = JSON.stringify(detail);
    throw new Error(detail);
  }
  const job = data.job || data;
  const msg = `XDR sync queued${job.id ? ` · job ${job.id}` : ""}`;
  if (toolsPaletteOutEl) {
    toolsPaletteOutEl.classList.remove("hidden");
    toolsPaletteOutEl.textContent = msg;
  }
  if (typeof notifyUser === "function") notifyUser(`**${msg}**`);
  return data;
}
window.syncXdrFromTools = syncXdrFromTools;

async function syncTheHiveFromTools() {
  const res = await fetch("/api/thehive/sync", { method: "POST", headers: authHeaders() });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    let detail = data.detail || `HTTP ${res.status}`;
    if (typeof detail !== "string") detail = JSON.stringify(detail);
    throw new Error(detail);
  }
  const job = data.job || data;
  const msg = `TheHive sync queued${job.id ? ` · job ${job.id}` : ""}`;
  if (toolsPaletteOutEl) {
    toolsPaletteOutEl.classList.remove("hidden");
    toolsPaletteOutEl.textContent = msg;
  }
  if (typeof notifyUser === "function") notifyUser(`**${msg}**`);
  return data;
}
window.syncTheHiveFromTools = syncTheHiveFromTools;

async function runSocPackFromTools() {
  const notes = [];
  try {
    const [siemRes, xdrRes, thRes] = await Promise.all([
      fetch("/api/siem/status", { headers: authHeaders() }).catch(() => null),
      fetch("/api/xdr/status", { headers: authHeaders() }).catch(() => null),
      fetch("/api/thehive/status", { headers: authHeaders() }).catch(() => null),
    ]);
    const siem = siemRes?.ok ? await siemRes.json().catch(() => ({})) : {};
    const xdr = xdrRes?.ok ? await xdrRes.json().catch(() => ({})) : {};
    const th = thRes?.ok ? await thRes.json().catch(() => ({})) : {};
    if (siem.configured) {
      await syncSiemFromTools();
      notes.push("SIEM");
    }
    const vendors = xdr.vendors || {};
    if (Object.values(vendors).some((v) => v && v.configured)) {
      await syncXdrFromTools();
      notes.push("XDR");
    }
    if (th.configured) {
      await syncTheHiveFromTools();
      notes.push("TheHive");
    }
  } catch (err) {
    if (typeof notifyUser === "function") notifyUser(`**SOC sync error:** ${err.message || err}`);
  }
  try {
    await syncInventoryFromTools();
    notes.push("inventory");
  } catch (err) {
    if (typeof notifyUser === "function") notifyUser(`**Inventory sync error:** ${err.message || err}`);
  }
  return notes;
}
window.runSocPackFromTools = runSocPackFromTools;

async function syncAllAndRebuildSoftware(opts) {
  opts = opts || {};
  const statusEl = opts.statusEl || document.getElementById("softwarePageBody");
  const setStatus = (msg) => {
    if (statusEl && !opts.quiet) statusEl.innerHTML = `<p class="hint" aria-live="polite">${escapeHtml(msg)}</p>`;
  };
  window.__securaiqSoftwareSyncBusy = true;
  if (typeof window.setSoftwareSyncLive === "function") {
    window.setSoftwareSyncLive("Syncing all sources and rebuilding software inventory…", true);
  }
  setStatus("Syncing all sources (SIEM, XDR, inventory) and rebuilding software inventory…");
  try {
    const res = await fetch("/api/software/sync-all", { method: "POST", headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    const jobs = data.jobs_queued || [];
    if (jobs.length) {
      setStatus(`Waiting for ${jobs.length} background sync job(s)…`);
      if (typeof window.setSoftwareSyncLive === "function") {
        window.setSoftwareSyncLive(`Waiting for ${jobs.length} background sync job(s)…`, true);
      }
      for (const j of jobs) {
        if (j.id && typeof waitForJob === "function") {
          await waitForJob(j.id, { timeoutMs: 180000, intervalMs: 1500 });
        }
      }
      setStatus("Final rebuild after sync jobs…");
      if (typeof window.setSoftwareSyncLive === "function") {
        window.setSoftwareSyncLive("Final rebuild after sync jobs…", true);
      }
      const res2 = await fetch("/api/software/rebuild", { method: "POST", headers: authHeaders() });
      const data2 = await res2.json().catch(() => ({}));
      if (!res2.ok) throw new Error(data2.detail || `HTTP ${res2.status}`);
    }
    const probe = data.local_os_patches?.probe || {};
    const pending = Number(probe.pending_count || 0);
    const parts = [
      jobs.length ? `${jobs.length} sync job(s)` : null,
      pending ? `${pending} local OS update(s) pending` : "local OS patch check done",
    ].filter(Boolean);
    if (typeof notifyUser === "function") {
      notifyUser(`**Software inventory synced** — ${parts.join(" · ")}`);
    }
    if (typeof window.renderSoftwarePage === "function") window.renderSoftwarePage({ quiet: !!opts.quiet });
    if (typeof refreshMcSoftwareFromPush === "function") {
      refreshMcSoftwareFromPush(data.posture || {});
    } else if (typeof loadCommandCenter === "function") loadCommandCenter();
    if (typeof window.renderAssetsPage === "function") window.renderAssetsPage({ quiet: true });
    if (typeof window.pulseSoftwareFromPush === "function") {
      const p = data.posture || {};
      window.pulseSoftwareFromPush({
        type: "software_inventory",
        action: "sync",
        message: `Sync complete · ${parts.join(" · ")}`,
        ts: Date.now() / 1000,
        issues: p.issues,
        health_score: p.health_score,
        needs_update: (p.server_summary || {}).needs_update,
        up_to_date: (p.server_summary || {}).up_to_date,
        total_products: p.total_products,
      });
    }
    return data;
  } catch (err) {
    const msg = err.message || String(err);
    if (statusEl && !opts.quiet) {
      statusEl.innerHTML = `<div class="sw-empty-state"><p class="hint">Sync failed: ${escapeHtml(msg)}</p>
        <button type="button" class="btn-secondary" id="softwareSyncRetry">Retry</button></div>`;
      document.getElementById("softwareSyncRetry")?.addEventListener("click", () => syncAllAndRebuildSoftware(opts));
    }
    if (typeof notifyUser === "function") notifyUser(`**Sync all failed:** ${msg}`);
    throw err;
  } finally {
    window.__securaiqSoftwareSyncBusy = false;
    if (typeof window.setSoftwareSyncLive === "function") {
      window.setSoftwareSyncLive("", false);
    }
  }
}
window.syncAllAndRebuildSoftware = syncAllAndRebuildSoftware;
window.runSoftwareSyncAll = syncAllAndRebuildSoftware;

async function syncSiemFromTools() {
  const res = await fetch("/api/siem/sync", { method: "POST", headers: authHeaders() });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    let detail = data.detail || `HTTP ${res.status}`;
    if (typeof detail !== "string") detail = JSON.stringify(detail);
    throw new Error(detail);
  }
  const job = data.job || data;
  const msg = `SIEM sync queued${job.id ? ` · job ${job.id}` : ""}`;
  if (toolsPaletteOutEl) {
    toolsPaletteOutEl.classList.remove("hidden");
    toolsPaletteOutEl.textContent = msg;
  }
  if (typeof notifyUser === "function") notifyUser(`**${msg}**`);
  return data;
}
window.syncSiemFromTools = syncSiemFromTools;

async function syncInventoryFromTools() {
  const out = (msg) => {
    if (toolsPaletteOutEl) {
      toolsPaletteOutEl.classList.remove("hidden");
      toolsPaletteOutEl.textContent = msg;
    }
    if (typeof notifyUser === "function") notifyUser(`**${msg}**`);
  };
  const res = await fetch("/api/assets/lan-refresh?scans=false", { method: "POST", headers: authHeaders() });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    let detail = data.detail || `HTTP ${res.status}`;
    if (typeof detail !== "string") detail = JSON.stringify(detail);
    throw new Error(detail);
  }
  const invJob = data.inventory_job || {};
  const n = 1 + (data.neighbors || []).length;
  out(`Live inventory queued · ${n} host(s) · subnet ${data.subnet || "local /24"}${invJob.id ? ` · job ${invJob.id}` : ""}`);
  if (invJob.id && typeof window.waitForJob === "function") {
    const job = await window.waitForJob(invJob.id, { timeoutMs: 180000 });
    const r = job?.result || {};
    const st = (job?.status || "").toLowerCase();
    if (st === "done") {
      out(`Inventory done · ${r.audited || n} host(s) audited`);
    } else if (st === "error") {
      throw new Error(job.error || "inventory failed");
    }
  }
  if (typeof window.renderAssetsPage === "function") window.renderAssetsPage({ quiet: true });
  if (typeof loadCommandCenter === "function") loadCommandCenter();
  return data;
}
window.syncInventoryFromTools = syncInventoryFromTools;

async function ensurePtPackSelected() {
  if (selectedTools.length) return selectedTools;
  try {
    const res = await fetch("/api/tools", { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    const soc = (Array.isArray(data.soc_pack) ? data.soc_pack : []).filter((id) =>
      (data.tools || []).some((t) => t.id === id && t.available)
    );
    selectedTools =
      Array.isArray(data.pt_pack) && data.pt_pack.length
        ? [...data.pt_pack, ...soc]
        : LIVE_SCAN_DEFAULT_TOOLS.slice();
  } catch {
    selectedTools = LIVE_SCAN_DEFAULT_TOOLS.slice();
  }
  syncToolsPaletteSelection();
  updateToolsChipState();
  return selectedTools;
}

async function runAllFromTools() {
  const engine = document.getElementById("toolsEngineScanner")?.value || "combo";
  await ensurePtPackSelected();
  if (engine === "combo") {
    showView("chat");
    openAiTab("chat");
    try {
      await submitComboAssessment({ openModal: false });
      await runSocPackFromTools();
    } catch (err) {
      appendMessage("assistant", renderMarkdown(`**Integrated VA failed:** ${err.message || err}`), true);
    }
    return;
  }
  const notes = [];
  const jobs = [];
  if (engine !== "none") {
    jobs.push(
      queueEngineScanFromTools({ poll: true })
        .then((queued) => {
          if (!queued.skipped) notes.push(`engine: ${(queued.scan_ids || []).join(", ")}`);
        })
        .catch((err) => {
          appendMessage(
            "assistant",
            renderMarkdown(`**Engine scan skipped:** ${err.message || err}`),
            true
          );
        })
    );
  }
  jobs.push(runSelectedTools());
  jobs.push(runSocPackFromTools().catch(() => []));
  await Promise.all(jobs);
  if (notes.length && toolsPaletteOutEl) {
    toolsPaletteOutEl.classList.remove("hidden");
    const prev = toolsPaletteOutEl.textContent || "";
    toolsPaletteOutEl.textContent = `${notes.join(" · ")}\n${prev}`.slice(0, 4000);
  }
}
window.runAllFromTools = runAllFromTools;

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

const ASSET_CATEGORY_LABELS = window.ASSET_CATEGORY_LABELS || {
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

function assetCategoryId(item) {
  return String(item?.asset_category || item?.asset_type || item?.type || "other").toLowerCase();
}

function displayCategoryLabel(item) {
  const id = assetCategoryId(item);
  return item?.category_label || ASSET_CATEGORY_LABELS[id] || id.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function categoryChipHtml(item) {
  const id = assetCategoryId(item);
  const label = displayCategoryLabel(item);
  return `<span class="category-chip category-${escapeHtml(id)}">${escapeHtml(label)}</span>`;
}
window.displayCategoryLabel = displayCategoryLabel;

function renderScanSteps(progress) {
  const ul = document.getElementById("newScanSteps");
  if (!ul) return;
  const steps = Array.isArray(progress) ? progress : [];
  ul.innerHTML = steps
    .map((s) => {
      const st = s.status || "pending";
      const mark = st === "done" ? "✓" : st === "active" ? "●" : st === "failed" ? "✗" : "○";
      return `<li class="scan-step scan-step-${st}"><span>${mark}</span> ${s.label || s.id}</li>`;
    })
    .join("");
}

const COMBO_DEFAULT_STEPS = [
  { id: "authorize", label: "Authorized", status: "done" },
  { id: "scope", label: "Scope verified", status: "done" },
  { id: "scan", label: "Scanners running", status: "active" },
  { id: "evidence", label: "Evidence pack", status: "pending" },
  { id: "investigate", label: "Investigation pack", status: "pending" },
  { id: "triage", label: "Auto-triage", status: "pending" },
];

async function refreshComboScannerHint(profile) {
  const hint = document.getElementById("newScanScannerHint");
  const sel = document.getElementById("newScanScanner");
  if (!hint || !sel || sel.value !== "combo") return;
  try {
    const res = await fetch("/api/scans/combo/scanners", { headers: authHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    const includeWeb = profile === "web" || profile === "full" || profile === "vulnerability";
    const engines = includeWeb ? data.with_web || data.core : data.core || [];
    const names = (engines || []).map((id) => {
      if (id === "zap") return "SecuraIQ Web Scanner";
      if (id === "securaiq") return "SecuraIQ";
      if (id === "nmap") return "Nmap";
      if (id === "nuclei") return "Nuclei";
      return id;
    });
    hint.textContent = names.length
      ? `Built-in live: ${names.join(" → ")} → evidence → AI investigate → triage`
      : "Built-in SecuraIQ engines — always available, no external install.";
  } catch (_) {
    /* ignore */
  }
}

async function pulseComboFromPush(push) {
  if (!push) return null;
  const watching = window.__securaiqWatchingComboJob;
  if (watching && push.job_id && String(push.job_id) !== String(watching)) return null;
  const statusLabel = document.getElementById("newScanStatusLabel");
  const summaryEl = document.getElementById("newScanSummary");
  const idLabel = document.getElementById("newScanIdLabel");
  if (push.steps && Array.isArray(push.steps)) renderScanSteps(push.steps);
  if (statusLabel && push.status) {
    const step = push.step ? ` · ${push.step}` : "";
    statusLabel.textContent = `COMBO ${String(push.status).toUpperCase()}${step}`;
  }
  if (push.scan_id) {
    watchScanRealtime(push.scan_id);
    if (idLabel) idLabel.textContent = push.scan_id;
    if (typeof pulseActiveScanFromPush === "function") {
      pulseActiveScanFromPush({ type: "scan", id: push.scan_id, step: push.step, status: push.scan_status || push.status });
    }
  }
  if (summaryEl) {
    if (push.scan_detail) summaryEl.textContent = push.scan_detail;
    else if (push.scanner) summaryEl.textContent = `Running ${push.scanner}…`;
    else if (push.step === "investigate") summaryEl.textContent = "Building investigation pack from evidence…";
    else if (push.step === "triage") summaryEl.textContent = "Auto-triaging high/critical findings…";
    else if (push.step === "evidence") summaryEl.textContent = "Collecting evidence from completed scans…";
  }
  if (push.status === "completed") {
    window.__securaiqComboCompleted = true;
    if (watching) {
      try {
        const res = await fetch(`/api/jobs/${encodeURIComponent(watching)}`, { headers: authHeaders() });
        const job = await res.json().catch(() => ({}));
        const pack = job.result || job.result_json || {};
        if (pack.ok) {
          window.__securaiqComboLastPack = pack;
          renderComboResult(pack);
          window.__securaiqWatchingComboJob = null;
          if (typeof setLiveState === "function") setLiveState("live-ok", "Combo complete", pack.primary_scan_id);
          if (typeof syncLiveWorkspace === "function") syncLiveWorkspace({ pushType: "combo" });
          return pack;
        }
      } catch (_) {
        /* poll fallback will finish */
      }
    }
  }
  return null;
}
window.pulseComboFromPush = pulseComboFromPush;

function watchScanRealtime(scanId) {
  if (!scanId) return;
  window.__securaiqWatchingScans = window.__securaiqWatchingScans || new Set();
  window.__securaiqWatchingScans.add(String(scanId));
}

function unwatchScanRealtime(scanId) {
  window.__securaiqWatchingScans?.delete(String(scanId));
}

async function applyScanRecordToUi(scan) {
  if (!scan || !scan.id) return scan;
  const statusLabel = document.getElementById("newScanStatusLabel");
  const idLabel = document.getElementById("newScanIdLabel");
  const summaryEl = document.getElementById("newScanSummary");
  const progressEl = document.getElementById("newScanProgress");
  const form = document.getElementById("newScanForm");
  if (form) form.classList.add("hidden");
  if (progressEl) progressEl.classList.remove("hidden");
  if (idLabel) idLabel.textContent = scan.id;
  if (statusLabel) statusLabel.textContent = (scan.status || "").toUpperCase();
  renderScanSteps(scan.progress);
  const terminal = ["completed", "failed", "blocked"].includes(scan.status);
  if (terminal && summaryEl) {
    const sum = scan.summary || {};
    if (scan.status === "completed") {
      const reportUrl = sum.report_url || `/api/scans/${encodeURIComponent(scan.id)}/report`;
      const pdfUrl = sum.report_pdf_url || `/api/scans/${encodeURIComponent(scan.id)}/report.pdf`;
      summaryEl.innerHTML = `Open ports: ${sum.open_ports ?? "—"} · Findings: ${sum.findings_created ?? sum.findings ?? "—"} · Risk: ${
        sum.risk?.score != null ? `${sum.risk.score} (${sum.risk.band || "—"})` : "—"
      } · Asset linked<br/>
        <button type="button" class="cc-action" id="newScanOpenReport" data-href="${reportUrl}">Download MD report</button>
        <button type="button" class="cc-action" id="newScanOpenPdf" data-href="${pdfUrl}">Download PDF report</button>
        <button type="button" class="cc-action" data-workspace="reports" id="newScanGotoReports">Open Reports</button>
        <button type="button" class="cc-action" data-workspace="vulns" id="newScanGotoVulns">View findings</button>
        <button type="button" class="cc-action" data-workspace="assets" id="newScanGotoAssets">View assets</button>
        <button type="button" class="cc-action" id="newScanAskAi">Ask AI (from evidence)</button>`;
      document.getElementById("newScanGotoAssets")?.addEventListener("click", () => {
        document.getElementById("newScanModal")?.classList.add("hidden");
        if (typeof window.showWorkspace === "function") window.showWorkspace("assets");
      });
      document.getElementById("newScanGotoReports")?.addEventListener("click", () => {
        document.getElementById("newScanModal")?.classList.add("hidden");
        if (typeof window.showWorkspace === "function") window.showWorkspace("reports");
      });
      document.getElementById("newScanGotoVulns")?.addEventListener("click", () => {
        document.getElementById("newScanModal")?.classList.add("hidden");
        if (typeof window.showWorkspace === "function") window.showWorkspace("vulns");
      });
      document.getElementById("newScanAskAi")?.addEventListener("click", () => {
        document.getElementById("newScanModal")?.classList.add("hidden");
        if (typeof window.askAboutScan === "function") {
          window.askAboutScan(scan.id, sum);
        }
      });
      const dl = document.getElementById("newScanOpenReport");
      dl?.addEventListener("click", async () => {
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
          alert(err.message || "Report download failed");
        }
      });
      document.getElementById("newScanOpenPdf")?.addEventListener("click", async () => {
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
          alert(err.message || "PDF download failed");
        }
      });
    } else {
      summaryEl.textContent = scan.error || scan.status;
    }
  }
  if (terminal) {
    unwatchScanRealtime(scan.id);
    if (typeof syncLiveWorkspace === "function") {
      syncLiveWorkspace({ pushType: "scan" });
    }
  }
  return scan;
}

async function pulseActiveScanFromPush(push) {
  const scanId = push && push.id ? String(push.id) : "";
  if (!scanId || !window.__securaiqWatchingScans?.has(scanId)) return null;
  try {
    const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}`, { headers: authHeaders() });
    if (!res.ok) return null;
    const scan = await res.json();
    return applyScanRecordToUi(scan);
  } catch {
    return null;
  }
}
window.pulseActiveScanFromPush = pulseActiveScanFromPush;

async function pollScanUntilDone(scanId) {
  watchScanRealtime(scanId);
  const progressEl = document.getElementById("newScanProgress");
  const form = document.getElementById("newScanForm");
  const statusLabel = document.getElementById("newScanStatusLabel");
  const idLabel = document.getElementById("newScanIdLabel");
  const summaryEl = document.getElementById("newScanSummary");
  if (form) form.classList.add("hidden");
  if (progressEl) progressEl.classList.remove("hidden");
  if (idLabel) idLabel.textContent = scanId;
  for (let i = 0; i < 120; i++) {
    const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}`, { headers: authHeaders() });
    if (!res.ok) break;
    const scan = await res.json();
    await applyScanRecordToUi(scan);
    const terminal = ["completed", "failed", "blocked"].includes(scan.status);
    if (terminal) {
      return scan;
    }
    await new Promise((r) => setTimeout(r, 800));
  }
  unwatchScanRealtime(scanId);
  if (summaryEl) summaryEl.textContent = "Still running — check Jobs or refresh later.";
  return null;
}

/** Poll one or many queued scans (scanner=all returns scans[]). */
async function pollScansUntilDone(scanIds) {
  const ids = (Array.isArray(scanIds) ? scanIds : [scanIds]).filter(Boolean);
  if (!ids.length) return [];
  const statusLabel = document.getElementById("newScanStatusLabel");
  const idLabel = document.getElementById("newScanIdLabel");
  const summaryEl = document.getElementById("newScanSummary");
  const form = document.getElementById("newScanForm");
  const progressEl = document.getElementById("newScanProgress");
  if (form) form.classList.add("hidden");
  if (progressEl) progressEl.classList.remove("hidden");
  if (idLabel) idLabel.textContent = ids.length === 1 ? ids[0] : `${ids.length} scans`;
  const results = [];
  for (let i = 0; i < ids.length; i++) {
    if (statusLabel) statusLabel.textContent = `RUNNING ${i + 1}/${ids.length}`;
    if (summaryEl && ids.length > 1) {
      summaryEl.textContent = `Waiting on scan ${i + 1} of ${ids.length}…`;
    }
    results.push(await pollScanUntilDone(ids[i]));
  }
  if (summaryEl && ids.length > 1) {
    const done = results.filter((s) => s && s.status === "completed").length;
    const findings = results.reduce((n, s) => {
      const sum = (s && s.summary) || {};
      return n + Number(sum.findings_created ?? sum.findings ?? 0);
    }, 0);
    summaryEl.textContent = `Batch done: ${done}/${ids.length} completed · Findings: ${findings}`;
  }
  return results;
}

async function pollJobUntilDone(jobId, { timeoutMs = 300000, intervalMs = 1200, onTick, shouldStop } = {}) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (typeof shouldStop === "function" && shouldStop()) {
      return window.__securaiqComboLastPack
        ? { status: "done", result: window.__securaiqComboLastPack, result_json: window.__securaiqComboLastPack }
        : { status: "done" };
    }
    const res = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`, { headers: authHeaders() });
    const job = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(job.detail || `Job HTTP ${res.status}`);
    const st = String(job.status || "").toLowerCase();
    if (typeof onTick === "function") onTick(job);
    if (st === "done" || st === "completed") return job;
    if (st === "error" || st === "failed") {
      throw new Error(job.error || "Combo job failed");
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error("Combo workflow timed out — check Jobs for status.");
}

function renderComboResult(pack) {
  const summaryEl = document.getElementById("newScanSummary");
  const statusLabel = document.getElementById("newScanStatusLabel");
  const idLabel = document.getElementById("newScanIdLabel");
  const progressEl = document.getElementById("newScanProgress");
  const form = document.getElementById("newScanForm");
  if (form) form.classList.add("hidden");
  if (progressEl) progressEl.classList.remove("hidden");
  if (pack.steps) renderScanSteps(pack.steps);
  if (statusLabel) statusLabel.textContent = "COMBO COMPLETE";
  if (idLabel) idLabel.textContent = pack.primary_scan_id || (pack.scan_ids || [])[0] || "combo";
  if (!summaryEl) return;
  const steps = Array.isArray(pack.steps)
    ? pack.steps.map((s) => `${s.label}: ${s.status}`).join(" · ")
    : "";
  const reportUrl = pack.report_url || `/api/scans/${encodeURIComponent(pack.primary_scan_id || "")}/report`;
  const pdfUrl = pack.report_pdf_url || `/api/scans/${encodeURIComponent(pack.primary_scan_id || "")}/report.pdf`;
  summaryEl.innerHTML = `Combo: ${pack.summary?.scanners_ok ?? "—"} scanners · Findings: ${
    pack.findings_count ?? "—"
  } · High/Crit: ${pack.summary?.high_critical ?? "—"} · Triaged: ${pack.summary?.triaged ?? 0}<br/>
    <span class="hint">${steps}</span><br/>
    <button type="button" class="cc-action" id="comboOpenReport" data-href="${reportUrl}">Download MD report</button>
    <button type="button" class="cc-action" id="comboOpenPdf" data-href="${pdfUrl}">Download PDF</button>
    <button type="button" class="cc-action" data-workspace="vulns" id="comboGotoVulns">View findings</button>
    <button type="button" class="cc-action" id="comboAskAi">Ask AI (from evidence)</button>`;
  document.getElementById("comboGotoVulns")?.addEventListener("click", () => {
    document.getElementById("newScanModal")?.classList.add("hidden");
    if (typeof window.showWorkspace === "function") window.showWorkspace("vulns");
  });
  document.getElementById("comboAskAi")?.addEventListener("click", () => {
    document.getElementById("newScanModal")?.classList.add("hidden");
    if (pack.prompt && typeof window.runNavPrompt === "function") {
      window.runNavPrompt("assess", pack.prompt, { stay: true });
    } else if (pack.primary_scan_id && typeof window.askAboutScan === "function") {
      window.askAboutScan(pack.primary_scan_id, pack.summary);
    }
  });
  document.getElementById("comboOpenReport")?.addEventListener("click", async () => {
    try {
      if (typeof downloadMd === "function") {
        await downloadMd(reportUrl, `securaiq-combo-${String(pack.primary_scan_id || "run").slice(0, 8)}.md`);
      }
    } catch (_) {
      /* ignore */
    }
  });
  document.getElementById("comboOpenPdf")?.addEventListener("click", () => {
    window.open(pdfUrl, "_blank");
  });
}

async function submitComboAssessment(opts = {}) {
  const target =
    opts.target ||
    document.getElementById("newScanTarget")?.value?.trim() ||
    (typeof getScanTarget === "function" ? getScanTarget() : "");
  const authorized =
    opts.authorized != null
      ? !!opts.authorized
      : !!document.getElementById("newScanAuthorized")?.checked;
  const profile =
    opts.profile ||
    document.querySelector('input[name="scanProfile"]:checked')?.value ||
    "discovery";
  const scopeRaw = opts.scopeRaw != null ? opts.scopeRaw : document.getElementById("newScanScope")?.value || "";
  let scope = String(scopeRaw)
    .split(/[\n,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (!scope.length && target) {
    scope = [target];
    const scopeEl = document.getElementById("newScanScope");
    if (scopeEl && !String(scopeEl.value || "").trim()) scopeEl.value = target;
  }
  const autoTriage =
    opts.auto_triage_high != null
      ? !!opts.auto_triage_high
      : document.getElementById("newScanAutoTriage")?.checked !== false;
  if (!target) {
    alert("Enter a target hostname or IP you are authorized to assess.");
    return;
  }
  if (!authorized) {
    alert("Confirm authorization before starting the combo workflow.");
    return;
  }
  if (!scope.length) {
    alert("Combo requires structured scope (host, IP, or CIDR).");
    return;
  }
  const modal = document.getElementById("newScanModal");
  if (modal && opts.openModal !== false) {
    modal.classList.remove("hidden");
    const form = document.getElementById("newScanForm");
    const progressEl = document.getElementById("newScanProgress");
    if (form) form.classList.add("hidden");
    if (progressEl) progressEl.classList.remove("hidden");
  }
  const statusLabel = document.getElementById("newScanStatusLabel");
  const summaryEl = document.getElementById("newScanSummary");
  if (statusLabel) statusLabel.textContent = "COMBO QUEUED";
  if (summaryEl) summaryEl.textContent = "Running combo: scan → evidence → investigate → triage…";
  const btn = document.getElementById("newScanStart");
  if (btn) btn.disabled = true;
  try {
    const body = {
      target,
      profile,
      authorized: true,
      scope,
      engagement_id: typeof engagementSelectEl !== "undefined" ? engagementSelectEl?.value || null : null,
      include_web: profile === "web" || profile === "full" || profile === "vulnerability",
      auto_triage_high: autoTriage,
      async_mode: true,
    };
    const res = await fetch("/api/scans/combo", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      let detail = data.detail || `HTTP ${res.status}`;
      if (typeof detail !== "string") detail = JSON.stringify(detail);
      throw new Error(detail);
    }
    if (data.ok && data.workflow === "combo_assessment") {
      renderComboResult(data);
      return data;
    }
    const jobId = data.job_id;
    if (!jobId) throw new Error("No combo job_id returned");
    window.__securaiqWatchingComboJob = jobId;
    window.__securaiqComboCompleted = false;
    window.__securaiqComboLastPack = null;
    renderScanSteps(COMBO_DEFAULT_STEPS);
    if (Array.isArray(data.scanners) && data.scanners.length && summaryEl) {
      summaryEl.textContent = `Queued · live engines: ${data.scanners.join(" → ")}`;
    }
    if (typeof setLiveState === "function") setLiveState("live-busy", "Combo workflow", jobId);
    const pollMs = window.__securaiqEsConnected ? 4000 : 1500;
    const job = await pollJobUntilDone(jobId, {
      intervalMs: pollMs,
      onTick: (j) => {
        if (statusLabel) statusLabel.textContent = `COMBO ${(j.status || "").toUpperCase()}`;
        if (j.status === "running" && summaryEl && !window.__securaiqComboCompleted) {
          summaryEl.textContent = "Combo running — live step updates via SSE…";
        }
      },
      shouldStop: () => window.__securaiqComboCompleted,
    });
    if (window.__securaiqComboLastPack?.ok) {
      window.__securaiqWatchingComboJob = null;
      return window.__securaiqComboLastPack;
    }
    const pack = job.result || job.result_json || {};
    if (!pack.ok) throw new Error(pack.error || "Combo finished without a pack");
    renderComboResult(pack);
    window.__securaiqWatchingComboJob = null;
    if (typeof setLiveState === "function") setLiveState("live-ok", "Combo complete", pack.primary_scan_id);
    if (typeof syncLiveWorkspace === "function") syncLiveWorkspace({ pushType: "combo" });
    return pack;
  } catch (err) {
    if (summaryEl) summaryEl.textContent = String(err.message || err);
    if (statusLabel) statusLabel.textContent = "COMBO FAILED";
    alert(String(err.message || err));
    throw err;
  } finally {
    if (btn) btn.disabled = false;
  }
}
window.submitComboAssessment = submitComboAssessment;

async function submitNewScan(ev) {
  ev?.preventDefault?.();
  const targetEl = document.getElementById("newScanTarget");
  const scopeEl = document.getElementById("newScanScope");
  const authEl = document.getElementById("newScanAuthorized");
  let target = targetEl?.value?.trim() || "";
  let scopeRaw = scopeEl?.value || "";
  // If user only filled Target (common), use it as structured scope.
  if (target && !String(scopeRaw).trim()) {
    scopeRaw = target;
    if (scopeEl) scopeEl.value = target;
  }
  // If only Scope filled, use first line as Target.
  if (!target && String(scopeRaw).trim()) {
    target = String(scopeRaw)
      .split(/[\n,;]+/)
      .map((s) => s.trim())
      .filter(Boolean)[0] || "";
    if (targetEl && target) targetEl.value = target;
  }
  const authorized = !!authEl?.checked;
  const scanner = document.getElementById("newScanScanner")?.value || "securaiq";
  const profile =
    document.querySelector('input[name="scanProfile"]:checked')?.value || "discovery";
  const scope = scopeRaw
    .split(/[\n,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (!target) {
    alert("Enter a target hostname or IP you are authorized to scan.");
    targetEl?.focus();
    return;
  }
  if (!authorized) {
    alert("Confirm authorization before starting a scan.");
    authEl?.focus();
    return;
  }
  const needsScope =
    scanner === "combo" ||
    scanner === "nmap" ||
    scanner === "nuclei" ||
    scanner === "zap" ||
    scanner === "all" ||
    profile === "vulnerability" ||
    profile === "full";
  if (needsScope && !scope.length) {
    alert("Add at least one host/IP/CIDR in Scope (or put it in Target).");
    scopeEl?.focus();
    return;
  }
  if (scanner === "combo") {
    const form = document.getElementById("newScanForm");
    const progressEl = document.getElementById("newScanProgress");
    if (form) form.classList.add("hidden");
    if (progressEl) progressEl.classList.remove("hidden");
    await submitComboAssessment({ target, authorized, profile, scopeRaw, openModal: false });
    return;
  }
  const btn = document.getElementById("newScanStart");
  if (btn) btn.disabled = true;
  const form = document.getElementById("newScanForm");
  const progressEl = document.getElementById("newScanProgress");
  const statusLabel = document.getElementById("newScanStatusLabel");
  const summaryEl = document.getElementById("newScanSummary");
  if (form) form.classList.add("hidden");
  if (progressEl) progressEl.classList.remove("hidden");
  if (statusLabel) statusLabel.textContent = "QUEUED";
  if (summaryEl) summaryEl.textContent = `Starting ${scanner} · ${profile} on ${target}…`;
  try {
    const body = {
      target,
      scanner,
      profile,
      authorized: true,
      scope,
      engagement_id: engagementSelectEl?.value || null,
    };
    const res = await fetch("/api/scans", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      let detail = data.detail || `HTTP ${res.status}`;
      if (typeof detail !== "string") detail = JSON.stringify(detail);
      if (res.status === 405) {
        detail =
          "Scan API not loaded (Method Not Allowed). Restart the SecuraIQ server (python run.py), then hard-refresh the page.";
      }
      throw new Error(detail);
    }
    const scanIds = Array.isArray(data.scans)
      ? data.scans.map((s) => s.scan_id).filter(Boolean)
      : data.scan_id
        ? [data.scan_id]
        : [];
    if (!scanIds.length) throw new Error("No scan_id returned");
    if (typeof setLiveState === "function") {
      const label =
        data.scanner === "all"
          ? `${scanIds.length} scanners queued`
          : "Scan queued";
      setLiveState("live-busy", label, scanIds[0]);
    }
    if (summaryEl) {
      summaryEl.textContent =
        data.scanner === "all"
          ? `Queued ${scanIds.length} scanner(s) for ${target}`
          : `Queued ${scanner} for ${target}`;
    }
    await pollScansUntilDone(scanIds);
  } catch (err) {
    if (progressEl) progressEl.classList.remove("hidden");
    if (summaryEl) summaryEl.textContent = String(err.message || err);
    if (statusLabel) statusLabel.textContent = "FAILED";
    alert(String(err.message || err));
  } finally {
    if (btn) btn.disabled = false;
  }
}

function bindNewScanModal() {
  const modal = document.getElementById("newScanModal");
  if (!modal) return;
  on(document.getElementById("newScanClose"), "click", () => modal.classList.add("hidden"));
  on(modal, "click", (e) => {
    if (e.target === modal) modal.classList.add("hidden");
  });
  on(document.getElementById("newScanForm"), "submit", submitNewScan);
  on(document.getElementById("newScanAdvanced"), "click", () => {
    modal.classList.add("hidden");
    startLiveScan();
  });
}

const attachBtn = document.getElementById("attachBtn");
const chatAttachInput = document.getElementById("chatAttachInput");
const attachChipsEl = document.getElementById("attachChips");
const composerEl = document.getElementById("composer");
/** @type {{ file: File, id?: string }[]} */
let pendingAttachments = [];
const MAX_CHAT_ATTACHMENTS = 8;
const gapBtn = document.getElementById("gapBtn");
const dashboardBtn = document.getElementById("dashboardBtn");
const riskBtn = document.getElementById("riskBtn");
const vulnBtn = document.getElementById("vulnBtn");
const assetBtn = document.getElementById("assetBtn");
const remBtn = document.getElementById("remBtn");
const playbookBtn = document.getElementById("playbookBtn");
const campaignBtn = document.getElementById("campaignBtn");
const gapModal = document.getElementById("gapModal");
const gapForm = document.getElementById("gapForm");
const gapResult = document.getElementById("gapResult");
const dashModal = document.getElementById("dashModal");
const dashBody = document.getElementById("dashBody");
const riskModal = document.getElementById("riskModal");
const riskForm = document.getElementById("riskForm");
const riskList = document.getElementById("riskList");
const vulnModal = document.getElementById("vulnModal");
const vulnList = document.getElementById("vulnList");
const vulnFileInput = document.getElementById("vulnFileInput");
const assetModal = document.getElementById("assetModal");
const assetForm = document.getElementById("assetForm");
const assetList = document.getElementById("assetList");
const remModal = document.getElementById("remModal");
const remBoard = document.getElementById("remBoard");
const playbookModal = document.getElementById("playbookModal");
const playbookForm = document.getElementById("playbookForm");
const playbookList = document.getElementById("playbookList");
const campaignModal = document.getElementById("campaignModal");
const campaignForm = document.getElementById("campaignForm");
const campaignList = document.getElementById("campaignList");
const AUTH_TOKEN_KEY = "securaiq.auth.token";
let authToken = localStorage.getItem(AUTH_TOKEN_KEY) || "";
let serverChatId = null;
let authEnabled = false;
const setupPanelEl = document.getElementById("setupPanel");
const setupTitleEl = document.getElementById("setupTitle");
const setupTextEl = document.getElementById("setupText");
const setupPrimaryEl = document.getElementById("setupPrimary");
const setupDismissEl = document.getElementById("setupDismiss");
/** @type {"" | "copy" | "preload" | "settings" | "docs"} */
let setupAction = "";
let setupDismissedKey = sessionStorage.getItem("setupDismissed") || "";

const CHAT_STORE_KEY = "securaiq.chats.v1";
const CHAT_STORE_LEGACY = "hackgpt.chats.v1";
function authHeaders(extra = {}) {
  const h = { ...extra };
  if (authToken) h.Authorization = `Bearer ${authToken}`;
  return h;
}
window.authHeaders = authHeaders;

async function refreshAuthStatus() {
  try {
    const res = await fetch("/api/auth/status", { headers: authHeaders() });
    const data = await res.json();
    authEnabled = Boolean(data.auth_enabled);
    window.__securaiqUser = data.user?.username || "";
    const hint = document.getElementById("authStatusHint");
    const oidcBtn = document.getElementById("authOidcBtn");
    if (oidcBtn) {
      oidcBtn.classList.toggle("hidden", !data.oidc_enabled);
    }
    if (hint) {
      if (!authEnabled) hint.textContent = "Auth disabled (open local mode). Enable AUTH_ENABLED for team use.";
      else if (data.user) {
        const mfaNote = data.mfa?.enabled ? " · MFA on" : data.mfa_enrollment_required ? " · enroll MFA (admin)" : "";
        hint.textContent = `Signed in as ${data.user.username} (${data.user.role})${mfaNote}`;
      } else hint.textContent = data.oidc_enabled ? "Auth required — login, SSO, or register." : "Auth required — login or register.";
    }
    if (authBtn) authBtn.textContent = data.user && authEnabled ? `Account (${data.user.username})` : "Account";
    refreshMfaAccountPanel(data);
  } catch {
    /* ignore */
  }
}

async function refreshMfaAccountPanel(cached) {
  const hint = document.getElementById("mfaAccountHint");
  const enrollBtn = document.getElementById("mfaEnrollBtn");
  const disableBtn = document.getElementById("mfaDisableBtn");
  const enrollBlock = document.getElementById("mfaEnrollBlock");
  if (!hint) return;
  try {
    const data = cached || (await fetch("/api/auth/status", { headers: authHeaders() }).then((r) => r.json()));
    if (!data.auth_enabled) {
      hint.textContent = "Enable AUTH_ENABLED to use MFA.";
      enrollBtn?.classList.add("hidden");
      disableBtn?.classList.add("hidden");
      enrollBlock?.classList.add("hidden");
      return;
    }
    if (!data.user) {
      hint.textContent = "Sign in (Account) to manage two-factor authentication.";
      enrollBtn?.classList.add("hidden");
      disableBtn?.classList.add("hidden");
      enrollBlock?.classList.add("hidden");
      return;
    }
    if (data.mfa?.enabled) {
      hint.textContent = "MFA is enabled on your account.";
      enrollBtn?.classList.add("hidden");
      disableBtn?.classList.remove("hidden");
      enrollBlock?.classList.add("hidden");
    } else if (data.mfa?.enrolled) {
      hint.textContent = "Finish enrollment — enter a code from your authenticator.";
      enrollBtn?.classList.add("hidden");
      disableBtn?.classList.add("hidden");
      enrollBlock?.classList.remove("hidden");
    } else {
      hint.textContent = "Protect your account with TOTP (Google Authenticator, 1Password, etc.).";
      enrollBtn?.classList.remove("hidden");
      disableBtn?.classList.add("hidden");
      enrollBlock?.classList.add("hidden");
    }
  } catch {
    /* ignore */
  }
}

function openAuth() {
  authModal?.classList.remove("hidden");
  refreshAuthStatus();
}
function closeAuth() {
  authModal?.classList.add("hidden");
}

async function loadEngagements() {
  if (!engagementSelectEl) return;
  try {
    const res = await fetch("/api/engagements", { headers: authHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    const cur = engagementSelectEl.value;
    engagementSelectEl.innerHTML = '<option value="">Local (no engagement)</option>';
    for (const e of data.engagements || []) {
      const opt = document.createElement("option");
      opt.value = e.id;
      const status = e.status && e.status !== "active" ? ` (${e.status})` : "";
      opt.textContent = `${e.name}${status}`;
      engagementSelectEl.appendChild(opt);
    }
    if (cur) engagementSelectEl.value = cur;
  } catch {
    /* ignore */
  }
}

async function ensureServerChat() {
  if (serverChatId) return serverChatId;
  const body = {
    title: "New chat",
    mode: modeEl?.value || "default",
    engagement_id: engagementSelectEl?.value || null,
  };
  const res = await fetch("/api/chats", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  if (!res.ok) return null;
  const chat = await res.json();
  serverChatId = chat.id;
  return serverChatId;
}

async function createEngagement() {
  const name = prompt("Engagement name (e.g. HTB lab / Client ACME)");
  if (!name) return;
  const scope = prompt("Scope notes (authorized targets / VPN)") || "";
  const res = await fetch("/api/engagements", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ name, scope_notes: scope }),
  });
  if (!res.ok) {
    appendMessage("assistant", renderMarkdown(`**Engagement failed:** HTTP ${res.status}`), true);
    return;
  }
  const eng = await res.json();
  await loadEngagements();
  if (engagementSelectEl) engagementSelectEl.value = eng.id;
  appendMessage("assistant", renderMarkdown(`**Engagement created:** ${eng.name}`), true);
}

async function renameEngagement() {
  const id = engagementSelectEl?.value;
  if (!id) {
    appendMessage("assistant", renderMarkdown("**Select a Project/engagement** first."), true);
    return;
  }
  const name = prompt("New engagement name:");
  if (!name?.trim()) return;
  const scope = prompt("Scope notes (leave blank to keep unchanged)") ?? "";
  try {
    const body = { name: name.trim() };
    if (scope.trim()) body.scope_notes = scope.trim();
    const res = await fetch(`/api/engagements/${id}`, {
      method: "PATCH",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    await loadEngagements();
    if (engagementSelectEl) engagementSelectEl.value = id;
    appendMessage("assistant", renderMarkdown(`**Engagement renamed** → ${data.name || name}`), true);
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**Rename failed:** ${err.message}`), true);
  }
}

async function exportEngagement() {
  const id = engagementSelectEl?.value;
  if (!id) {
    appendMessage("assistant", renderMarkdown("**Select a Project/engagement** first, then Export."), true);
    return;
  }
  try {
    const res = await fetch(`/api/engagements/${id}/export`, { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    const md =
      data.markdown ||
      `# ${data.name || "Engagement"}\n\n\`\`\`json\n${JSON.stringify(data, null, 2)}\n\`\`\`\n`;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([md], { type: "text/markdown" }));
    a.download = `securaiq-engagement-${id}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**Export failed:** ${err.message}`), true);
  }
}

const ENGAGEMENT_STATUS_CHOICES = ["draft", "active", "on_hold", "completed", "archived"];

async function changeEngagementStatus() {
  const id = engagementSelectEl?.value;
  if (!id) {
    appendMessage("assistant", renderMarkdown("**Select a Project/engagement** first."), true);
    return;
  }
  const choice = prompt(
    `New status (${ENGAGEMENT_STATUS_CHOICES.join(" / ")}):\n` +
      "on_hold = paused/partial engagement, not completed or archived."
  );
  if (!choice) return;
  const status = choice.trim().toLowerCase();
  if (!ENGAGEMENT_STATUS_CHOICES.includes(status)) {
    appendMessage("assistant", renderMarkdown(`**Invalid status.** Must be one of: ${ENGAGEMENT_STATUS_CHOICES.join(", ")}`), true);
    return;
  }
  try {
    const res = await fetch(`/api/engagements/${id}/status`, {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ status }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    await loadEngagements();
    if (engagementSelectEl) engagementSelectEl.value = id;
    appendMessage("assistant", renderMarkdown(`**Engagement status updated** → \`${status}\``), true);
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**Status change failed:** ${err.message}`), true);
  }
}

async function uploadFile() {
  const files = fileUploadInput?.files;
  if (!files?.length) return;
  for (const f of Array.from(files)) {
    await uploadOneFile(f, true);
  }
  if (fileUploadInput) fileUploadInput.value = "";
}

async function uploadOneFile(file, showToast) {
  const fd = new FormData();
  fd.append("file", file);
  const eng = engagementSelectEl?.value;
  const q = eng ? `?engagement_id=${encodeURIComponent(eng)}&ingest=true` : "?ingest=true";
  const res = await fetch(`/api/files${q}`, { method: "POST", headers: authHeaders(), body: fd });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (showToast) {
      appendMessage("assistant", renderMarkdown(`**Upload failed:** ${data.detail || res.status}`), true);
    }
    throw new Error(data.detail || `Upload failed (${res.status})`);
  }
  if (showToast) {
    appendMessage(
      "assistant",
      renderMarkdown(`**Uploaded** \`${data.filename}\` (${data.size_bytes} bytes)${data.ingested ? " → RAG" : ""}`),
      true
    );
  }
  return data;
}

function renderAttachChips() {
  if (!attachChipsEl) return;
  if (!pendingAttachments.length) {
    attachChipsEl.classList.add("hidden");
    attachChipsEl.innerHTML = "";
    return;
  }
  attachChipsEl.classList.remove("hidden");
  attachChipsEl.innerHTML = pendingAttachments
    .map(
      (a, i) =>
        `<span class="attach-chip"><span title="${a.file.name}">${a.file.name}</span>` +
        `<button type="button" data-rm="${i}" aria-label="Remove">×</button></span>`
    )
    .join("");
  attachChipsEl.querySelectorAll("button[data-rm]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.getAttribute("data-rm"));
      pendingAttachments.splice(idx, 1);
      renderAttachChips();
    });
  });
}

function queueChatFiles(fileList) {
  const incoming = Array.from(fileList || []);
  for (const f of incoming) {
    if (pendingAttachments.length >= MAX_CHAT_ATTACHMENTS) break;
    if (pendingAttachments.some((p) => p.file.name === f.name && p.file.size === f.size)) continue;
    pendingAttachments.push({ file: f });
  }
  renderAttachChips();
}

async function uploadPendingAttachments() {
  const ids = [];
  const names = [];
  for (const item of pendingAttachments) {
    if (item.id) {
      ids.push(item.id);
      names.push(item.file.name);
      continue;
    }
    const data = await uploadOneFile(item.file, false);
    item.id = data.id;
    ids.push(data.id);
    names.push(data.filename || item.file.name);
  }
  return { ids, names };
}

async function exportCurrentChat() {
  try {
    const cid = await ensureServerChat();
    if (!cid) throw new Error("Could not create server chat");
    const res = await fetch(`/api/chats/${cid}/export`, { headers: authHeaders() });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const md = await res.text();
    const blob = new Blob([md], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `securaiq-report-${cid.slice(0, 8)}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**Export failed:** ${err.message}`), true);
  }
}

function openGap(preferredFrameworkId) {
  gapModal?.classList.remove("hidden");
  gapResult?.classList.add("hidden");
  const preferred =
    typeof preferredFrameworkId === "string" && preferredFrameworkId.trim()
      ? preferredFrameworkId.trim()
      : "";
  if (preferred) {
    const sel = document.getElementById("gapFramework");
    if (sel && [...sel.options].some((o) => o.value === preferred)) sel.value = preferred;
  }
  loadGapFrameworks(true, preferred);
}
async function loadGapFrameworks(force = false, preferredId = "") {
  const sel = document.getElementById("gapFramework");
  if (!sel) return;
  if (!force && sel.dataset.loaded === "1" && sel.options.length > 3) {
    if (preferredId && [...sel.options].some((o) => o.value === preferredId)) {
      sel.value = preferredId;
    }
    return;
  }
  try {
    const res = await fetch("/api/frameworks", { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (typeof notifyUser === "function") {
        notifyUser(`**Frameworks catalog failed:** ${formatApiDetail(data.detail, res.status)}`);
      }
      return;
    }
    const frameworks = data.frameworks || [];
    if (!frameworks.length) return;
    const current = preferredId || sel.value;
    sel.innerHTML = frameworks
      .map((f) => {
        const label = f.version
          ? `${f.name || f.id} (${f.version})`
          : f.name || f.id;
        const n = f.control_count != null ? ` · ${f.control_count} controls` : "";
        return `<option value="${escapeHtml(f.id)}">${escapeHtml(label + n)}</option>`;
      })
      .join("");
    if (current && [...sel.options].some((o) => o.value === current)) sel.value = current;
    sel.dataset.loaded = "1";
  } catch (err) {
    if (typeof notifyUser === "function") {
      notifyUser(`**Frameworks catalog failed:** ${err.message || err}`);
    }
  }
}
function closeGap() {
  gapModal?.classList.add("hidden");
}
function openDash() {
  // Legacy ops modal → Mission Control
  if (typeof showView === "function") showView("command");
  if (typeof loadCommandCenter === "function") loadCommandCenter();
  else loadDashboard();
}
function closeDash() {
  dashModal?.classList.add("hidden");
}

async function runGapAnalysis(e) {
  e?.preventDefault?.();
  const framework_id = document.getElementById("gapFramework")?.value || "iso27001";
  const title = document.getElementById("gapTitle")?.value?.trim() || "Gap assessment";
  const evidence = document.getElementById("gapEvidence")?.value?.trim() || "";
  if (!evidence) {
    const msg = "**Gap analysis:** paste real policies, interview notes, or evidence first.";
    if (typeof notifyUser === "function") notifyUser(msg);
    else appendMessage("assistant", renderMarkdown(msg), true);
    document.getElementById("gapEvidence")?.focus();
    return;
  }
  const btn = document.getElementById("gapRunBtn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Running…";
  }
  try {
    const res = await fetch("/api/gap/run", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        framework_id,
        title,
        evidence,
        engagement_id: engagementSelectEl?.value || null,
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(formatApiDetail(data.detail, `HTTP ${res.status}`));
    renderGapResult(data);
    const summary =
      `**Gap analysis complete** — ${data.framework_name}: **${data.compliance_percent}%**\n\n` +
      `${data.executive_summary || ""}\n\n` +
      `Created **${data.remediations_created || 0}** remediation tasks. Open **Frameworks** to review controls.`;
    if (typeof notifyUser === "function") notifyUser(summary);
    else appendMessage("assistant", renderMarkdown(summary), true);
    if (typeof loadCommandCenter === "function") loadCommandCenter();
    if (typeof window.renderFrameworksPage === "function" && window.__securaiqWorkspaceView === "frameworks") {
      try {
        window.renderFrameworksPage();
      } catch {
        /* ignore */
      }
    }
    if (typeof window.renderRemsPage === "function" && window.__securaiqWorkspaceView === "remediations") {
      try {
        window.renderRemsPage();
      } catch {
        /* ignore */
      }
    }
  } catch (err) {
    const fail = `**Gap analysis failed:** ${err.message || err}`;
    if (typeof notifyUser === "function") notifyUser(fail);
    else appendMessage("assistant", renderMarkdown(fail), true);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Run gap analysis";
    }
  }
}

function renderGapResult(data) {
  if (!gapResult) return;
  const counts = data.counts || {};
  const gaps = (data.top_gaps || [])
    .slice(0, 8)
    .map(
      (g) =>
        `<li><strong>${escapeHtml(g.control_id)}</strong> (${escapeHtml(g.status)}) — ${escapeHtml(g.title)}</li>`
    )
    .join("");
  const rems = (data.remediations || [])
    .slice(0, 8)
    .map(
      (r) =>
        `<li data-rem="${escapeHtml(r.id)}"><strong>${escapeHtml(r.control_id)}</strong> — ${escapeHtml(r.title)}
         <button type="button" class="btn-secondary rem-done" data-id="${escapeHtml(r.id)}">Mark done</button></li>`
    )
    .join("");
  gapResult.classList.remove("hidden");
  gapResult.innerHTML = `
    <div class="gap-score">${escapeHtml(data.compliance_percent)}% compliance</div>
    <p class="hint">${escapeHtml(
      (data.methodology && data.methodology.summary) ||
        "Heuristic keyword score — not auditor-certified. Manual overrides raise confidence for that control only."
    )}</p>
    <div class="gap-counts">
      <span class="gap-chip">implemented ${counts.implemented || 0}</span>
      <span class="gap-chip">partial ${counts.partial || 0}</span>
      <span class="gap-chip">missing ${counts.missing || 0}</span>
      <span class="gap-chip">remediation tasks ${data.remediations_created || 0}</span>
    </div>
    <div class="gap-exec-summary">${renderMarkdown(data.executive_summary || "")}</div>
    <p class="sidebar-label">Top gaps</p>
    <ul>${gaps || "<li>None</li>"}</ul>
    <p class="sidebar-label">Remediation tracker (DB)</p>
    <ul id="remList">${rems || "<li>None</li>"}</ul>
    <button type="button" class="btn-sidebar" id="gapExportBtn">Export report (Markdown)</button>
  `;
  document.getElementById("gapExportBtn")?.addEventListener("click", () => exportGap(data.id));
  gapResult.querySelectorAll(".rem-done").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-id");
      await fetch(`/api/gap/remediations/${id}`, {
        method: "PATCH",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ status: "done" }),
      });
      btn.closest("li")?.remove();
      refreshActiveWorkspace("remediations");
    });
  });
  refreshActiveWorkspace("remediations");
  refreshActiveWorkspace("frameworks");
}

async function exportGap(assessmentId) {
  try {
    const res = await fetch(`/api/gap/assessments/${assessmentId}/export`, { headers: authHeaders() });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const md = await res.text();
    const blob = new Blob([md], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `securaiq-gap-${assessmentId.slice(0, 8)}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**Gap export failed:** ${err.message}`), true);
  }
}

async function loadDashboard() {
  if (!dashBody) return;
  try {
    const res = await fetch("/api/dashboard", { headers: authHeaders() });
    const data = await res.json();
    if (!res.ok) throw new Error(formatApiDetail(data.detail, `HTTP ${res.status}`));
    const fws = (data.frameworks || [])
      .map(
        (f) =>
          `<li><strong>${escapeHtml(f.framework_id)}</strong>: ${escapeHtml(f.compliance_percent)}% — ${escapeHtml(
            f.title || ""
          )}</li>`
      )
      .join("");
    const recs = (data.recommendations || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("");
    const risks = (data.findings?.top_risks || [])
      .map((r) => `<li>Score ${escapeHtml(r.risk_score)}: ${escapeHtml(r.threat)}</li>`)
      .join("");
    const vulns = (data.findings?.top_vulns || [])
      .map((v) => `<li>${escapeHtml(v.severity)}: ${escapeHtml(v.cve || "")} ${escapeHtml(v.title)}</li>`)
      .join("");
    dashBody.innerHTML = `
      <div class="dash-score-row">
        <div class="dash-metric"><span>Compliance</span><strong>${data.compliance_score}%</strong></div>
        <div class="dash-metric"><span>Open risks</span><strong>${data.risks_open || 0}</strong></div>
        <div class="dash-metric"><span>Open vulns</span><strong>${data.vulnerabilities_open || 0}</strong></div>
        <div class="dash-metric"><span>Remediations</span><strong>${data.remediations_open || 0}</strong></div>
        <div class="dash-metric"><span>Assets</span><strong>${data.assets_total || 0}</strong></div>
        <div class="dash-metric"><span>Campaigns</span><strong>${data.campaigns_active || 0}</strong></div>
      </div>
      <p class="hint">${data.assessment_count || 0} gap assessments · ${data.playbooks_total || 0} playbooks · avg risk ${data.avg_open_risk_score || 0}</p>
      <p class="sidebar-label">Framework scores</p>
      <ul>${fws || "<li>No gap assessments yet</li>"}</ul>
      <p class="sidebar-label">Top risks</p>
      <ul>${risks || "<li>None</li>"}</ul>
      <p class="sidebar-label">Top vulnerabilities</p>
      <ul>${vulns || "<li>None</li>"}</ul>
      <p class="sidebar-label">Recommendations</p>
      <ul>${recs}</ul>
    `;
  } catch (err) {
    dashBody.innerHTML = `<p class="hint">Dashboard unavailable: ${err.message}</p>`;
  }
}

function openRisk() {
  riskModal?.classList.remove("hidden");
  loadRisks();
}
function closeRisk() {
  riskModal?.classList.add("hidden");
}
function openVuln() {
  vulnModal?.classList.remove("hidden");
  loadVulns();
}
function closeVuln() {
  vulnModal?.classList.add("hidden");
}

async function loadRisks() {
  if (!riskList) return;
  const res = await fetch("/api/risks", { headers: authHeaders() });
  const data = await res.json();
  const rows = (data.risks || [])
    .map(
      (r) =>
        `<li><strong>${escapeHtml(r.risk_score)}</strong> ${escapeHtml(r.threat)} · ${escapeHtml(
          r.asset_name || "—"
        )} · ${escapeHtml(r.status)}
         <button type="button" class="btn-secondary risk-mitigate" data-id="${escapeHtml(r.id)}">Mitigate</button></li>`
    )
    .join("");
  riskList.innerHTML = `<p class="sidebar-label">Register (${(data.risks || []).length})</p><ul>${rows || "<li>Empty</li>"}</ul>`;
  riskList.querySelectorAll(".risk-mitigate").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await fetch(`/api/risks/${btn.getAttribute("data-id")}`, {
        method: "PATCH",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ status: "mitigated" }),
      });
      loadRisks();
      refreshActiveWorkspace("risks");
    });
  });
}

async function submitRisk(e) {
  e.preventDefault();
  const body = {
    threat: document.getElementById("riskThreat")?.value?.trim(),
    vulnerability: document.getElementById("riskVuln")?.value?.trim() || "",
    asset_name: document.getElementById("riskAsset")?.value?.trim() || "",
    impact: Number(document.getElementById("riskImpact")?.value || 3),
    likelihood: Number(document.getElementById("riskLikelihood")?.value || 3),
    owner: document.getElementById("riskOwner")?.value?.trim() || "",
    mitigation: document.getElementById("riskMitigation")?.value?.trim() || "",
    engagement_id: engagementSelectEl?.value || null,
  };
  const res = await fetch("/api/risks", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    notifyUser(`**Risk create failed:** ${formatApiDetail(err.detail, res.status)}`);
    return;
  }
  riskForm?.reset();
  document.getElementById("riskImpact").value = "3";
  document.getElementById("riskLikelihood").value = "3";
  closeRisk();
  loadRisks();
  refreshActiveWorkspace("risks");
  notifyUser("**Risk added** to the register.");
}

async function loadVulns() {
  if (!vulnList) return;
  const res = await fetch("/api/vulnerabilities", { headers: authHeaders() });
  const data = await res.json();
  const rows = (data.vulnerabilities || [])
    .slice(0, 40)
    .map(
      (v) =>
        `<li><strong>${escapeHtml(v.severity)}</strong> ${escapeHtml(v.cve || "")} — ${escapeHtml(v.title)}
         <button type="button" class="btn-secondary vuln-close" data-id="${escapeHtml(v.id)}">Close</button></li>`
    )
    .join("");
  vulnList.innerHTML = `<p class="sidebar-label">Findings (${(data.vulnerabilities || []).length})</p><ul>${rows || "<li>Empty — import a scan</li>"}</ul>`;
  vulnList.querySelectorAll(".vuln-close").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await fetch(`/api/vulnerabilities/${btn.getAttribute("data-id")}`, {
        method: "PATCH",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ status: "closed" }),
      });
      loadVulns();
      refreshActiveWorkspace("vulns");
    });
  });
}

async function importVulns() {
  const f = vulnFileInput?.files?.[0];
  if (!f) return;
  const fd = new FormData();
  fd.append("file", f);
  const eng = engagementSelectEl?.value;
  const q = eng ? `?engagement_id=${encodeURIComponent(eng)}` : "";
  const res = await fetch(`/api/vulnerabilities/import${q}`, { method: "POST", headers: authHeaders(), body: fd });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    notifyUser(`**Vuln import failed:** ${formatApiDetail(data.detail, res.status)}`);
    return;
  }
  notifyUser(`**Imported ${data.imported} vulnerabilities** into the register.`);
  if (vulnFileInput) vulnFileInput.value = "";
  closeVuln();
  loadVulns();
  refreshActiveWorkspace("vulns");
}

function openAsset() {
  assetModal?.classList.remove("hidden");
  loadAssets();
}
function closeAsset() {
  assetModal?.classList.add("hidden");
}
function openRem() {
  remModal?.classList.remove("hidden");
  loadRemediations();
}
function closeRem() {
  remModal?.classList.add("hidden");
}
function openPlaybook() {
  playbookModal?.classList.remove("hidden");
  loadPlaybooks();
}
function closePlaybook() {
  playbookModal?.classList.add("hidden");
}
function openCampaign() {
  campaignModal?.classList.remove("hidden");
  loadCampaigns();
}
function closeCampaign() {
  campaignModal?.classList.add("hidden");
}

async function loadAssets() {
  if (!assetList) return;
  const res = await fetch("/api/assets", { headers: authHeaders() });
  const data = await res.json();
  const rows = (data.assets || [])
    .map(
      (a) =>
        `<li><strong>${escapeHtml(displayAssetLabel(a))}</strong> · ${categoryChipHtml(a)} · ${escapeHtml(
          a.criticality
        )} · ${escapeHtml(a.owner || "—")}
         <button type="button" class="btn-secondary asset-del" data-id="${escapeHtml(a.id)}">Delete</button></li>`
    )
    .join("");
  assetList.innerHTML = `<p class="sidebar-label">Inventory (${(data.assets || []).length})</p><ul>${rows || "<li>Empty</li>"}</ul>`;
  assetList.querySelectorAll(".asset-del").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await fetch(`/api/assets/${btn.getAttribute("data-id")}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      loadAssets();
      refreshActiveWorkspace("assets");
    });
  });
}

async function submitAsset(e) {
  e.preventDefault();
  const body = {
    name: document.getElementById("assetName")?.value?.trim(),
    asset_type: document.getElementById("assetType")?.value || "server",
    criticality: document.getElementById("assetCriticality")?.value || "medium",
    owner: document.getElementById("assetOwner")?.value?.trim() || "",
    notes: document.getElementById("assetNotes")?.value?.trim() || "",
    engagement_id: engagementSelectEl?.value || null,
  };
  const res = await fetch("/api/assets", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    notifyUser(`**Asset create failed:** ${formatApiDetail(err.detail, res.status)}`);
    return;
  }
  assetForm?.reset();
  document.getElementById("assetCriticality").value = "medium";
  closeAsset();
  loadAssets();
  refreshActiveWorkspace("assets");
  notifyUser("**Asset added.**");
}

async function loadRemediations() {
  if (!remBoard) return;
  const res = await fetch("/api/gap/remediations", { headers: authHeaders() });
  const data = await res.json();
  const rows = (data.remediations || [])
    .map(
      (r) =>
        `<li><strong>${escapeHtml(r.control_id)}</strong> — ${escapeHtml(r.title)}
         <span class="gap-chip">${escapeHtml(r.status)}</span> · ${escapeHtml(r.owner || "unassigned")}
         ${r.status !== "done" ? `<button type="button" class="btn-secondary rem-done" data-id="${escapeHtml(r.id)}">Mark done</button>` : ""}</li>`
    )
    .join("");
  remBoard.innerHTML = `<p class="sidebar-label">Tasks (${(data.remediations || []).length})</p><ul>${rows || "<li>Empty — run Gap analysis first</li>"}</ul>`;
  remBoard.querySelectorAll(".rem-done").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await fetch(`/api/gap/remediations/${btn.getAttribute("data-id")}`, {
        method: "PATCH",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ status: "done" }),
      });
      loadRemediations();
      refreshActiveWorkspace("remediations");
    });
  });
}

async function loadPlaybooks() {
  if (!playbookList) return;
  const res = await fetch("/api/playbooks", { headers: authHeaders() });
  const data = await res.json();
  const rows = (data.playbooks || [])
    .map(
      (p) =>
        `<li><strong>${escapeHtml(p.title)}</strong> · ${escapeHtml(p.category)} · ${escapeHtml(p.severity)}
         <pre class="playbook-steps">${escapeHtml(p.steps || "")}</pre>
         <button type="button" class="btn-secondary pb-del" data-id="${escapeHtml(p.id)}">Delete</button></li>`
    )
    .join("");
  playbookList.innerHTML = `<p class="sidebar-label">Playbooks (${(data.playbooks || []).length})</p><ul>${rows || "<li>Empty</li>"}</ul>`;
  playbookList.querySelectorAll(".pb-del").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await fetch(`/api/playbooks/${btn.getAttribute("data-id")}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      loadPlaybooks();
      refreshActiveWorkspace("playbooks");
    });
  });
}

async function submitPlaybook(e) {
  e.preventDefault();
  const body = {
    title: document.getElementById("playbookTitle")?.value?.trim(),
    category: document.getElementById("playbookCategory")?.value || "ir",
    severity: document.getElementById("playbookSeverity")?.value || "high",
    steps: document.getElementById("playbookSteps")?.value?.trim() || "",
    engagement_id: engagementSelectEl?.value || null,
  };
  const res = await fetch("/api/playbooks", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    notifyUser(`**Playbook create failed:** ${formatApiDetail(err.detail, res.status)}`);
    return;
  }
  playbookForm?.reset();
  document.getElementById("playbookSeverity").value = "high";
  closePlaybook();
  loadPlaybooks();
  refreshActiveWorkspace("playbooks");
  notifyUser("**Playbook saved.**");
}

async function loadCampaigns() {
  if (!campaignList) return;
  const res = await fetch("/api/campaigns", { headers: authHeaders() });
  const data = await res.json();
  const rows = (data.campaigns || [])
    .map((c) => {
      const sent = Number(c.sent_count || 0);
      const clickRate = sent ? Math.round((100 * Number(c.click_count || 0)) / sent) : 0;
      const reportRate = sent ? Math.round((100 * Number(c.report_count || 0)) / sent) : 0;
      return `<li><strong>${escapeHtml(c.name)}</strong> · ${escapeHtml(c.status)} · ${escapeHtml(c.campaign_type)}
        <br/><span class="hint">${escapeHtml(c.audience || "—")} · click ${clickRate}% · report ${reportRate}%</span>
        <button type="button" class="btn-secondary camp-run" data-id="${escapeHtml(c.id)}">Mark running</button>
        <button type="button" class="btn-secondary camp-del" data-id="${escapeHtml(c.id)}">Delete</button></li>`;
    })
    .join("");
  campaignList.innerHTML = `<p class="sidebar-label">Campaigns (${(data.campaigns || []).length})</p><ul>${rows || "<li>Empty</li>"}</ul>`;
  campaignList.querySelectorAll(".camp-run").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await fetch(`/api/campaigns/${btn.getAttribute("data-id")}`, {
        method: "PATCH",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ status: "running" }),
      });
      loadCampaigns();
      refreshActiveWorkspace("campaigns");
    });
  });
  campaignList.querySelectorAll(".camp-del").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await fetch(`/api/campaigns/${btn.getAttribute("data-id")}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      loadCampaigns();
      refreshActiveWorkspace("campaigns");
    });
  });
}

async function submitCampaign(e) {
  e.preventDefault();
  const body = {
    name: document.getElementById("campaignName")?.value?.trim(),
    campaign_type: document.getElementById("campaignType")?.value || "phishing_sim",
    status: document.getElementById("campaignStatus")?.value || "planned",
    audience: document.getElementById("campaignAudience")?.value?.trim() || "",
    sent_count: Number(document.getElementById("campaignSent")?.value || 0),
    click_count: Number(document.getElementById("campaignClicks")?.value || 0),
    report_count: Number(document.getElementById("campaignReports")?.value || 0),
    notes: document.getElementById("campaignNotes")?.value?.trim() || "",
    engagement_id: engagementSelectEl?.value || null,
  };
  const res = await fetch("/api/campaigns", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    notifyUser(`**Campaign create failed:** ${formatApiDetail(err.detail, res.status)}`);
    return;
  }
  campaignForm?.reset();
  document.getElementById("campaignSent").value = "0";
  document.getElementById("campaignClicks").value = "0";
  document.getElementById("campaignReports").value = "0";
  closeCampaign();
  loadCampaigns();
  refreshActiveWorkspace("campaigns");
  notifyUser("**Campaign saved.**");
}

async function downloadMd(url, name) {
  const res = await fetch(url, { headers: authHeaders() });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const md = await res.text();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([md], { type: "text/markdown" }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

async function downloadBinary(url, name, mime) {
  const res = await fetch(url, { headers: authHeaders() });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const buf = await res.arrayBuffer();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([buf], { type: mime || "application/octet-stream" }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}
window.downloadBinary = downloadBinary;
window.downloadMd = downloadMd;

const THEME_KEY = "securaiq.theme";

const LIVE_PHASE_LABELS = {
  start: "Preparing…",
  think: "Thinking…",
  route: "Routing intent…",
  intel: "Loading threat intel…",
  search: "Searching the web…",
  assess: "Probing target…",
  tools: "Running security tools…",
  rag: "Reading knowledge & attachments…",
  model: "Writing answer…",
  done: "Ready",
  error: "Pipeline error",
};

const THINK_STEPS = [
  { id: "think", label: "Understand the ask & constraints" },
  { id: "route", label: "Route intent & agent" },
  { id: "intel", label: "Load threat intel" },
  { id: "search", label: "Gather live context" },
  { id: "assess", label: "Probe authorized target" },
  { id: "tools", label: "Run security tools" },
  { id: "rag", label: "Use knowledge & attachments" },
  { id: "model", label: "Compose the answer" },
];

function paintLiveDeck(state, phaseText, activity, data) {
  const ticker = document.getElementById("liveTicker");
  const rail = document.getElementById("railLive");
  const apply = (el) => {
    if (!el) return;
    el.classList.remove("live-on", "live-busy", "live-off");
    el.classList.add(state);
    el.setAttribute("data-state", state);
  };
  apply(liveBarEl);
  apply(ticker);
  apply(rail);
  if (livePhaseEl && phaseText) livePhaseEl.textContent = phaseText;
  if (liveActivityEl && activity !== undefined) liveActivityEl.textContent = activity || "";
  const tickerState = document.getElementById("tickerState");
  if (tickerState) {
    tickerState.textContent = state === "live-busy" ? "BUSY" : state === "live-on" ? "LIVE" : "HOLD";
  }
  const railText = document.getElementById("railLiveText");
  if (railText) {
    railText.textContent =
      state === "live-busy" ? phaseText || "Pipeline" : state === "live-on" ? "Feed live" : "Feed hold";
  }
  const rt = data || window.__securaiqRealtime || {};
  const jobsBusy = Number(rt.jobs_running || 0) + Number(rt.jobs_pending || 0);
  const jobsEl = document.getElementById("tickerJobs");
  if (jobsEl) jobsEl.textContent = `${jobsBusy} jobs`;
  const findingsEl = document.getElementById("tickerFindings");
  if (findingsEl) {
    const vulns = rt.kpis && rt.kpis.vulns_open != null ? rt.kpis.vulns_open : null;
    findingsEl.textContent = vulns != null ? `${vulns} vulns` : "— vulns";
    findingsEl.title = vulns != null ? `${vulns} open findings` : "Open findings";
  }
  const legacyKpi = document.getElementById("tickerKpi");
  if (legacyKpi) legacyKpi.hidden = true;
}

function setLiveState(state, phaseText, activity) {
  paintLiveDeck(state, phaseText, activity);
}

function applyLiveMarker(phase) {
  const label = LIVE_PHASE_LABELS[phase] || phase;
  updateThinkingUI(phase);
  if (phase === "done") {
    setLiveState("live-on", "Ready", "");
    finishThinkingUI(true);
    return;
  }
  if (phase === "error") {
    setLiveState("live-off", label, "");
    finishThinkingUI(false);
    return;
  }
  setLiveState("live-busy", label, phase);
}

/** @type {HTMLElement | null} */
let activeThinkingEl = null;
/** @type {Set<string>} */
let thinkingSeen = new Set();

function startThinkingUI(bubble) {
  thinkingSeen = new Set(["start"]);
  activeThinkingEl = document.createElement("div");
  activeThinkingEl.className = "thinking-card";
  activeThinkingEl.innerHTML = `
    <div class="thinking-head">
      <span class="thinking-pulse" aria-hidden="true"></span>
      <strong>Analysis pipeline</strong>
      <span class="thinking-sub">routing an authorized control answer</span>
    </div>
    <ol class="thinking-steps">
      ${THINK_STEPS.map((s) => `<li data-step="${s.id}" class="pending">${s.label}</li>`).join("")}
    </ol>
  `;
  bubble.textContent = "";
  bubble.appendChild(activeThinkingEl);
  bubble.classList.add("thinking");
  bubble.classList.remove("typing");
}

function updateThinkingUI(phase) {
  if (!activeThinkingEl) return;
  thinkingSeen.add(phase);
  const items = activeThinkingEl.querySelectorAll(".thinking-steps li");
  items.forEach((li) => {
    const id = li.getAttribute("data-step");
    li.classList.remove("pending", "active", "done");
    if (thinkingSeen.has(id) && id !== phase) li.classList.add("done");
    else if (id === phase) li.classList.add("active");
    else li.classList.add("pending");
  });
  const sub = activeThinkingEl.querySelector(".thinking-sub");
  if (sub) sub.textContent = LIVE_PHASE_LABELS[phase] || phase;
}

function finishThinkingUI(ok) {
  if (!activeThinkingEl) return;
  const card = activeThinkingEl;
  activeThinkingEl = null;
  card.classList.add(ok ? "thinking-done" : "thinking-error");
  const head = card.querySelector("strong");
  if (head) head.textContent = ok ? "Thought process" : "Interrupted";
  const sub = card.querySelector(".thinking-sub");
  if (sub) sub.textContent = ok ? "ready — streaming answer" : "pipeline error";
  // keep a compact summary briefly, then remove when answer replaces bubble
  return card;
}

function stripLiveMarkers(text) {
  return text
    .replace(/\[\[router:([^\]|]+)\|([^\]|]*)\|([^\]]*)\]\]/gi, (_, agent, intent, backend) => {
      if (livePhaseEl) {
        livePhaseEl.textContent = `${agent}${intent ? ` · ${intent}` : ""}${backend ? ` → ${backend}` : ""}`;
      }
      return "";
    })
    .replace(/\[\[live:route:([a-z0-9_-]+)\]\]/gi, (_, intent) => {
      applyLiveMarker("route");
      if (liveActivityEl) liveActivityEl.textContent = intent;
      return "";
    })
    /* legacy per-tool markers → keep static "tools" label */
    .replace(/\[\[live:tool:[^\]]+\]\]/gi, () => {
      applyLiveMarker("tools");
      return "";
    })
    .replace(/\[\[live:([a-z0-9_-]+)\]\]/gi, (_, phase) => {
      applyLiveMarker(phase.toLowerCase());
      return "";
    });
}

function startRealtimeFeed() {
  if (!window.EventSource) {
    setLiveState("live-off", "SSE unsupported", "");
    return;
  }
  try {
    if (window.__securaiqRealtimeEs) {
      try {
        window.__securaiqRealtimeEs.close();
      } catch {
        /* ignore */
      }
    }
    const es = new EventSource("/api/realtime");
    window.__securaiqRealtimeEs = es;
    es.onopen = () => {
      window.__securaiqEsConnected = true;
      if (!streaming) setLiveState("live-on", "Ready", "");
    };
    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.error) {
          if (!streaming && !window.__securaiqStreaming) {
            setLiveState("live-off", "Feed error", data.error);
          }
          return;
        }
        const prev = window.__securaiqRealtime || {};
        window.__securaiqRealtime = data;
        const push = data.push || null;
        const pushType = push && push.type ? String(push.type) : "";
        if (pushType === "archive" || pushType === "scan_clear") {
          if (typeof loadReports === "function") {
            try {
              loadReports();
            } catch (_) {}
          }
        }
        const ready = data.backend_ready || data.backend_status === "loads_on_chat";
        const backend = data.backend || "model";
        const jobsBusy = Number(data.jobs_running || 0) + Number(data.jobs_pending || 0);
        const liveState = jobsBusy > 0 ? "live-busy" : ready ? "live-on" : "live-off";
        // Keep badge/KPIs live even while chat streams; only soften the rail label.
        if (!streaming && !window.__securaiqStreaming) {
          setLiveState(
            liveState,
            jobsBusy > 0
              ? `Live · ${jobsBusy} job${jobsBusy === 1 ? "" : "s"}`
              : ready
                ? `Live · ${backend}`
                : "Backend hold",
            data.model || ""
          );
          paintLiveDeck(liveState, null, data.model || "", data);
        }
        const pulseEl = document.getElementById("topLastSync");
        if (pulseEl) pulseEl.textContent = `pulse ${new Date().toLocaleTimeString()}`;
        if (liveMetaEl && !streaming && !window.__securaiqStreaming) {
          const bits = [];
          const tt = Number(data.tools_total || 0);
          const ta = Number(data.tools_available || 0);
          if (tt > 0) bits.push(`tools ${ta}/${tt}`);
          const rag = Number(data.rag_documents || 0);
          if (rag > 0) bits.push(`RAG ${rag}`);
          if (jobsBusy > 0) bits.push(`jobs ${jobsBusy}`);
          const hk = data.hardeningkitty || {};
          if (hk.installed) bits.push(`HK ${hk.lists || 0}`);
          const inv = data.inventory || {};
          if (inv.devices_cached != null) bits.push(`inv ${inv.devices_cached || 0}`);
          if (pushType) bits.push(`push ${pushType}`);
          liveMetaEl.textContent = bits.join(" · ");
        }
        if (toolsStatusEl && data.tools_total != null) {
          const tt = Number(data.tools_total || 0);
          toolsStatusEl.textContent =
            tt > 0 ? `Tools ${data.tools_available || 0}/${tt} ready` : "Tools ready";
        }
        // Live KPI chips on Mission Control (no full reload)
        const k = data.kpis || {};
        const setKpi = (id, val) => {
          const el = document.getElementById(id);
          if (el && val != null) el.textContent = String(val);
        };
        setKpi("ccAssets", k.assets);
        // Soft-refresh notifications badge from pulse
        const badge = document.getElementById("notifBadge");
        if (badge && data.notifications_unread != null) {
          const n = Number(data.notifications_unread) || 0;
          badge.hidden = n <= 0;
          badge.textContent = n > 99 ? "99+" : String(n);
        }
        if (pushType === "tool_progress") {
          pulseToolProgress(push);
        }
        if (pushType === "tool" && typeof pulseToolFromPush === "function") {
          pulseToolFromPush(push);
        }
        if (pushType === "scan") {
          pulseVaScanFromPush(push);
        }
        if (pushType === "combo" && typeof pulseComboFromPush === "function") {
          pulseComboFromPush(push);
        }
        if (pushType === "inventory") {
          pulseInventoryFromPush(push);
        }
        if (pushType === "software_inventory") {
          pulseSoftwareFromPush(push);
          const swIssuesEl = document.getElementById("ccSoftwareIssues");
          const swBarEl = document.getElementById("ccSoftwareHealthBar");
          if (push && push.issues != null && swIssuesEl) {
            swIssuesEl.textContent = String(Number(push.issues) || 0);
          }
          if (push && push.health_score != null && swBarEl) {
            swBarEl.style.width = `${Math.min(100, Math.max(0, Number(push.health_score) || 0))}%`;
          }
          const wzPatchEl = document.getElementById("wzPatchHealthPct");
          if (push && push.health_score != null && wzPatchEl) {
            wzPatchEl.textContent = `${Math.round(Number(push.health_score) || 0)}%`;
          }
        }
        if (pushType === "intel" || pushType === "intel_watch") {
          refreshIntelStrip();
        }
        if (pushType === "agent_threat" && push && typeof notifyUser === "function") {
          const sev = String(push.severity || "medium");
          if (sev === "critical" || sev === "high") {
            const host = push.hostname || push.agent_id || "agent";
            notifyUser(`**SecuraIQ Sentinel · ${sev.toUpperCase()}** — ${push.title || "Suspicious activity"} on \`${host}\``);
          }
        }
        // Detect job completions → notify workspace to refresh
        const prevJobs = JSON.stringify((prev.jobs_recent || []).map((j) => `${j.id}:${j.status}`));
        const nextJobs = JSON.stringify((data.jobs_recent || []).map((j) => `${j.id}:${j.status}`));
        const jobsChanged = (prevJobs && prevJobs !== nextJobs) || pushType === "job";
        const kpisChanged =
          JSON.stringify(prev.kpis || {}) !== JSON.stringify(k) ||
          JSON.stringify(prev.inventory || {}) !== JSON.stringify(data.inventory || {}) ||
          JSON.stringify(prev.hardeningkitty || {}) !== JSON.stringify(data.hardeningkitty || {});
        const pushRefresh = !!pushType;
        window.dispatchEvent(
          new CustomEvent("securaiq:realtime", {
            detail: {
              ...data,
              jobsChanged,
              kpisChanged,
              pushRefresh,
              pushType,
              heartbeat: !pushType,
            },
          })
        );
        applyRealtimeWorkspaceRefresh(data, {
          jobsChanged,
          kpisChanged,
          pushRefresh,
          pushType,
          heartbeat: !pushType,
        });
        // The SSE endpoint coalesces a burst of pushes fired in quick succession
        // (e.g. agent check-in publishes "asset" then "agent") into ONE frame,
        // keeping only the first as the top-level `push` and stashing the rest
        // in `push.also[]`. Without this, any type buried in `also[]` never
        // reaches type-based UI refresh logic (REALTIME_LIVE_TYPES,
        // SOC_RELEVANT_PUSH_TYPES, etc.) even though the data arrived live.
        // Replay the same dispatch for each nested sub-event so its type is
        // treated as a first-class live push.
        const alsoPushes = push && Array.isArray(push.also) ? push.also : [];
        for (const sub of alsoPushes) {
          const subType = sub && sub.type ? String(sub.type) : "";
          if (!subType || subType === pushType) continue;
          const subData = { ...data, push: sub };
          window.dispatchEvent(
            new CustomEvent("securaiq:realtime", {
              detail: {
                ...subData,
                jobsChanged,
                kpisChanged,
                pushRefresh: true,
                pushType: subType,
                heartbeat: false,
              },
            })
          );
          applyRealtimeWorkspaceRefresh(subData, {
            jobsChanged,
            kpisChanged,
            pushRefresh: true,
            pushType: subType,
            heartbeat: false,
          });
          if (subType === "agent_threat" && typeof notifyUser === "function") {
            const sev = String(sub.severity || "medium");
            if (sev === "critical" || sev === "high") {
              const host = sub.hostname || sub.agent_id || "agent";
              notifyUser(`**SecuraIQ Sentinel · ${sev.toUpperCase()}** — ${sub.title || "Suspicious activity"} on \`${host}\``);
            }
          }
        }
        if (pushType === "notification" && typeof refreshNotifBadge === "function") {
          clearTimeout(window.__securaiqNotifRtTimer);
          window.__securaiqNotifRtTimer = setTimeout(() => {
            refreshNotifBadge();
            const panel = document.getElementById("notifPanel");
            if (panel && !panel.hidden && typeof fetchNotifications === "function") {
              fetchNotifications().then((d) => {
                if (d && typeof renderNotifList === "function") renderNotifList(d);
              });
            }
          }, 250);
        }
      } catch {
        /* ignore */
      }
    };
    es.onerror = () => {
      window.__securaiqEsConnected = false;
      if (!streaming && !window.__securaiqStreaming) {
        setLiveState("live-off", "Reconnecting…", "");
      }
      if (es.readyState === EventSource.CLOSED) {
        clearTimeout(window.__securaiqEsRetry);
        window.__securaiqEsRetry = setTimeout(startRealtimeFeed, 2500);
      }
    };
  } catch {
    setLiveState("live-off", "Realtime offline", "");
  }
}

const REALTIME_LIVE_TYPES = new Set([
  "scan",
  "job",
  "combo",
  "asset",
  "vuln",
  "vuln_batch",
  "inventory",
  "software_inventory",
  "software.inventory.updated",
  "software.inventory.updated",
  "software.vulnerability.changed",
  "software.vulnerability.changed",
  "scan_clear",
  "archive",
  "intel",
  "intel_watch",
  "tool_progress",
  "tool",
  "xdr",
  "xdr_batch",
  "siem",
  "agent",
  "agent_threat",
  "cloud",
  "thehive",
  "incident",
  "remediation",
  "risk",
  "playbook",
  "campaign",
  "gap",
  "hardening",
  "notification",
  "hunt",
]);
window.REALTIME_LIVE_TYPES = REALTIME_LIVE_TYPES;

function applyRealtimeWorkspaceRefresh(data, flags) {
  const view =
    window.__securaiqWorkspaceView ||
    (typeof currentView !== "undefined" ? currentView : "") ||
    "";
  const pt = flags.pushType || "";
  if (REALTIME_LIVE_TYPES.has(pt) || flags.jobsChanged) {
    clearTimeout(window.__securaiqInvRtTimer);
    window.__securaiqInvRtTimer = setTimeout(() => {
      if (typeof syncLiveWorkspace === "function") syncLiveWorkspace({ pushType: pt, push: data.push });
    }, 180);
  }
  if (pt === "scan") {
    if (typeof pulseVaScanFromPush === "function") pulseVaScanFromPush(data.push);
    if (typeof pulseActiveScanFromPush === "function" && data.push) pulseActiveScanFromPush(data.push);
  } else if (pt === "combo" && typeof pulseComboFromPush === "function") {
    pulseComboFromPush(data.push);
  } else if (pt === "inventory" && typeof pulseInventoryFromPush === "function") {
    pulseInventoryFromPush(data.push);
  } else if (isSoftwarePushType(pt)) {
    pulseSoftwareFromPush(data.push);
    if (typeof window.refreshSoftwareFromPush === "function") {
      window.refreshSoftwareFromPush(data.push, { partial: true, skipPulse: true });
    }
  } else if (pt === "tool_progress" && typeof pulseToolProgress === "function") {
    pulseToolProgress(data.push);
    pulseToolFromPush(data.push);
  } else if (pt === "tool" && typeof pulseToolFromPush === "function") {
    pulseToolFromPush(data.push);
  } else if ((pt === "intel" || pt === "intel_watch") && typeof refreshIntelStrip === "function") {
    refreshIntelStrip();
  }
  const incremental = isSoftwarePushType(pt) || isToolPushType(pt);
  if (flags.pushRefresh && !incremental && typeof loadCommandCenter === "function") {
    clearTimeout(window.__securaiqCcAnyTimer);
    window.__securaiqCcAnyTimer = setTimeout(() => loadCommandCenter(), 320);
  }
  if (flags.jobsChanged && typeof window.refreshAutomationPage === "function" && view === "automation") {
    window.refreshAutomationPage();
  }
  if (
    (flags.kpisChanged || flags.pushRefresh || flags.heartbeat) &&
    view === "command" &&
    !incremental &&
    typeof loadCommandCenter === "function"
  ) {
    clearTimeout(window.__securaiqCcRtTimer);
    window.__securaiqCcRtTimer = setTimeout(() => loadCommandCenter(), flags.pushRefresh ? 400 : 1200);
  }
  if (flags.jobsChanged && typeof window.__securaiqOnJobPulse === "function") {
    window.__securaiqOnJobPulse(data);
  }
  if ((flags.pushRefresh || flags.heartbeat) && typeof window.__securaiqOnPushPulse === "function") {
    window.__securaiqOnPushPulse(data, flags);
  }
  if (typeof window.__securaiqRefreshActiveView === "function") {
    window.__securaiqRefreshActiveView(data, flags);
  }
}

async function waitForJob(jobId, { timeoutMs = 180000, intervalMs = 1200 } = {}) {
  if (!jobId) return null;
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`, { headers: authHeaders() });
      const job = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(job.detail || `HTTP ${res.status}`);
      const st = (job.status || "").toLowerCase();
      if (st === "done" || st === "error" || st === "failed") return job;
    } catch (err) {
      if (Date.now() - start > timeoutMs - intervalMs) throw err;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return { id: jobId, status: "timeout" };
}
window.waitForJob = waitForJob;

function getTheme() {
  const t = document.documentElement.getAttribute("data-theme");
  return t === "dark" ? "dark" : "light";
}

function applyTheme(theme) {
  const next = theme === "dark" ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", next);
  try {
    localStorage.setItem(THEME_KEY, next);
  } catch {
    /* ignore */
  }
  if (metaThemeColor) {
    metaThemeColor.setAttribute("content", next === "dark" ? "#0c1117" : "#0f6e6a");
  }
  const appleBar = document.querySelector('meta[name="apple-mobile-web-app-status-bar-style"]');
  if (appleBar) {
    appleBar.setAttribute("content", next === "dark" ? "black-translucent" : "default");
  }
  if (themeToggleLabel) {
    themeToggleLabel.textContent = next === "dark" ? "Light mode" : "Dark mode";
  }
  const tip = next === "dark" ? "Switch to light mode" : "Switch to dark mode";
  themeToggleBtn?.setAttribute("title", tip);
  themeToggleTopBtn?.setAttribute("title", tip);
}

function toggleTheme() {
  applyTheme(getTheme() === "dark" ? "light" : "dark");
}

function initTheme() {
  let theme = "light";
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") theme = saved;
    else if (window.matchMedia("(prefers-color-scheme: dark)").matches) theme = "dark";
  } catch {
    /* ignore */
  }
  applyTheme(theme);
  try {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (e) => {
      const saved = localStorage.getItem(THEME_KEY);
      if (saved === "light" || saved === "dark") return;
      applyTheme(e.matches ? "dark" : "light");
    });
  } catch {
    /* ignore */
  }
}
const MAX_CHATS = 40;
const MAX_MESSAGES = 40;

/** @type {{role: string, content: string}[]} */
let history = [];
let streaming = false;
/** @type {Record<string, string[]>} */
let quickPrompts = {};
let lastSetupCommand = "";
let backendReady = false;
let hermesSessionId = localStorage.getItem("hermesSessionId") || "";
let resetHermesNext = false;
let autoSwitchAttempted = false;
/** @type {string} */
let currentChatId = "";
/** @type {{id: string, title: string, createdAt: number, updatedAt: number, mode: string, messages: {role: string, content: string}[]}[]} */
let chatStore = [];

function on(el, event, handler) {
  if (el) el.addEventListener(event, handler);
}

function uid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return `c_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 9)}`;
}

function titleFromMessages(messages) {
  const firstUser = (messages || []).find((m) => m.role === "user" && m.content.trim());
  if (!firstUser) return "New chat";
  const t = firstUser.content.trim().replace(/\s+/g, " ");
  return t.length > 42 ? `${t.slice(0, 42)}…` : t;
}

function formatChatTime(ts) {
  const d = new Date(ts || Date.now());
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  if (sameDay) {
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}

function loadChatStore() {
  try {
    let raw = localStorage.getItem(CHAT_STORE_KEY);
    if (!raw) {
      raw = localStorage.getItem(CHAT_STORE_LEGACY);
      if (raw) {
        localStorage.setItem(CHAT_STORE_KEY, raw);
      }
    }
    if (!raw) {
      chatStore = [];
      currentChatId = "";
      return;
    }
    const data = JSON.parse(raw);
    chatStore = Array.isArray(data.chats) ? data.chats : [];
    currentChatId = data.currentId || (chatStore[0] && chatStore[0].id) || "";
  } catch {
    chatStore = [];
    currentChatId = "";
  }
}

function saveChatStore() {
  try {
    localStorage.setItem(
      CHAT_STORE_KEY,
      JSON.stringify({
        currentId: currentChatId,
        chats: chatStore.slice(0, MAX_CHATS),
      })
    );
  } catch {
    /* quota / private mode */
  }
}

function getCurrentChat() {
  return chatStore.find((c) => c.id === currentChatId) || null;
}

function persistCurrentChat() {
  const chat = getCurrentChat();
  if (!chat) return;
  chat.messages = history.slice(-MAX_MESSAGES);
  chat.updatedAt = Date.now();
  chat.mode = modeEl?.value || chat.mode || "default";
  chat.title = titleFromMessages(chat.messages);
  chatStore = [chat, ...chatStore.filter((c) => c.id !== chat.id)].slice(0, MAX_CHATS);
  saveChatStore();
  renderChatList();
  updateChatTitle();
}

function updateChatTitle() {
  const chat = getCurrentChat();
  const title = chat?.title || "New chat";
  if (topbarChatTitleEl) topbarChatTitleEl.textContent = title;
  document.title = `${title} — SecuraIQ`;
}

function renderTranscript(messages) {
  chatEl.innerHTML = "";
  for (const msg of messages || []) {
    if (msg.role === "assistant") {
      appendMessage("assistant", renderMarkdown(msg.content || ""), true);
    } else if (msg.role === "user") {
      appendMessage("user", msg.content || "", false);
    }
  }
  syncEmptyState();
  chatEl.scrollTop = chatEl.scrollHeight;
}

function renderChatList() {
  if (!chatListEl) return;
  chatListEl.innerHTML = "";
  const sorted = [...chatStore].sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
  for (const chat of sorted) {
    const row = document.createElement("div");
    row.className = `chat-item${chat.id === currentChatId ? " active" : ""}`;
    row.setAttribute("role", "listitem");

    const main = document.createElement("button");
    main.type = "button";
    main.className = "chat-item-main";
    main.title = chat.title || "Chat";
    main.innerHTML = `<span class="chat-item-title">${escapeHtml(chat.title || "New chat")}</span>
      <span class="chat-item-meta">${escapeHtml(formatChatTime(chat.updatedAt))}</span>`;
    main.addEventListener("click", () => openChat(chat.id));

    const del = document.createElement("button");
    del.type = "button";
    del.className = "chat-item-delete";
    del.title = "Delete chat";
    del.setAttribute("aria-label", "Delete chat");
    del.textContent = "×";
    del.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteChat(chat.id);
    });

    row.append(main, del);
    chatListEl.appendChild(row);
  }
}

function createChat(activate = true, { clearUi = true } = {}) {
  const chat = {
    id: uid(),
    title: "New chat",
    createdAt: Date.now(),
    updatedAt: Date.now(),
    mode: modeEl?.value || "default",
    messages: [],
  };
  chatStore = [chat, ...chatStore].slice(0, MAX_CHATS);
  if (activate) {
    currentChatId = chat.id;
    if (clearUi) {
      history = [];
      chatEl.innerHTML = "";
      syncEmptyState();
    }
    updateChatTitle();
  }
  saveChatStore();
  renderChatList();
  return chat;
}

function openChat(id) {
  if (typeof showView === "function") showView("chat", { skipFocus: true });
  if (streaming) return;
  if (!id || id === currentChatId) {
    closeSidebar();
    return;
  }
  const chat = chatStore.find((c) => c.id === id);
  if (!chat) return;

  persistCurrentChat();

  const activate = (c) => {
    currentChatId = c.id;
    serverChatId = c.serverId || (c.fromServer ? c.id : null);
    history = (c.messages || []).slice(-MAX_MESSAGES);
    if (c.mode && modeEl) {
      modeEl.value = c.mode;
      updateModeLabel();
      renderQuickPrompts();
    }
    renderTranscript(history);
    updateChatTitle();
    saveChatStore();
    renderChatList();
    closeSidebar();
    inputEl?.focus();
  };

  if (chat.fromServer && !(chat.messages || []).length) {
    const sid = chat.serverId || chat.id;
    fetch(`/api/chats/${sid}`, { headers: authHeaders() })
      .then((r) => r.json())
      .then((data) => {
        chat.messages = (data.messages || []).map((m) => ({
          role: m.role,
          content: m.content,
        }));
        chat.title = (data.chat || {}).title || chat.title;
        chat.mode = (data.chat || {}).mode || chat.mode;
        activate(chat);
      })
      .catch(() => activate(chat));
    return;
  }
  activate(chat);
}

function deleteChat(id) {
  if (streaming) return;
  const doomed = chatStore.find((c) => c.id === id);
  const sid = doomed?.serverId || (doomed?.fromServer ? doomed.id : null);
  if (sid) {
    fetch(`/api/chats/${sid}`, { method: "DELETE", headers: authHeaders() }).catch(() => {});
  }
  const next = chatStore.filter((c) => c.id !== id);
  chatStore = next;
  if (currentChatId === id) {
    if (chatStore.length) {
      currentChatId = chatStore[0].id;
      history = (chatStore[0].messages || []).slice(-MAX_MESSAGES);
      renderTranscript(history);
      if (chatStore[0].mode && modeEl) {
        modeEl.value = chatStore[0].mode;
        updateModeLabel();
        renderQuickPrompts();
      }
    } else {
      createChat(true);
      return;
    }
  }
  saveChatStore();
  renderChatList();
  updateChatTitle();
}

async function syncServerChats() {
  try {
    const res = await fetch("/api/chats", { headers: authHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    let changed = false;
    for (const c of data.chats || []) {
      if (chatStore.some((x) => x.serverId === c.id || x.id === c.id)) continue;
      chatStore.push({
        id: c.id,
        serverId: c.id,
        fromServer: true,
        title: c.title || "Server chat",
        mode: c.mode || "default",
        messages: [],
        createdAt: Date.parse(c.created_at || "") || Date.now(),
        updatedAt: Date.parse(c.updated_at || c.created_at || "") || Date.now(),
      });
      changed = true;
    }
    if (changed) {
      chatStore = chatStore.slice(0, MAX_CHATS);
      saveChatStore();
      renderChatList();
    }
  } catch {
    /* ignore */
  }
}

function newChat() {
  if (streaming) return;
  const current = getCurrentChat();
  if (current && (!history || history.length === 0)) {
    // Already on empty chat
    chatEl.innerHTML = "";
    syncEmptyState();
    updateChatTitle();
    closeSidebar();
    inputEl?.focus();
    renderChatList();
    return;
  }
  persistCurrentChat();
  createChat(true);
  closeSidebar();
  inputEl?.focus();
}

function ensureActiveChat() {
  loadChatStore();
  if (!currentChatId || !getCurrentChat()) {
    if (chatStore.length) {
      currentChatId = chatStore[0].id;
    } else {
      createChat(true);
      return;
    }
  }
  const chat = getCurrentChat();
  history = (chat.messages || []).slice(-MAX_MESSAGES);
  if (chat.mode && modeEl) {
    modeEl.value = chat.mode;
  }
  renderTranscript(history);
  updateChatTitle();
  renderChatList();
  updateModeLabel();
}

if (typeof marked !== "undefined" && marked.setOptions) {
  marked.setOptions({ breaks: true, gfm: true });
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatApiDetail(detail, fallback) {
  if (detail == null || detail === "") return fallback || "Request failed";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => (typeof d === "string" ? d : d?.msg || JSON.stringify(d)))
      .join("; ");
  }
  if (typeof detail === "object" && detail.msg) return String(detail.msg);
  try {
    return JSON.stringify(detail);
  } catch {
    return fallback || "Request failed";
  }
}

/** Refresh the open module page after modal CRUD so tables stay in sync. */
function refreshActiveWorkspace(view) {
  if (typeof loadCommandCenter === "function") loadCommandCenter();
  if (typeof window.showWorkspace !== "function") return;
  const map = {
    assets: "assets",
    risks: "risks",
    vulns: "vulns",
    remediations: "remediations",
    playbooks: "playbooks",
    campaigns: "campaigns",
    frameworks: "frameworks",
  };
  const target = map[view];
  if (!target) return;
  const panel = document.querySelector(`.workspace-view[data-view-panel="${target}"]`);
  const visible = panel && !panel.classList.contains("hidden");
  if (visible) window.showWorkspace(target);
}

function notifyUser(md, opts) {
  opts = opts || {};
  const text = String(md || "");
  // Prefer visible toast on module pages; also mirror to chat when asked
  let toast = document.getElementById("securaiqToast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "securaiqToast";
    toast.className = "securaiq-toast hidden";
    toast.setAttribute("role", "status");
    document.body.appendChild(toast);
  }
  toast.innerHTML = typeof renderMarkdown === "function" ? renderMarkdown(text) : escapeHtml(text);
  toast.classList.remove("hidden");
  clearTimeout(toast._hideTimer);
  toast._hideTimer = setTimeout(() => toast.classList.add("hidden"), 4500);
  if (opts.toChat && typeof appendMessage === "function") {
    if (opts.openChat && typeof showView === "function") showView("chat");
    appendMessage("assistant", typeof renderMarkdown === "function" ? renderMarkdown(text) : text, true);
  }
}
window.notifyUser = notifyUser;
window.formatApiDetail = formatApiDetail;
window.openGap = openGap;
window.runGapAnalysis = runGapAnalysis;
window.refreshActiveWorkspace = refreshActiveWorkspace;

function renderMarkdown(text) {
  let html;
  if (typeof marked !== "undefined" && typeof marked.parse === "function") {
    html = marked.parse(text ?? "");
  } else {
    html = `<pre class="md-fallback">${escapeHtml(text ?? "")}</pre>`;
  }
  return sanitizeHtml(html);
}

function sanitizeHtml(html) {
  try {
    const tpl = document.createElement("template");
    tpl.innerHTML = String(html || "");
    tpl.content.querySelectorAll("script,iframe,object,embed,form,link,meta").forEach((el) => el.remove());
    tpl.content.querySelectorAll("*").forEach((el) => {
      [...el.attributes].forEach((attr) => {
        const n = attr.name.toLowerCase();
        const v = attr.value || "";
        if (n.startsWith("on") || n === "srcdoc" || n === "xlink:href") {
          el.removeAttribute(attr.name);
          return;
        }
        if ((n === "href" || n === "src") && /^\s*javascript:/i.test(v)) {
          el.removeAttribute(attr.name);
        }
      });
    });
    return tpl.innerHTML;
  } catch {
    return escapeHtml(String(html || ""));
  }
}


/* === COMMAND_CENTER_V29 === */

function wireCommandCenterUi() {
  if (window.__securaiqCcWired) return;
  window.__securaiqCcWired = true;
  const navCmd = document.getElementById("navCommand");
  const navAi = document.getElementById("navChat");
  on(navCmd, "click", () => showView("command"));
  on(navAi, "click", () => showView("chat"));
  document.getElementById("riskMatrixBtn")?.addEventListener("click", () => {
    showView("command");
    setTimeout(() => document.getElementById("ccHeatMap")?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
  });
  // Collapsible nav groups
  document.querySelectorAll("[data-nav-group] .nav-group-toggle").forEach((btn) => {
    const group = btn.closest("[data-nav-group]");
    const expanded = btn.getAttribute("aria-expanded") !== "false";
    group?.classList.toggle("collapsed", !expanded);
    btn.addEventListener("click", () => {
      const open = btn.getAttribute("aria-expanded") !== "false";
      btn.setAttribute("aria-expanded", open ? "false" : "true");
      group?.classList.toggle("collapsed", open);
    });
  });
  // Top enterprise nav
  on(document.getElementById("topSettingsBtn"), "click", () => openSettings());
  on(document.getElementById("topProfileBtn"), "click", () => openAuth());
  on(document.getElementById("topOrgBtn"), "click", () => {
    if (typeof window.showWorkspace === "function") window.showWorkspace("orgs");
  });
  on(document.getElementById("topProjectsBtn"), "click", () => {
    document.getElementById("engagementSelect")?.focus();
    notifyUser("**Projects** — use the Project selector in the sidebar (engagements).");
  });
  document.querySelectorAll("[data-open-settings]").forEach((el) => el.addEventListener("click", () => openSettings()));
  document.querySelectorAll("[data-open-auth]").forEach((el) => el.addEventListener("click", () => openAuth()));
  document.querySelectorAll("[data-open-upload]").forEach((el) =>
    el.addEventListener("click", () => fileUploadInput?.click())
  );
  document.querySelectorAll("[data-module]").forEach((el) => {
    el.addEventListener("click", (e) => {
      const mod = el.getAttribute("data-module");
      const ws = el.getAttribute("data-workspace");
      if (ws && typeof window.showWorkspace === "function") {
        e.preventDefault();
        window.showWorkspace(ws);
        return;
      }
      handleModuleAction(mod);
    });
  });
  document.querySelectorAll("[data-view][data-prompt], [data-view][data-mode], [data-view][data-ai-tab], .agent-chip").forEach((el) => {
    if (el.id === "navCommand" || el.id === "navChat") return;
    el.addEventListener("click", () => {
      const view = el.getAttribute("data-view");
      if (view === "chat" || el.classList.contains("agent-chip")) {
        if (el.getAttribute("data-ai-tab")) {
          showView("chat");
          openAiTab(el.getAttribute("data-ai-tab"));
          if (el.getAttribute("data-ai-tab") === "tools") openToolsPalette(true);
          return;
        }
        runNavPrompt(el.getAttribute("data-mode"), el.getAttribute("data-prompt"));
      } else if (view === "command") {
        showView("command");
      }
    });
  });
  document.querySelectorAll(".intent-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const intent = chip.getAttribute("data-intent");
      const more = chip.closest(".intent-more");
      if (more) more.open = false;
      showView("chat");
      if (intent === "attach") {
        chatAttachInput?.click();
        return;
      }
      if (intent === "search") {
        if (webSearchEl) webSearchEl.checked = true;
        chip.classList.add("active");
        inputEl?.focus();
        return;
      }
      if (intent === "tools") {
        openAiTab("tools");
        openToolsPalette(true);
        return;
      }
      const mode = chip.getAttribute("data-mode");
      const prompt = chip.getAttribute("data-prompt");
      runNavPrompt(mode, prompt);
    });
  });
  // Global search handled by workspace.js (API search) — fallback only if not present
  if (!window.__securaiqSearchWired) {
    const search = document.getElementById("globalSearch");
    on(search || globalSearchEl, "keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        const el = search || globalSearchEl;
        handleGlobalSearch(el && el.value ? el.value : "");
      }
    });
  }
  wireToolsPalette();
  wireLiveScanActions(document);
  bindNewScanModal();
  document.querySelectorAll("#emptySuite .suite-chip").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.getAttribute("data-action") === "live-scan" || btn.getAttribute("data-action") === "new-scan") return;
      if (btn.getAttribute("data-ai-tab")) {
        showView("chat");
        openAiTab(btn.getAttribute("data-ai-tab"));
        if (btn.getAttribute("data-ai-tab") === "tools") openToolsPalette(true);
      } else if (btn.getAttribute("data-workspace") && typeof window.showWorkspace === "function") {
        window.showWorkspace(btn.getAttribute("data-workspace"));
      } else if (btn.getAttribute("data-module")) {
        handleModuleAction(btn.getAttribute("data-module"));
      }
    });
  });
}

function openAiTab(name) {
  document.querySelectorAll(".ai-tab").forEach((t) => {
    t.classList.toggle("active", t.getAttribute("data-ai-tab") === name);
  });
  document.querySelectorAll(".ai-tab-panel").forEach((p) => p.classList.add("hidden"));
  const panel = document.getElementById(`aiTab-${name}`);
  if (panel) panel.classList.remove("hidden");
  if (name === "tools" && typeof window.refreshAiToolsTab === "function") window.refreshAiToolsTab();
  if (name === "files" && typeof window.refreshAiFilesTab === "function") window.refreshAiFilesTab();
  if (name === "memory" && typeof window.refreshAiMemoryTab === "function") window.refreshAiMemoryTab();
  if (name === "tasks" && typeof window.refreshAiTasksTab === "function") window.refreshAiTasksTab();
  if (name === "automation" && typeof window.refreshAutomationPage === "function") {
    window.refreshAutomationPage();
  }
  if (name === "canvas") {
    const ta = document.getElementById("aiCanvasNotes");
    if (ta && !ta.value) {
      try {
        ta.value = localStorage.getItem("securaiq.canvas") || "";
      } catch {
        /* ignore */
      }
    }
  }
}
window.openAiTab = openAiTab;

function updateToolsChipState() {
  const chip = document.querySelector('.intent-chip[data-intent="tools"]');
  if (chip) chip.classList.toggle("active", selectedTools.length > 0);
  if (localToolsEl && selectedTools.length) localToolsEl.checked = true;
  if (toolsStatusEl && selectedTools.length) {
    toolsStatusEl.textContent = `Selected tools: ${selectedTools.join(", ")}`;
  }
}

function syncToolsPaletteSelection() {
  if (!toolsPaletteGridEl) return;
  toolsPaletteGridEl.querySelectorAll(".tool-pick").forEach((el) => {
    const id = el.getAttribute("data-id");
    el.classList.toggle("selected", selectedTools.includes(id));
    const cb = el.querySelector("input");
    if (cb) cb.checked = selectedTools.includes(id);
  });
}

function openToolsPalette(forceOpen) {
  if (!toolsPaletteEl) return;
  const opening = forceOpen || toolsPaletteEl.classList.contains("hidden");
  toolsPaletteEl.classList.toggle("hidden", !opening);
  if (opening) {
    syncScanTargetFields(false);
    renderToolsPalette().catch(() => {});
  }
}
window.openToolsPalette = openToolsPalette;

async function renderToolsPalette() {
  if (!toolsPaletteGridEl) return;
  try {
    const [toolsRes, scannersRes] = await Promise.all([
      fetch("/api/tools", { headers: authHeaders() }),
      fetch("/api/scans/scanners", { headers: authHeaders() }).catch(() => null),
    ]);
    const data = await toolsRes.json();
    toolsCatalogCache = data.tools || [];
    let scanners = [];
    if (scannersRes && scannersRes.ok) {
      const scData = await scannersRes.json().catch(() => ({}));
      scanners = Array.isArray(scData.scanners) ? scData.scanners : [];
      const engineSel = document.getElementById("toolsEngineScanner");
      if (engineSel && scanners.length) {
        const cur = engineSel.value || "securaiq";
        const enabled = scanners.filter((s) => s.engine_enabled);
        const opts = [
          '<option value="combo">Engine: Integrated VA (all scanners)</option>',
          '<option value="securaiq">Engine: SecuraIQ only</option>',
          '<option value="all">Engine: all available</option>',
          ...enabled
            .filter((s) => s.id !== "securaiq")
            .map((s) => {
              const label = s.available ? s.name : `${s.name} (fallback/PATH)`;
              return `<option value="${escapeHtml(s.id)}">Engine: ${escapeHtml(label)}</option>`;
            }),
          '<option value="none">Engine: off (tools only)</option>',
        ];
        engineSel.innerHTML = opts.join("");
        const prefer = "combo";
        if ([...engineSel.options].some((o) => o.value === prefer)) engineSel.value = prefer;
        else if ([...engineSel.options].some((o) => o.value === cur)) engineSel.value = cur;
      }
    }
    const originMeta = {
      securaiq: {
        label: "SecuraIQ tools",
        hint: "Built-in — no install · findings save with Auth",
      },
      third_party: {
        label: "Third-party tools & APIs",
        hint: "PATH binaries or vendor APIs · missing tools use builtin fallback",
      },
    };
    const byOrigin = { securaiq: {}, third_party: {} };
    toolsCatalogCache.forEach((t) => {
      const origin = t.origin === "third_party" ? "third_party" : "securaiq";
      const cat = t.category || "other";
      (byOrigin[origin][cat] = byOrigin[origin][cat] || []).push(t);
    });
    const renderTool = (t) => {
      const selectable = t.available || !!t.fallback;
      const readyLabel = t.available
        ? t.heavy
          ? "heavy"
          : "ready"
        : t.fallback
          ? `fallback → ${t.fallback}`
          : t.origin === "third_party"
            ? t.kind === "external"
              ? "not installed"
              : "API not configured"
            : "unavailable";
      const provider =
        t.origin === "third_party" && t.provider ? ` · ${t.provider}` : "";
      return `<label class="tool-pick tool-origin-${escapeHtml(t.origin || "securaiq")} ${
        selectable ? "" : "unavailable"
      } ${selectedTools.includes(t.id) ? "selected" : ""}" data-id="${escapeHtml(
        t.id
      )}" title="${escapeHtml(t.description || "")}">
                <input type="checkbox" ${selectedTools.includes(t.id) ? "checked" : ""} ${
        selectable ? "" : "disabled"
      } />
                <span><strong>${escapeHtml(t.name || t.id)}</strong>
                <small>${escapeHtml(readyLabel)}${escapeHtml(provider)}</small></span>
              </label>`;
    };
    const engineSection = scanners.length
      ? `<section class="tools-origin tools-origin-engine">
          <header class="tools-origin-head">
            <strong>Scan engine</strong>
            <span class="hint">${scanners.filter((s) => s.available).length}/${scanners.length} available · Queue engine scan or Run all</span>
          </header>
          <div class="tools-cat-grid">${scanners
            .map((s) => {
              const ready = s.available ? "ready" : s.engine_enabled ? "PATH / fallback" : "disabled";
              return `<div class="tool-pick tool-origin-securaiq" title="${escapeHtml(s.description || s.name || "")}">
                <span><strong>${escapeHtml(s.name || s.id)}</strong><small>${escapeHtml(ready)}</small></span>
              </div>`;
            })
            .join("")}</div>
        </section>`
      : "";
    toolsPaletteGridEl.innerHTML =
      engineSection +
      ["securaiq", "third_party"]
        .map((origin) => {
          const cats = byOrigin[origin] || {};
          const entries = Object.entries(cats);
          if (!entries.length) return "";
          const meta = originMeta[origin];
          const avail =
            origin === "securaiq" ? data.securaiq_available : data.third_party_available;
          const total = origin === "securaiq" ? data.securaiq_count : data.third_party_count;
          return `<section class="tools-origin tools-origin-${origin}">
          <header class="tools-origin-head">
            <strong>${escapeHtml(meta.label)}</strong>
            <span class="hint">${avail || 0}/${total || 0} ready · ${escapeHtml(meta.hint)}</span>
          </header>
          ${entries
            .map(
              ([cat, tools]) =>
                `<div class="tools-cat"><p class="sidebar-label">${escapeHtml(
                  cat
                )}</p><div class="tools-cat-grid">${tools.map(renderTool).join("")}</div></div>`
            )
            .join("")}
        </section>`;
        })
        .join("");
    toolsPaletteGridEl.querySelectorAll(".tool-pick[data-id]").forEach((el) => {
      el.addEventListener("click", (e) => {
        if (el.classList.contains("unavailable")) return;
        e.preventDefault();
        const id = el.getAttribute("data-id");
        if (selectedTools.includes(id)) selectedTools = selectedTools.filter((x) => x !== id);
        else selectedTools.push(id);
        syncToolsPaletteSelection();
        updateToolsChipState();
      });
    });
    const hint = document.getElementById("toolsPaletteHint");
    if (hint) {
      hint.textContent = `Engine + SecuraIQ ${data.securaiq_available || 0}/${data.securaiq_count || 0} · third-party ${
        data.third_party_available || 0
      }/${data.third_party_count || 0} · Auth + owned target`;
    }
  } catch (err) {
    toolsPaletteGridEl.innerHTML = `<p class="hint">Tools unavailable: ${escapeHtml(err.message)}</p>`;
  }
}

function wireToolsPalette() {
  if (window.__securaiqToolsWired) return;
  window.__securaiqToolsWired = true;
  on(document.getElementById("toolsPaletteClose"), "click", () => toolsPaletteEl?.classList.add("hidden"));
  on(document.getElementById("toolsPaletteClear"), "click", () => {
    selectedTools = [];
    syncToolsPaletteSelection();
    updateToolsChipState();
    loadToolsStatus();
  });
  on(document.getElementById("toolsPalettePtPack"), "click", async () => {
    try {
      const res = await fetch("/api/tools", { headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      const pack = Array.isArray(data.pt_pack) && data.pt_pack.length
        ? data.pt_pack
        : LIVE_SCAN_DEFAULT_TOOLS;
      selectedTools = pack.slice();
      syncToolsPaletteSelection();
      updateToolsChipState();
      const hint = document.getElementById("toolsPaletteHint");
      if (hint) hint.textContent = `PT pack selected (${selectedTools.length} tools) · Auth + Run all`;
      if (typeof notifyUser === "function") {
        notifyUser(`**PT pack ready:** ${selectedTools.join(", ")}`);
      }
    } catch (err) {
      selectedTools = LIVE_SCAN_DEFAULT_TOOLS.slice();
      syncToolsPaletteSelection();
      updateToolsChipState();
    }
  });
  on(document.getElementById("toolsPaletteEngineRun"), "click", async () => {
    try {
      showView("chat");
      openAiTab("chat");
      await queueEngineScanFromTools({ poll: true });
    } catch (err) {
      appendMessage("assistant", renderMarkdown(`**Engine scan failed:** ${err.message || err}`), true);
    }
  });
  on(document.getElementById("toolsPaletteSyncSiem"), "click", async () => {
    try {
      await syncSiemFromTools();
    } catch (err) {
      appendMessage("assistant", renderMarkdown(`**SIEM sync failed:** ${err.message || err}`), true);
    }
  });
  on(document.getElementById("toolsPaletteSyncXdr"), "click", async () => {
    try {
      await syncXdrFromTools();
    } catch (err) {
      appendMessage("assistant", renderMarkdown(`**XDR sync failed:** ${err.message || err}`), true);
    }
  });
  on(document.getElementById("toolsPaletteSyncInv"), "click", async () => {
    try {
      await syncInventoryFromTools();
    } catch (err) {
      appendMessage("assistant", renderMarkdown(`**Inventory sync failed:** ${err.message || err}`), true);
    }
  });
  on(document.getElementById("toolsPaletteNewScan"), "click", () => {
    toolsPaletteEl?.classList.add("hidden");
    if (typeof openNewScanModal === "function") openNewScanModal();
  });
  on(document.getElementById("toolsPaletteUseChat"), "click", () => {
    if (localToolsEl) localToolsEl.checked = true;
    toolsPaletteEl?.classList.add("hidden");
    openAiTab("chat");
    if (inputEl && selectedTools.length && !inputEl.value.trim()) {
      inputEl.value = `Run ${selectedTools.join(", ")} on the authorized target and summarize findings with remediations.`;
      resizeInput();
    }
    inputEl?.focus();
    updateToolsChipState();
  });
  on(document.getElementById("toolsPaletteRun"), "click", () => runAllFromTools());
  on(scanTargetIpEl, "input", () => syncScanTargetFields(true));
  on(scanTargetIpEl, "keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      runAllFromTools();
    }
  });
  on(scanAuthorizedEl, "change", () => syncScanTargetFields(true));
  on(targetIpEl, "input", () => syncScanTargetFields(false));
  on(authorizedTargetEl, "change", () => syncScanTargetFields(false));
  syncScanTargetFields(false);
}

async function runSelectedTools() {
  syncScanTargetFields(true);
  const target = getScanTarget();
  const authorized = getScanAuthorized();
  if (!selectedTools.length) {
    appendMessage("assistant", renderMarkdown("**Select at least one tool** in the palette first."), true);
    return;
  }
  if (!target) {
    appendMessage(
      "assistant",
      renderMarkdown(
        "**Set a Target** in the Live scan bar (owned IP/host or local code path) and keep **Auth** checked so findings and assets save live."
      ),
      true
    );
    showView("chat");
    openToolsPalette(true);
    (scanTargetIpEl || targetIpEl)?.focus();
    return;
  }
  if (authorizedTargetEl) authorizedTargetEl.checked = authorized;
  if (targetIpEl) targetIpEl.value = target;
  if (!authorized) {
    appendMessage(
      "assistant",
      renderMarkdown(
        "**Auth is off** — tools will run but **assets and vulnerabilities will not be saved**. Check **Auth** only for systems you own or are authorized to assess."
      ),
      true
    );
  }
  showView("chat");
  openAiTab("chat");
  appendMessage(
    "user",
    `Run tools [${selectedTools.join(", ")}] on ${target}${authorized ? " (authorized)" : ""}`
  );
  const toolList = selectedTools.join(", ");
  const bubble = appendMessage(
    "assistant",
    renderMarkdown(`**Running security tools** on \`${target}\`…\n\n\`${toolList}\``),
    true
  );
  streaming = true;
  window.__securaiqStreaming = true;
  setLiveState("live-busy", "Running security tools…", toolList);
  const doneRuns = [];
  try {
    const res = await fetch("/api/tools/run/stream", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        target,
        tools: selectedTools,
        authorized_target: authorized,
        engagement_id: engagementSelectEl?.value || null,
        message: `authorized assessment of ${target}`,
      }),
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
        if (ev.event === "start") {
          const list = (ev.tools || selectedTools).join(", ");
          if (toolsPaletteOutEl) {
            toolsPaletteOutEl.classList.remove("hidden");
            toolsPaletteOutEl.textContent = `Running: ${list}`;
          }
        } else if (ev.event === "tool_progress") {
          const scanned = Number(ev.scanned || 0);
          const total = Number(ev.total || 0);
          const findings = Number(ev.findings || 0);
          const label = `Code scan ${scanned}/${total || "?"} · ${findings} hit(s)`;
          setLiveState("live-busy", label, ev.file || toolList);
          if (toolsPaletteOutEl) {
            toolsPaletteOutEl.classList.remove("hidden");
            toolsPaletteOutEl.textContent = label + (ev.file ? ` · ${ev.file}` : "");
          }
        } else if (ev.event === "tool_done" && ev.run) {
          doneRuns.push(ev.run);
          if (toolsPaletteOutEl) {
            const preview = doneRuns
              .map((r) => `${r.name || r.tool}: ${r.ok ? "OK" : "FAIL"}`)
              .join(" · ");
            toolsPaletteOutEl.classList.remove("hidden");
            toolsPaletteOutEl.textContent = preview;
          }
        } else if (ev.event === "done") {
          data = ev.payload || {};
        }
      }
    }
    if (!data) data = { ok: false, error: "No tool output", runs: doneRuns, target };
    let md = data.markdown || "";
    if (!md && Array.isArray(data.runs)) {
      md = data.runs
        .map((r) => {
          const status = r.ok ? "OK" : "FAIL";
          const body = r.output || r.error || JSON.stringify(r);
          return `### ${r.name || r.tool || r.id} [${status}]\n\`\`\`\n${body}\n\`\`\``;
        })
        .join("\n\n");
    }
    if (!md) md = data.error || "```json\n" + JSON.stringify(data, null, 2) + "\n```";
    const vp = data.vulnerabilities_persisted || {};
    let persistNote = "";
    if (vp.ok && (vp.created || vp.asset_id)) {
      const bits = [];
      if (vp.asset_name || vp.asset_id) bits.push(`asset \`${vp.asset_name || vp.asset_id}\``);
      if (vp.created) bits.push(`**${vp.created}** finding(s) saved`);
      else bits.push("inventory updated (no new findings)");
      persistNote = `\n\n**Live inventory:** ${bits.join(" · ")} — open **Assets** / **Vulnerabilities** / Mission Control.`;
    } else if (vp.error) {
      persistNote = `\n\n**Persist warning:** ${vp.error}`;
    } else if (!data.authorized && !authorized) {
      persistNote =
        "\n\n_Findings were not saved — enable **Auth** for owned targets to populate Assets and Vulnerabilities._";
    }
    bubble.innerHTML = renderMarkdown(
      `**Tool run ${data.ok ? "complete" : "finished with errors"}** · target \`${data.target || target}\`${data.light ? " · light" : ""}${persistNote}\n\n${md}`
    );
    if (toolsPaletteOutEl) {
      toolsPaletteOutEl.classList.remove("hidden");
      toolsPaletteOutEl.textContent = typeof md === "string" ? md.slice(0, 4000) : JSON.stringify(data, null, 2);
    }
    if (vp.ok && (vp.created || vp.asset_id)) {
      try {
        if (typeof loadAssets === "function") loadAssets();
        if (typeof loadVulns === "function") loadVulns();
        if (typeof loadCommandCenter === "function") loadCommandCenter();
      } catch {
        /* ignore refresh errors */
      }
    }
    setLiveState("live-on", "Ready", "");
  } catch (err) {
    bubble.innerHTML = renderMarkdown(`**Tool run failed:** ${err.message}`);
    setLiveState("live-off", "Tools error", "");
  } finally {
    streaming = false;
    window.__securaiqStreaming = false;
  }
}
window.runSelectedTools = runSelectedTools;

/** Ask AI about an ops entity (asset/risk/vuln/rem/incident). */
function askAboutEntity(kind, payload) {
  const p = payload || {};
  const map = {
    asset: {
      mode: "assess",
      prompt: `Triage asset "${p.name || p.id}" (type=${p.asset_type || "?"}, criticality=${p.criticality || "?"}). Suggest monitoring, hardening, and mapping to risks/vulns.`,
    },
    risk: {
      mode: "ciso",
      prompt: `Analyze risk "${p.threat || p.id}" (score=${p.risk_score || "?"}, L=${p.likelihood} I=${p.impact}). Propose mitigation owners, SLA, and residual risk.`,
    },
    vuln: {
      mode: "blueteam",
      prompt: `Triage vulnerability ${p.cve || ""} — ${p.title || p.id} (severity=${p.severity || "?"}, asset=${p.asset_name || "?"}, exposure=${p.scope || "unknown"}).

Rules:
- If asset is 127.0.0.1, ::1, or localhost: loopback-only — not internet-exposed.
- If asset is RFC1918 (10/8, 172.16/12, 192.168/16) and finding is SMB/445, MSRPC/135, or NetBIOS/139: treat as expected Windows LAN service (info/low residual). Do NOT call it High ransomware exposure unless internet-facing.
- VirtualBox/VMware host-only gateway (.1) is usually the host, not the lab VM — say so.
- Only recommend real commands (nmap, Windows Firewall, Get-SmbServerConfiguration / Set-SmbServerConfiguration -RequireSecuritySignature $true). Never invent tools (no vulcanize, fake firewall CLIs, or made-up smbclient flags).
- Be concrete: detection, harden/verify, owner. No generic marketing.`,
    },
    remediation: {
      mode: "ciso",
      prompt: `Draft implementation guidance for remediation ${p.control_id || ""} — ${p.title || p.id}. Include evidence to collect, owner checklist, and verification steps.`,
    },
    incident: {
      mode: "ir",
      prompt: `Incident response plan for "${p.title || p.id}" (severity=${p.severity || "high"}). Cover contain, eradicate, recover, and comms for an authorized org.`,
    },
  };
  const cfg = map[kind] || { mode: "default", prompt: `Explain and recommend actions for ${kind}: ${JSON.stringify(p)}` };
  runNavPrompt(cfg.mode, cfg.prompt, { stay: true });
}
window.askAboutEntity = askAboutEntity;

/** Ask AI using real scan evidence (report.md via /api/ai/investigate-scan). */
async function askAboutScan(scanId, summary) {
  const sid = String(scanId || "").trim();
  if (!sid) return;
  let prompt = "";
  try {
    const res = await fetch("/api/ai/investigate-scan", {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: sid }),
    });
    if (res.ok) {
      const data = await res.json();
      prompt = data.prompt || (data.ai_prompts && data.ai_prompts[0] && data.ai_prompts[0].prompt) || "";
    }
  } catch (_) {
    /* fall through */
  }
  if (!prompt) {
    const sum = summary || {};
    try {
      const r = await fetch(`/api/scans/${encodeURIComponent(sid)}/report`, { headers: authHeaders() });
      const md = r.ok ? (await r.text()).slice(0, 12000) : "";
      prompt =
        `Investigate SecuraIQ scan \`${sid}\` using only stored evidence.\n` +
        `Risk: ${sum.risk?.score ?? "n/a"} (${sum.risk?.band || "n/a"}).\n` +
        `Do not invent scan results.\n\n--- report.md excerpt ---\n${md || "(report unavailable)"}\n`;
    } catch (_) {
      prompt =
        `Investigate scan ${sid} using only stored evidence and findings. ` +
        `Do not invent scan results.`;
    }
  }
  runNavPrompt("assess", prompt, { stay: true });
}
window.askAboutScan = askAboutScan;

let currentView = "command";
window.__setSecuraIQView = function (v) {
  currentView = v === "chat" ? "chat" : v === "command" ? "command" : "page";
};
const viewCommandEl = document.getElementById("viewCommand");
const viewChatEl = document.getElementById("viewChat");
const composerWrapEl = document.getElementById("composerWrap");
const globalSearchEl = document.getElementById("globalSearch");
const navCommandBtn = document.getElementById("navCommand");
const navChatBtn = document.getElementById("navChat");

function setNavActive(view) {
  document.querySelectorAll(".nav-item[data-view]").forEach((el) => {
    el.classList.toggle("active", el.getAttribute("data-view") === view);
  });
}

function showView(view, opts = {}) {
  const moduleViews = new Set([
    "assets", "risks", "vulns", "remediations", "playbooks", "campaigns",
    "intel", "reports", "soc", "evidence", "orgs", "frameworks",
    "integrations", "billing", "graph", "automation", "webscan", "software",
  ]);
  if (moduleViews.has(view) && typeof window.showWorkspace === "function") {
    window.showWorkspace(view, opts);
    return;
  }
  currentView = view === "chat" ? "chat" : "command";
  viewCommandEl?.classList.toggle("hidden", currentView !== "command");
  viewChatEl?.classList.toggle("hidden", currentView !== "chat");
  // Hide module pages when returning to chat/command
  document.querySelectorAll(".workspace-view[data-module-page]").forEach((el) => el.classList.add("hidden"));
  composerWrapEl?.classList.toggle("is-command", currentView === "command");
  composerWrapEl?.classList.toggle("is-page", false);
  composerWrapEl?.classList.toggle("is-chat", currentView === "chat");
  composerWrapEl?.classList.toggle("is-floating", currentView !== "chat");
  if (currentView === "chat") {
    composerWrapEl?.classList.remove("is-open");
    document.getElementById("aiFab")?.classList.add("hidden");
  } else {
    composerWrapEl?.classList.remove("is-open");
    document.getElementById("aiFab")?.classList.remove("hidden");
    document.getElementById("aiFab")?.setAttribute("aria-expanded", "false");
  }
  setNavActive(currentView);
  if (topbarChatTitleEl) {
    topbarChatTitleEl.textContent = currentView === "command" ? "Security dashboard" : (getCurrentChat()?.title || "Assistant");
  }
  if (currentView === "command") {
    loadCommandCenter();
  } else {
    syncEmptyState();
    if (!opts.skipFocus) inputEl?.focus();
  }
  closeSidebar();
}

async function loadCommandCenter() {
  if (window.__securaiqCcLoading) {
    window.__securaiqCcReloadQueued = true;
    return;
  }
  window.__securaiqCcLoading = true;
  window.__securaiqCcReloadQueued = false;
  clearTimeout(window.__securaiqCcLockTimer);
  window.__securaiqCcLockTimer = setTimeout(() => {
    if (window.__securaiqCcLoading) {
      window.__securaiqCcLoading = false;
      if (window.__securaiqCcReloadQueued) {
        window.__securaiqCcReloadQueued = false;
        loadCommandCenter();
      }
    }
  }, 20000);
  const scoreEl = document.getElementById("ccScore");
  const compEl = document.getElementById("ccCompliance");
  const barEl = document.getElementById("ccComplianceBar");
  const critEl = document.getElementById("ccCrit");
  const risksEl = document.getElementById("ccRisks");
  const remsEl = document.getElementById("ccRems");
  const assetsEl = document.getElementById("ccAssets");
  const fwEl = document.getElementById("ccFrameworks");
  const riskListEl = document.getElementById("ccTopRisks");
  const vulnListEl = document.getElementById("ccTopVulns");
  try {
    const [res, briefRes, scansRes] = await Promise.all([
      fetch("/api/dashboard", { headers: authHeaders() }),
      fetch("/api/dashboard/brief", { headers: authHeaders() }).catch(() => null),
      fetch("/api/scans?limit=6", { headers: authHeaders() }).catch(() => null),
    ]);
    const data = await res.json();
    const briefData = briefRes && briefRes.ok ? await briefRes.json().catch(() => ({})) : {};
    const scansData = scansRes && scansRes.ok ? await scansRes.json().catch(() => ({})) : {};
    const recentScans = scansData.scans || [];
    window.__securaiqRecentScans = recentScans;
    if (!res.ok) throw new Error(formatApiDetail(data.detail, `HTTP ${res.status}`));

    // Render software posture immediately — do not wait on later Mission Control sections.
    try {
      renderMcSoftwarePosturePanel(data.software_posture || {});
      window.__securaiqLastSoftwarePosture = data.software_posture || {};
      wireMcSoftwarePanelOnce();
    } catch (swErr) {
      const swEl = document.getElementById("mcSoftwarePostureBody");
      if (swEl) {
        swEl.innerHTML = `<p class="hint">Software posture unavailable: ${escapeHtml(swErr.message || String(swErr))}</p>`;
      }
    }

    const mc = data.mission_control || {};
    const compliance = Number(data.compliance_score || 0);
    const openRisks = Number(data.risks_open || 0);
    const crit = Number(data.vulnerabilities_critical_high || 0);
    const openRems = Number(data.remediations_open || 0);
    const index = Number(data.security_index != null ? data.security_index : mc.security_score) || 0;
    const emptyWorkspace =
      data.is_empty === true ||
      (!(data.assets_total || 0) &&
        !(data.vulnerabilities_total || 0) &&
        !(data.risks_total || 0) &&
        !(data.remediations_total || 0) &&
        !(data.incidents_total || 0) &&
        !(data.assessment_count || 0) &&
        !(data.intel?.watch_count || 0) &&
        !(data.playbooks_total || 0) &&
        !(data.campaigns_total || 0) &&
        !(data.software_posture?.total_products || 0) &&
        !(data.software_posture?.windows_host?.installed_apps || 0) &&
        !(data.software_posture?.coverage?.control_panel || 0));

    // KPI trends: prefer server snapshot deltas when available
    const trends = data.kpi_trends || {};
    const setTrend = (id, text, goodUp) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = text;
      el.classList.toggle("up", text.startsWith("↑") && goodUp);
      el.classList.toggle("down", text.startsWith("↓") && goodUp);
      el.classList.toggle("up-bad", text.startsWith("↑") && !goodUp);
      el.classList.toggle("down-good", text.startsWith("↓") && !goodUp);
    };
    const fmtApi = (d) => {
      const n = Number(d || 0);
      if (!n) return "";
      return n > 0 ? `↑ ${n}` : `↓ ${Math.abs(n)}`;
    };
    if (emptyWorkspace) {
      try {
        localStorage.removeItem("securaiq.kpi.snap");
        localStorage.removeItem("securaiq.chats.v1");
        localStorage.removeItem("securaiq.checklist.integrations");
      } catch {
        /* ignore */
      }
      ["ccScoreTrend", "ccCompTrend", "ccCritTrend", "ccRiskTrend", "ccRemTrend", "ccAssetTrend", "ccIncidentTrend", "ccFindingsTrend"].forEach(
        (id) => setTrend(id, "", true)
      );
    } else if (trends.has_baseline) {
      setTrend("ccScoreTrend", fmtApi(trends.security_index_delta), true);
      setTrend("ccCompTrend", fmtApi(trends.compliance_delta), true);
      setTrend("ccCritTrend", fmtApi(trends.vulns_delta), false);
      setTrend("ccRiskTrend", fmtApi(trends.risks_delta), false);
      setTrend("ccRemTrend", fmtApi(trends.rems_delta), false);
      setTrend("ccAssetTrend", fmtApi(trends.assets_delta), true);
      setTrend("ccIncidentTrend", fmtApi(trends.incidents_delta), false);
      setTrend("ccFindingsTrend", fmtApi(trends.findings_delta || trends.vulns_delta), false);
    } else {
      const snapKey = "securaiq.kpi.snap";
      let prev = {};
      try {
        prev = JSON.parse(localStorage.getItem(snapKey) || "{}");
      } catch {
        prev = {};
      }
      const delta = (cur, key) => {
        if (prev[key] == null) return "";
        const d = cur - Number(prev[key] || 0);
        if (d === 0) return "";
        return d > 0 ? `↑ ${d}` : `↓ ${Math.abs(d)}`;
      };
      setTrend("ccScoreTrend", delta(index, "index"), true);
      setTrend("ccCompTrend", delta(compliance, "comp"), true);
      setTrend("ccCritTrend", delta(crit, "crit"), false);
      setTrend("ccRiskTrend", delta(openRisks, "risks"), false);
      setTrend("ccRemTrend", delta(openRems, "rems"), false);
      setTrend("ccAssetTrend", delta(Number(data.assets_total || 0), "assets"), true);
      setTrend("ccIncidentTrend", delta(Number(data.incidents_open || 0), "incidents"), false);
      setTrend("ccFindingsTrend", delta(Number(data.vulnerabilities_total || 0), "findings"), false);
      localStorage.setItem(
        snapKey,
        JSON.stringify({
          index,
          comp: compliance,
          crit,
          risks: openRisks,
          rems: openRems,
          assets: data.assets_total || 0,
          incidents: data.incidents_open || 0,
          findings: data.vulnerabilities_total || 0,
          swIssues: data.software_posture?.issues || 0,
          at: Date.now(),
        })
      );
    }

    const complianceRounded = Math.round(emptyWorkspace ? 0 : compliance);
    const sevCounts = data.severity_counts || {};
    if (scoreEl) scoreEl.textContent = String(emptyWorkspace ? 0 : index);
    if (compEl) compEl.textContent = emptyWorkspace ? "0%" : `${complianceRounded}%`;
    if (barEl) barEl.style.width = `${Math.min(100, complianceRounded)}%`;
    if (critEl) critEl.textContent = String(emptyWorkspace ? 0 : Number(sevCounts.critical ?? crit));
    if (risksEl) risksEl.textContent = String(emptyWorkspace ? 0 : openRisks);
    if (remsEl) remsEl.textContent = String(emptyWorkspace ? 0 : openRems);
    if (assetsEl) assetsEl.textContent = String(emptyWorkspace ? 0 : data.assets_total || 0);
    const findingsTotalEl = document.getElementById("ccFindingsTotal");
    if (findingsTotalEl) {
      findingsTotalEl.textContent = String(emptyWorkspace ? 0 : data.vulnerabilities_total || 0);
    }
    const sp = data.software_posture || {};
    const swIssuesEl = document.getElementById("ccSoftwareIssues");
    const swBarEl = document.getElementById("ccSoftwareHealthBar");
    const swTrendEl = document.getElementById("ccSoftwareTrend");
    const swIssues = emptyWorkspace ? 0 : Number(sp.issues || 0) + Number((sp.windows_host || {}).pending_updates || 0);
    const swHealth = emptyWorkspace ? 100 : Number(sp.health_score ?? 100);
    if (swIssuesEl) swIssuesEl.textContent = String(swIssues);
    if (swBarEl) swBarEl.style.width = `${Math.min(100, Math.max(0, swHealth))}%`;
    const swHealthPct = document.getElementById("ccSoftwareHealthPct");
    if (swHealthPct) swHealthPct.textContent = emptyWorkspace ? "—" : `${Math.round(swHealth)}%`;
    const wzPatchEl = document.getElementById("wzPatchHealthPct");
    if (wzPatchEl) wzPatchEl.textContent = emptyWorkspace ? "—" : `${Math.round(swHealth)}%`;
    if (swTrendEl && !emptyWorkspace) {
      const prevSnap = JSON.parse(localStorage.getItem(snapKey) || "{}");
      const d = swIssues - Number(prevSnap.swIssues || 0);
      if (d === 0) swTrendEl.textContent = "";
      else swTrendEl.textContent = d > 0 ? `↑ ${d}` : `↓ ${Math.abs(d)}`;
    }
    const gauge = document.getElementById("ccScoreGauge");
    if (gauge) gauge.style.setProperty("--p", String(Math.min(100, Math.max(0, emptyWorkspace ? 0 : index))));
    const levelEl = document.getElementById("ccScoreLevel");
    if (levelEl) {
      if (emptyWorkspace) {
        levelEl.textContent = "EMPTY";
        levelEl.dataset.level = "ok";
      } else {
        const band =
          index >= 80 ? "STRONG" : index >= 60 ? "STABLE" : index >= 40 ? "MEDIUM" : "CRITICAL";
        levelEl.textContent = band;
        levelEl.dataset.level = index >= 60 ? "ok" : index >= 40 ? "warn" : "bad";
        levelEl.title = mc.security_score_note || data.security_index_note || "Live workspace score";
      }
    }
    const highCountEl = document.getElementById("sqHighCount");
    if (highCountEl) highCountEl.textContent = String(Number(sevCounts.high || 0));
    const incEl = document.getElementById("ccIncidents");
    if (incEl) incEl.textContent = String(emptyWorkspace ? 0 : data.incidents_open || 0);
    // notifBadge is now driven by the real GET /api/notifications unread_count
    // (see refreshNotifBadge()) instead of a client-side guess from crit+incidents.
    const orgFull = mc.organization || "Local workspace";
    const topOrg = document.getElementById("topOrgName");
    const topOrgBtn = document.getElementById("topOrgBtn");
    if (topOrg) {
      topOrg.textContent = shortScopeLabel(orgFull, 12);
      topOrg.title = orgFull;
    }
    if (topOrgBtn) topOrgBtn.title = `Organization: ${orgFull}`;
    const topEnv = document.getElementById("topEnvName");
    if (topEnv) {
      const env = emptyWorkspace ? "Empty" : mc.environment || "Live";
      const short = env.split(/[·/]/)[0].trim() || "Live";
      topEnv.title = env;
      topEnv.textContent = short.replace(/\s+workspace$/i, "").trim() || "Live";
    }
    const topProj = document.getElementById("topProjectName");
    const topProjBtn = document.getElementById("topProjectsBtn");
    const projFull = engagementSelectEl?.selectedOptions?.[0]?.textContent || "Local";
    if (topProj) {
      topProj.textContent = shortScopeLabel(projFull, 14);
      topProj.title = projFull;
    }
    if (topProjBtn) topProjBtn.title = `Project: ${projFull}`;

    // Mission context header
    const setTxt = (id, v) => {
      const el = document.getElementById(id);
      if (el) el.textContent = v;
    };
    setTxt("mcOrgName", mc.organization || "Local workspace");
    setTxt("mcFramework", emptyWorkspace ? "—" : mc.framework || "—");
    const brief = briefData.brief || data.morning_brief || {};
    const greetEl = document.getElementById("mcGreeting");
    if (greetEl) {
      const uname = (window.__securaiqUser || "").trim();
      const hour = new Date().getHours();
      const fallback =
        hour < 12 ? "Good morning" : hour < 17 ? "Good afternoon" : "Good evening";
      greetEl.textContent = brief.greeting
        ? `${brief.greeting}${uname ? `, ${uname}` : ""}`
        : `${fallback}${uname ? `, ${uname}` : ""}`;
    }
    const aiSum = document.getElementById("mcAiSummary");
    if (aiSum) {
      if (emptyWorkspace) {
        aiSum.textContent = "Your workspace is empty — pick a path below when you're ready.";
      } else {
        aiSum.textContent =
          brief.attention ||
          brief.summary ||
          `${crit} critical/high findings and ${openRems} open actions need review.`;
      }
    }
    const lastScan = mc.last_scan;
    if (lastScan) {
      const d = new Date(Number(lastScan) * (Number(lastScan) < 1e12 ? 1000 : 1));
      setTxt("mcLastScan", Number.isNaN(d.getTime()) ? String(lastScan) : d.toLocaleString());
    } else setTxt("mcLastScan", emptyWorkspace ? "Never" : "No scans yet");
    const todayEl = document.getElementById("mcTodaySummary");
    if (todayEl) {
      todayEl.textContent = "";
      todayEl.hidden = true;
      todayEl.classList.add("hidden");
    }

    const viewCommand = document.getElementById("viewCommand");
    const liveDash = document.getElementById("mcLiveDashboard");
    viewCommand?.classList.toggle("mc-is-empty", emptyWorkspace);
    if (liveDash) liveDash.hidden = emptyWorkspace;

    const firstRun = document.getElementById("mcFirstRun");
    if (firstRun) {
      firstRun.classList.toggle("hidden", !emptyWorkspace);
      wireMissionFirstRunOnce();
      syncChecklistProgress(data);
    }

    // Software panel already rendered at the top of loadCommandCenter.
    try {
      const whEarly = (data.software_posture || {}).windows_host || {};
      if (
        String(whEarly.platform || "").toLowerCase() === "windows" &&
        (whEarly.needs_refresh || !Number(whEarly.installed_apps || 0))
      ) {
        refreshLocalWindowsHost(false);
      }
    } catch {
      /* ignore */
    }

    if (emptyWorkspace) {
      const emptyLists = [
        "ccTopRisks",
        "ccTopVulns",
        "ccRecommendedToday",
        "ccTodayList",
        "mcDecisionActions",
        "ccWorkQueue",
      ];
      emptyLists.forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = "";
      });
      ["wfImported", "wfTriaged", "wfActions", "wfClosed"].forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.textContent = "0";
      });
      if (fwEl) fwEl.textContent = "0";
      renderMcAssetInventory(0, {});
      renderMcHardeningPanel(data.hardening || {});
      wireMcToolUpdatesOnce();
      refreshMcToolUpdates();
      return;
    }

    const wf = data.workflow || {};
    const setWf = (id, n) => {
      const el = document.getElementById(id);
      if (el) el.textContent = String(n || 0);
    };
    setWf("wfImported", wf.imported);
    setWf("wfTriaged", wf.triaged);
    setWf("wfActions", wf.actions);
    setWf("wfClosed", wf.closed);
    document.querySelectorAll(".mc-wf-step").forEach((step) => {
      const key = step.getAttribute("data-wf");
      const n = Number(wf[key] || 0);
      step.classList.toggle("active", n > 0);
      step.style.cursor = "pointer";
      step.onclick = () => {
        if (key === "actions") window.showWorkspace?.("remediations");
        else window.showWorkspace?.("vulns");
      };
    });

    // Work queue
    renderWorkQueue(data.work_queue || []);
    renderMcDecisionPanel(data);
    renderMcCharts(data);
    renderAttentionDashboard(data, recentScans);
    refreshMcIntegrations();
    renderSqPostureBars(data, index, complianceRounded);

    const recEl = document.getElementById("ccRecommendedToday");
    if (recEl) {
      const top = (data.work_queue || []).slice(0, 4);
      recEl.innerHTML = top.length
        ? `<ul class="mc-rec-list">${top
            .map(
              (w) =>
                `<li><span class="wq-badge pri-${escapeHtml(
                  (w.priority || "medium").toLowerCase()
                )}">${escapeHtml((w.priority || "medium").toUpperCase())}</span>
                <strong>${escapeHtml(w.title)}</strong></li>`
            )
            .join("")}</ul>`
        : `<p class="hint">Empty queue — add risks, vulns, or a gap assessment to prioritize work.</p>`;
    }

    const today = mc.today || {};
    const todayListEl = document.getElementById("ccTodayList");
    if (todayListEl) {
      todayListEl.innerHTML = `
        <li><strong>${today.critical_findings || 0}</strong> critical / high findings</li>
        <li><strong>${today.open_risks || 0}</strong> open risks</li>
        <li><strong>${today.open_actions || 0}</strong> open remediation actions</li>
        <li><strong>${today.open_incidents || 0}</strong> open incidents</li>
        <li><strong>${compliance}%</strong> compliance · framework <strong>${escapeHtml(
          mc.framework || "—"
        )}</strong></li>`;
    }

    // Needs attention (aggregated)
    renderSqNeedsAttention(data);

    // Correlation hotspots — VAPT + XDR + incident + control on same asset
    const corrEl = document.getElementById("ccCorrelation");
    const corrDoc = document.getElementById("ccCorrDoctrine");
    const corr = data.correlation || {};
    if (corrDoc && corr.doctrine) corrDoc.textContent = corr.doctrine;
    if (corrEl) {
      const spots = corr.hotspots || [];
      if (spots.length) {
        corrEl.innerHTML = spots
          .slice(0, 8)
          .map((h) => {
            const c = h.counts || {};
            return `<li class="cc-clickable" data-workspace="graph" data-corr="${escapeHtml(h.label || "")}">
              <strong>${escapeHtml(h.label || "asset")}</strong>
              <span class="wq-badge pri-medium">${h.disciplines || 0} disciplines</span>
              <span class="hint">${escapeHtml(h.why || "")}</span>
            </li>`;
          })
          .join("");
      } else {
        corrEl.innerHTML = `<li class="hint">No multi-discipline hotspots yet — import a scan, sync XDR, or open an incident on a named asset.</li>
          <li><button type="button" class="cc-action" data-workspace="graph">Open knowledge graph</button></li>`;
      }
      corrEl.querySelectorAll("[data-workspace]").forEach((el) =>
        el.addEventListener("click", () => {
          const q = el.getAttribute("data-corr");
          if (q) window.__securaiqGraphFocus = q;
          window.showWorkspace?.(el.getAttribute("data-workspace"));
        })
      );
    }

    // Threat intel strip
    const intelEl = document.getElementById("ccIntel");
    if (intelEl) {
      const intel = data.intel || {};
      const watch = intel.watch || [];
      if (watch.length) {
        intelEl.innerHTML = watch
          .map(
            (w) =>
              `<li class="cc-clickable" data-workspace="intel"><strong>${escapeHtml(
                w.value || ""
              )}</strong> <span class="hint">${escapeHtml(w.kind || "")} · ${escapeHtml(
                (w.notes || "").slice(0, 60)
              )}</span></li>`
          )
          .join("");
      } else {
        intelEl.innerHTML = `<li class="hint">No watchlist items — open Threat intel to add CVEs or sync CISA KEV.</li>
          <li><button type="button" class="cc-action" data-workspace="intel">Open threat intel</button></li>`;
      }
      intelEl.querySelectorAll("[data-workspace]").forEach((el) =>
        el.addEventListener("click", () => window.showWorkspace?.(el.getAttribute("data-workspace")))
      );
    }

    // Frameworks with control stats when available
    if (fwEl) {
      const stats = data.framework_control_stats || [];
      const fws = stats.length ? stats : data.frameworks || [];
      fwEl.innerHTML = fws.length
        ? fws
            .slice(0, 4)
            .map((f) => {
              const pct = Number(f.compliance_percent || 0);
              const id = f.framework_id || f.id || f.title || "Framework";
              return `<li>
                <div class="sq-fw-line"><span>${escapeHtml(id)}</span><strong>${pct}%</strong></div>
                <div class="sq-fw-bar"><i style="width:${pct}%"></i></div>
              </li>`;
            })
            .join("")
        : `<li class="hint">No gap assessments yet — run Gap analysis</li>`;
    }

    // Asset breakdown + named inventory (so Mission Control shows *which* assets, not just counts)
    renderMcAssetInventory(
      Number(data.assets_total || 0),
      data.asset_breakdown || {},
      data.recent_assets || null
    );
    renderMcHardeningPanel(data.hardening || {});
    wireMcToolUpdatesOnce();
    refreshMcToolUpdates();
    // software panel already rendered above

    if (Number(data.assets_total || 0) > 0 && typeof window.renderAssetsPage === "function") {
      window.renderAssetsPage();
    }

    // Timeline (Wazuh-style security events)
    const tlEl = document.getElementById("ccTimeline");
    if (tlEl) {
      const events = data.timeline || [];
      tlEl.innerHTML = events.length
        ? events
            .slice(0, 12)
            .map((e) => {
              const ts = e.ts ? new Date(Number(e.ts) * (Number(e.ts) < 1e12 ? 1000 : 1)) : null;
              const when = ts && !Number.isNaN(ts.getTime()) ? ts.toLocaleString() : "—";
              return `<li class="wz-event-row">
                <span class="wz-event-time">${escapeHtml(when)}</span>
                <span class="wz-event-body"><strong>${escapeHtml(e.label || "")}</strong>
                <span class="hint">${escapeHtml(e.detail || "")}</span></span></li>`;
            })
            .join("")
        : `<li class="hint">No security events yet — run a scan or sync SIEM.</li>`;
    }

    // MITRE — keyword signals from live findings (not certified coverage %)
    const mitreEl = document.getElementById("ccMitre");
    if (mitreEl) {
      const rows = (data.mitre_coverage || []).filter((r) => Number(r.hits || r.coverage) > 0);
      mitreEl.innerHTML = rows.length
        ? `<p class="hint" style="margin:0 0 0.4rem">Signals from live findings / risks / playbooks</p>${rows
            .map(
              (r) =>
                `<div class="mitre-row"><span>${escapeHtml(r.tactic)}</span>
                <div class="cc-bar"><i style="width:${Number(r.coverage) || 0}%"></i></div>
                <strong>${Number(r.hits) || 0} hit${Number(r.hits) === 1 ? "" : "s"}</strong></div>`
            )
            .join("")}`
        : `<p class="hint">No MITRE keyword signals yet — run New scan or add risks/playbooks</p>`;
    }

    if (riskListEl) {
      const rows = data.findings?.top_risks || [];
      riskListEl.innerHTML = rows.length
        ? rows
            .map(
              (r) =>
                `<li class="cc-clickable"><strong>${escapeHtml(r.risk_score)}</strong> ${escapeHtml(
                  r.threat || ""
                )}</li>`
            )
            .join("")
        : `<li class="hint">No open risks</li>`;
      riskListEl.querySelectorAll(".cc-clickable").forEach((li) =>
        li.addEventListener("click", () => window.showWorkspace?.("risks"))
      );
    }
    if (vulnListEl) {
      const rows = data.findings?.top_vulns || [];
      vulnListEl.innerHTML = rows.length
        ? rows
            .map(
              (v) =>
                `<li class="cc-clickable"><strong>${escapeHtml(v.severity)}</strong> ${escapeHtml(
                  v.cve || ""
                )} — ${escapeHtml(v.title || "")}</li>`
            )
            .join("")
        : `<li class="hint">No critical findings</li>`;
      vulnListEl.querySelectorAll(".cc-clickable").forEach((li) =>
        li.addEventListener("click", () => window.showWorkspace?.("vulns"))
      );
    }
    const meta = document.getElementById("ccMeta");
    if (meta) {
      meta.textContent = `${data.playbooks_total || 0} playbooks · ${data.campaigns_active || 0} campaigns · ${
        data.assessment_count || 0
      } assessments · Mission Control`;
    }
    await renderRiskHeatMap();
  } catch (err) {
    if (scoreEl) scoreEl.textContent = "--";
    if (fwEl) fwEl.innerHTML = `<li class="hint">Dashboard unavailable: ${escapeHtml(err.message)}</li>`;
  } finally {
    clearTimeout(window.__securaiqCcLockTimer);
    window.__securaiqCcLoading = false;
    if (window.__securaiqCcReloadQueued) {
      window.__securaiqCcReloadQueued = false;
      setTimeout(() => loadCommandCenter(), 50);
    }
  }
}

function syncChecklistProgress(data) {
  const mc = data.mission_control || {};
  const today = mc.today || {};
  let integVisited = false;
  try {
    integVisited = localStorage.getItem("securaiq.checklist.integrations") === "1";
  } catch {
    /* ignore */
  }
  const marks = {
    org: (mc.organization || "") !== "Local workspace" && (mc.organization || "") !== "—",
    assets: Number(data.assets_total || 0) > 0,
    scan: Number(today.critical_findings || 0) + Number(data.vulnerabilities_open || 0) > 0,
    hardening: Boolean((data.hardening || {}).audit_done),
    gap: Number(data.assessment_count || 0) > 0,
    report: Number(data.assessment_count || 0) > 0 || Number(data.assets_total || 0) > 0,
    integrations: integVisited,
  };
  document.querySelectorAll("#mcChecklist li[data-step]").forEach((li) => {
    const step = li.getAttribute("data-step");
    if (marks[step]) li.classList.add("done");
    else li.classList.remove("done");
  });
}

function wireLiveScanActions(root) {
  (root || document).querySelectorAll("[data-action='live-scan'], [data-action='new-scan']").forEach((btn) => {
    if (btn.dataset.liveScanWired) return;
    btn.dataset.liveScanWired = "1";
    btn.addEventListener("click", async (e) => {
      e.preventDefault();
      const action = btn.getAttribute("data-action");
      if (action === "new-scan" && typeof window.openNewScanModal === "function") {
        window.openNewScanModal();
      }
      if (action === "combo-assess") {
        if (typeof window.openNewScanModal === "function") {
          await window.openNewScanModal();
          const sel = document.getElementById("newScanScanner");
          if (sel) sel.value = "combo";
          const hint = document.getElementById("newScanScannerHint");
          if (hint) {
            hint.textContent =
              "Combo runs SecuraIQ (+ Nmap when ready) → evidence → investigation pack → optional auto-triage.";
          }
          const scope = document.getElementById("newScanScope");
          if (scope && !scope.value.trim()) scope.value = "127.0.0.1\n127.0.0.0/8";
          const target = document.getElementById("newScanTarget");
          if (target && !target.value.trim()) target.value = "127.0.0.1";
          const auth = document.getElementById("newScanAuthorized");
          if (auth) auth.checked = true;
        }
      } else if (typeof window.startLiveScan === "function") {
        window.startLiveScan();
      }
    });
  });
}

function wireMissionFirstRunOnce() {
  if (window.__securaiqFirstRunWired) return;
  window.__securaiqFirstRunWired = true;
  wireLiveScanActions(document);
  document.querySelectorAll("#mcChecklist .mc-check-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.getAttribute("data-action") === "live-scan" || btn.getAttribute("data-action") === "new-scan") return;
      const ws = btn.getAttribute("data-workspace");
      const mod = btn.getAttribute("data-module");
      if (ws && typeof window.showWorkspace === "function") window.showWorkspace(ws);
      else if (mod === "gap") openGap();
    });
  });
  document.querySelectorAll("#mcFirstRun [data-workspace]").forEach((btn) => {
    if (btn.classList.contains("mc-check-btn")) return;
    btn.addEventListener("click", () => {
      const ws = btn.getAttribute("data-workspace");
      if (ws && typeof window.showWorkspace === "function") window.showWorkspace(ws);
    });
  });
}

function renderWorkQueue(items) {
  const el = document.getElementById("ccWorkQueue");
  if (!el) return;
  if (!items.length) {
    el.innerHTML = `<p class="hint">Empty queue — run a New scan on an owned target, or use the quick-start checklist.</p>`;
    return;
  }
  el.innerHTML = `<div class="wq-table-wrap"><table class="wq-table">
    <thead><tr>
      <th>Priority</th><th>Task</th><th>Owner</th><th>Due</th><th>Framework</th><th>Risk</th><th>Status</th><th>AI</th><th></th>
    </tr></thead>
    <tbody>
    ${items
      .map((w) => {
        const pri = (w.priority || "medium").toLowerCase();
        return `<tr class="pri-${escapeHtml(pri)}">
          <td><span class="wq-badge">${escapeHtml(pri)}</span></td>
          <td><strong>${escapeHtml(w.title)}</strong></td>
          <td>${escapeHtml(w.owner || "Unassigned")}</td>
          <td>${escapeHtml(w.due || "—")}</td>
          <td>${escapeHtml(w.framework || "—")}</td>
          <td>${escapeHtml(String(w.risk || "—"))}</td>
          <td>${escapeHtml(w.status || "open")}</td>
          <td class="wq-ai">${escapeHtml(w.ai || "")}</td>
          <td class="wq-actions">
            <button type="button" class="btn-secondary wq-ask" data-mode="${escapeHtml(
              w.mode || "ciso"
            )}" data-prompt="${escapeHtml(w.prompt || w.title)}">Ask AI</button>
            <button type="button" class="btn-primary-cc wq-task" data-title="${escapeHtml(
              w.title
            )}" data-workspace="${escapeHtml(w.workspace || "remediations")}" data-action="${escapeHtml(
          w.action || "open"
        )}" data-entity="${escapeHtml(w.entity_id || "")}">Act</button>
          </td>
        </tr>`;
      })
      .join("")}
    </tbody></table></div>`;
  el.querySelectorAll(".wq-ask").forEach((btn) => {
    btn.addEventListener("click", () => runNavPrompt(btn.getAttribute("data-mode"), btn.getAttribute("data-prompt")));
  });
  el.querySelectorAll(".wq-task").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const action = btn.getAttribute("data-action") || "open";
      const title = btn.getAttribute("data-title") || "Mission task";
      const ws = btn.getAttribute("data-workspace") || "remediations";
      if (action === "gap") {
        openGap();
        return;
      }
      if (action === "report" || action === "open") {
        window.showWorkspace?.(ws);
        notifyUser(`**Opened ${ws}:** ${title}`);
        return;
      }
      if (action === "task") {
        try {
          const res = await fetch("/api/gap/remediations", {
            method: "POST",
            headers: authHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify({
              control_id: "MC",
              title,
              status: "open",
              owner: "Unassigned",
              recommendation: title,
            }),
          });
          if (res.ok) {
            notifyUser(`**Task created:** ${title}`);
            window.showWorkspace?.("remediations");
          } else if (ws) window.showWorkspace?.(ws);
        } catch {
          if (ws) window.showWorkspace?.(ws);
        }
        return;
      }
      window.showWorkspace?.(ws);
    });
  });
}
window.renderWorkQueue = renderWorkQueue;

function renderMcDecisionPanel(data) {
  const what = document.getElementById("mcDecisionWhat");
  const why = document.getElementById("mcDecisionWhy");
  const next = document.getElementById("mcDecisionNext");
  const actions = document.getElementById("mcDecisionActions");
  if (!what) return;
  const wq = data.work_queue || [];
  const top = wq[0];
  const crit = data.vulnerabilities_critical_high || 0;
  const risks = data.risks_open || 0;
  if (!top && !crit && !risks) {
    what.textContent = "Posture is quiet — keep monitoring and attach evidence for compliance.";
    why.textContent = "No open critical queue items.";
    next.textContent = "Run a gap analysis or import the latest scanner export.";
  } else if (top) {
    what.textContent = top.title;
    why.textContent = top.ai || `Priority ${top.priority} · owner ${top.owner || "Unassigned"}`;
    next.textContent = top.prompt || "Ask AI for remediation steps, then create a tracked task.";
  } else {
    what.textContent = `${crit} critical/high findings · ${risks} open risks`;
    why.textContent = "Unresolved findings increase residual risk and audit exposure.";
    next.textContent = "Triage top vulns, assign owners, and open remediations.";
  }
  if (actions) {
    actions.innerHTML = `
      <button type="button" class="cc-action" data-workspace="vulns">Triage vulns</button>
      <button type="button" class="cc-action" data-module="gap">Gap analysis</button>
      <button type="button" class="cc-action" id="mcCreateTickets">Create remediations</button>
      <button type="button" class="cc-action" data-workspace="reports">Board report</button>`;
    actions.querySelectorAll("[data-workspace]").forEach((b) =>
      b.addEventListener("click", () => window.showWorkspace?.(b.getAttribute("data-workspace")))
    );
    actions.querySelectorAll("[data-module]").forEach((b) =>
      b.addEventListener("click", () => handleModuleAction(b.getAttribute("data-module")))
    );
    actions.querySelector("#mcCreateTickets")?.addEventListener("click", async () => {
      const tops = (data.findings?.top_vulns || []).slice(0, 3);
      if (!tops.length) {
        notifyUser("**No open vulns** — import a real scanner export first.");
        return;
      }
      let n = 0;
      for (const v of tops) {
        const res = await fetch(`/api/vulnerabilities/${v.id}/triage`, {
          method: "POST",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ owner: "SecOps", create_jira: false }),
        });
        if (res.ok) n += 1;
      }
      notifyUser(`**Created ${n} remediation(s)** from top findings.`);
      window.showWorkspace?.("remediations");
      loadCommandCenter();
    });
  }
}

function wireMcAssetNav(root) {
  root?.querySelectorAll("[data-workspace]").forEach((el) =>
    el.addEventListener("click", () => window.showWorkspace?.(el.getAttribute("data-workspace")))
  );
}

function inventoryKindFromAsset(a) {
  const blob = `${a.source || ""} ${a.notes || ""}`.toLowerCase();
  if (a._oa || /openaudit|open.?audit|securaiq_audit/.test(blob)) return "audit";
  return "scan";
}

function mcPortChips(ports) {
  const list = (ports || [])
    .map((p) => String(p == null ? "" : p).trim())
    .filter(Boolean)
    .slice(0, 8);
  if (!list.length) return `<span class="hint">—</span>`;
  return `<span class="port-chips">${list
    .map((p) => `<code class="port-chip">${escapeHtml(p)}</code>`)
    .join("")}</span>`;
}

function renderMcAssetTable(scanRows, auditRows) {
  const tableEl = document.getElementById("mcAssetsTable");
  const panelEl = document.getElementById("mcAssetsPanel");
  if (!tableEl) return;
  const scan = scanRows || [];
  const audit = auditRows || [];
  if (!scan.length && !audit.length) {
    if (panelEl) panelEl.classList.add("is-empty");
    tableEl.innerHTML = `<p class="hint">No live hosts yet — <strong>Refresh LAN</strong> or <strong>Queue engine scan</strong>.</p>`;
    return;
  }
  if (panelEl) panelEl.classList.remove("is-empty");
  const block = (title, list) => {
    const rows = list
      .map((a) => {
        const ip = a.ip || "";
        const scanSt = (a.last_scan_status || "").toLowerCase();
        const chip = scanSt
          ? `<span class="auto-job-status ${
              scanSt === "completed" ? "status-done" : /fail|block/.test(scanSt) ? "status-error" : "status-running"
            }">${escapeHtml(scanSt)}</span>`
          : `<span class="hint">idle</span>`;
        const target = ip || displayAssetLabel(a) || a.name || "";
        const src = /openaudit/i.test(`${a.source || ""} ${a.notes || ""}`) && !a._oa
          ? "Open-AudIT"
          : "securaiq live";
        const extra = [a.os, (a.shares || []).length ? `shares ${(a.shares || []).slice(0, 2).join(", ")}` : ""]
          .filter(Boolean)
          .join(" · ");
        const hostLabel = displayAssetLabel(a);
        return `<tr>
          <td><strong>${escapeHtml(hostLabel || "—")}</strong>${
            extra ? `<div class="hint">${escapeHtml(extra)}</div>` : ""
          }</td>
          <td>${ip ? `<code>${escapeHtml(ip)}</code>` : "—"}</td>
          <td>${categoryChipHtml(a)}</td>
          <td><span class="inventory-source">${escapeHtml(src)}</span></td>
          <td>${mcPortChips(a.open_ports)}</td>
          <td>${chip}</td>
          <td class="ws-actions">
            <button type="button" class="btn-primary-cc mc-scan-asset" data-target="${escapeHtml(target)}">Scan</button>
          </td>
        </tr>`;
      })
      .join("");
    return `<section class="inventory-block">
      <header class="inventory-block-head"><h2>${escapeHtml(title)}</h2><span class="hint">${list.length} live</span></header>
      ${
        rows
          ? `<div class="data-table-wrap mc-assets-wrap"><table class="data-table">
              <thead><tr><th>Host</th><th>IP</th><th>Category</th><th>Source</th><th>Open ports</th><th>Last scan</th><th></th></tr></thead>
              <tbody>${rows}</tbody></table></div>`
          : `<p class="hint">No ${escapeHtml(title)} hosts yet — Refresh LAN.</p>`
      }
    </section>`;
  };
  tableEl.innerHTML = `${block("Open Scan", scan)}${block("Open Audit", audit)}`;
  tableEl.querySelectorAll(".mc-scan-asset").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (typeof window.queueAssetScan === "function") window.queueAssetScan(btn.getAttribute("data-target"));
      else window.showWorkspace?.("assets");
    });
  });
}

function renderMcAssetInventory(assetsTotal, breakdown, recentAssets) {
  const abEl = document.getElementById("ccAssetBreakdown");
  const stripEl = document.getElementById("mcAssetStrip");
  const liveTiles = (assets) => {
    const n = assets.length;
    const withPorts = assets.filter((a) => (a.open_ports || []).length).length;
    return `<div class="asset-breakdown-grid">
      <button type="button" class="ab-tile" data-workspace="assets"><span>Hosts</span><strong>${n}</strong></button>
      <button type="button" class="ab-tile" data-workspace="assets"><span>With ports</span><strong>${withPorts}</strong></button>
    </div>`;
  };

  const paintAssets = (scanRows, auditRows) => {
    const seen = new Set();
    const assets = [];
    for (const a of [...(scanRows || []), ...(auditRows || [])]) {
      const key = a.id || a.ip || a.name;
      if (!key || seen.has(key)) continue;
      seen.add(key);
      assets.push(a);
    }
    renderMcAssetTable(scanRows, auditRows);
    const list = document.getElementById("ccAssetNames");
    if (list) {
      list.innerHTML = assets.length
        ? assets
            .slice(0, 12)
            .map(
              (a) =>
                `<li class="cc-clickable" data-workspace="assets">
                  <strong>${escapeHtml(displayAssetLabel(a))}</strong>
                  <span class="hint">${escapeHtml(a.ip || a.asset_type || "host")}${
                    a.os ? ` · ${escapeHtml(a.os)}` : ""
                  }</span>
                </li>`
            )
            .join("")
        : `<li class="hint">No hosts yet — Refresh LAN.</li>`;
      wireMcAssetNav(list);
    }
    if (stripEl) {
      if (!assets.length) {
        stripEl.classList.add("hidden");
        stripEl.innerHTML = "";
        return;
      }
      stripEl.classList.remove("hidden");
      const chips = assets
        .slice(0, 8)
        .map(
          (a) =>
            `<button type="button" class="mc-asset-chip" data-workspace="assets" title="Open asset inventory">
              <strong>${escapeHtml(displayAssetLabel(a))}</strong>
              <span class="hint">${escapeHtml(a.ip || a.asset_type || "host")}</span>
            </button>`
        )
        .join("");
      stripEl.innerHTML = `<span class="mc-kicker">Live inventory</span>${chips}
        <button type="button" class="btn-secondary" data-workspace="assets">View all (${assets.length})</button>`;
      wireMcAssetNav(stripEl);
    }
  };

  const applyFromAssets = (rawAssets, devices) => {
    const byAsset = {};
    (devices || []).forEach((d) => {
      if (d.asset_id) byAsset[d.asset_id] = d;
    });
    const merged = (rawAssets || []).map((a) => {
      const d = byAsset[a.id] || {};
      const ip = a.ip || d.ip || "";
      const hostname = a.hostname || d.hostname || "";
      const os = a.os || d.os || "";
      return {
        ...a,
        ip,
        hostname,
        os,
        open_ports: (a.open_ports && a.open_ports.length ? a.open_ports : d.open_ports) || [],
        shares: d.shares || a.shares || [],
        display_name:
          a.display_name ||
          displayAssetLabel({ name: a.name, ip, hostname, os, asset_name: a.name }),
        _oa: !!d.asset_id || /openaudit/i.test(a.notes || ""),
      };
    });
    const seen = new Set(merged.filter((a) => a._oa).map((a) => a.id));
    const oaOnly = (devices || [])
      .filter((d) => !d.asset_id || !seen.has(d.asset_id))
      .map((d) => ({
        id: d.asset_id || d.id,
        name: displayAssetLabel({ name: d.name, ip: d.ip, hostname: d.hostname, os: d.os }),
        display_name: displayAssetLabel({ name: d.name, ip: d.ip, hostname: d.hostname, os: d.os }),
        hostname: d.hostname || "",
        ip: d.ip || "",
        asset_type: d.type || "endpoint",
        os: d.os || "",
        source: "openaudit",
        notes: "openaudit",
        _oa: true,
        open_ports: d.open_ports || [],
        shares: d.shares || [],
      }));
    return { scan: merged, audit: [...merged.filter((a) => a._oa), ...oaOnly] };
  };

  fetch("/api/assets", { headers: authHeaders() })
    .then(async (res) => {
      const data = res.ok ? await res.json().catch(() => ({})) : {};
      const invRes = await fetch("/api/openaudit/devices?limit=200", { headers: authHeaders() }).catch(() => null);
      const inv = invRes && invRes.ok ? await invRes.json().catch(() => ({})) : {};
      const lists = applyFromAssets(data.assets || recentAssets || [], inv.devices || []);
      if (abEl) {
        abEl.innerHTML = `${liveTiles([...(lists.scan || []), ...(lists.audit || [])])}<ul id="ccAssetNames" class="cc-list mc-asset-names"></ul>`;
        wireMcAssetNav(abEl);
      }
      paintAssets(lists.scan, lists.audit);
    })
    .catch(() => {
      if (abEl) {
        abEl.innerHTML = `<p class="hint">Inventory unavailable.</p>`;
      }
      renderMcAssetTable([], []);
    });
  if (abEl && !abEl.innerHTML) {
    abEl.innerHTML = `<ul id="ccAssetNames" class="cc-list mc-asset-names"><li class="hint">Loading live inventory…</li></ul>`;
  }
}

function renderMcHardeningPanel(hk) {
  const el = document.getElementById("mcHardeningBody");
  if (!el) return;
  hk = hk || {};
  const installed = Boolean(hk.installed);
  const auditDone = Boolean(hk.audit_done);
  const platformOk = hk.platform_ok !== false;
  let statusChip = `<span class="auto-job-status status-planned">Not installed</span>`;
  let statusText = "HardeningKitty is not configured on this host.";
  if (!platformOk) {
    statusChip = `<span class="auto-job-status status-planned">Windows only</span>`;
    statusText = "HardeningKitty audits run on Windows lab hosts or VMs you own.";
  } else if (auditDone) {
    statusChip = `<span class="auto-job-status status-done">Audit done</span>`;
    statusText = `Last ${escapeHtml(hk.last_mode || "audit")} · score ${hk.last_score != null ? escapeHtml(String(hk.last_score)) : "—"} · failed ${hk.last_failed || 0} · imported ${hk.last_imported || 0}`;
  } else if (installed) {
    statusChip = `<span class="auto-job-status status-running">Ready — not audited</span>`;
    statusText = `${hk.finding_lists || 0} finding lists (${hk.cis_lists || 0} CIS). Run an audit to baseline this host.`;
  }
  const setupCmd = hk.setup_script_download || hk.setup_script || ".\\scripts\\use_hardeningkitty.cmd -Download";
  const when =
    hk.last_run_at != null
      ? new Date(Number(hk.last_run_at) * (Number(hk.last_run_at) < 1e12 ? 1000 : 1)).toLocaleString()
      : "";
  el.innerHTML = `
    <div class="hk-status mc-hk-status">
      ${statusChip}
      <p class="hint">${statusText}${when ? ` · ${escapeHtml(when)}` : ""}</p>
    </div>
    ${
      !installed && platformOk
        ? `<div class="hk-setup-block">
            <p class="hint">Install module (from repo root in PowerShell):</p>
            <code class="hk-setup-code" id="mcHkSetupCmd">${escapeHtml(setupCmd)}</code>
            <div class="cc-action-row">
              <button type="button" class="btn-secondary" id="mcHkCopySetup">Copy script</button>
              <button type="button" class="btn-secondary" data-workspace="integrations">Settings</button>
            </div>
            <p class="hint">Then restart SecuraIQ and run the audit below.</p>
          </div>`
        : ""
    }
    <div class="cc-action-row hk-actions">
      ${
        installed && platformOk
          ? `<button type="button" class="btn-primary-cc" id="mcHkAuditBtn">Run HardeningKitty audit</button>`
          : ""
      }
      <button type="button" class="btn-secondary" data-workspace="frameworks">Open hardening panel</button>
    </div>`;
  wireMcAssetNav(el);
  el.querySelector("#mcHkCopySetup")?.addEventListener("click", async () => {
    const cmd = el.querySelector("#mcHkSetupCmd")?.textContent || setupCmd;
    try {
      await navigator.clipboard.writeText(cmd);
      notifyUser("**Copied** setup command to clipboard.");
    } catch {
      notifyUser(`**Setup command:** \`${cmd}\``);
    }
  });
  el.querySelector("#mcHkAuditBtn")?.addEventListener("click", () => {
    if (typeof window.runHardeningKittyAudit === "function") window.runHardeningKittyAudit();
    else window.showWorkspace?.("frameworks");
  });
}

function softwareStatusChip(it) {
  const st = (it?.status || "unknown").toLowerCase();
  const cls = it?.status_class || (st === "current" || st === "up_to_date" ? "done" : st === "unknown" ? "planned" : "error");
  const label = it?.status_label || st.replace(/_/g, " ");
  return `<span class="sw-status-chip status-${escapeHtml(cls)}">${escapeHtml(label)}</span>`;
}
window.softwareStatusChip = softwareStatusChip;

function setMcSoftwareTab(tab) {
  const t = tab === "tools" ? "tools" : "hosts";
  document.querySelectorAll("#mcSoftwarePanel .sw-tab").forEach((btn) => {
    const on = btn.getAttribute("data-sw-tab") === t;
    btn.classList.toggle("is-active", on);
    btn.setAttribute("aria-selected", on ? "true" : "false");
  });
  document.querySelectorAll("#mcSoftwarePanel .sw-pane").forEach((pane) => {
    pane.classList.toggle("hidden", pane.getAttribute("data-sw-pane") !== t);
  });
  const rebuildBtn = document.getElementById("mcSoftwareRebuild");
  const toolsBtn = document.getElementById("mcToolUpdatesRefresh");
  if (rebuildBtn) rebuildBtn.classList.toggle("hidden", t === "tools");
  if (toolsBtn) toolsBtn.classList.toggle("hidden", t !== "tools");
}

function wireMcSoftwarePanelOnce() {
  if (window.__mcSoftwarePanelWired) return;
  window.__mcSoftwarePanelWired = true;
  document.querySelectorAll("#mcSoftwarePanel .sw-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      setMcSoftwareTab(btn.getAttribute("data-sw-tab"));
      if (btn.getAttribute("data-sw-tab") === "tools") refreshMcToolUpdates(true);
    });
  });
  document.getElementById("mcSoftwareRebuild")?.addEventListener("click", async () => {
    const el = document.getElementById("mcSoftwarePostureBody");
    if (el) el.innerHTML = `<p class="hint">Rebuilding software inventory…</p>`;
    try {
      const res = await fetch("/api/software/rebuild", { method: "POST", headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      renderMcSoftwarePosturePanel(data.posture || {});
      if (typeof notifyUser === "function") notifyUser("**Software inventory refreshed** from scans and XDR.");
      if (typeof window.renderSoftwarePage === "function") window.renderSoftwarePage({ quiet: true });
    } catch (err) {
      if (el) el.innerHTML = `<p class="hint">Rebuild failed: ${escapeHtml(err.message || err)}</p>`;
    }
  });
  document.getElementById("mcToolUpdatesRefresh")?.addEventListener("click", () => refreshMcToolUpdates(true));
  document.getElementById("mcSoftwareSyncAll")?.addEventListener("click", async () => {
    const el = document.getElementById("mcSoftwarePostureBody");
    if (el) el.innerHTML = `<p class="hint">Syncing all sources…</p>`;
    try {
      if (typeof window.syncAllAndRebuildSoftware === "function") {
        await window.syncAllAndRebuildSoftware({ quiet: true });
      }
      if (typeof loadCommandCenter === "function") loadCommandCenter();
    } catch (err) {
      if (el) el.innerHTML = `<p class="hint">Sync failed: ${escapeHtml(err.message || err)}</p>`;
    }
  });
}

function wireMcSoftwarePostureOnce() {
  wireMcSoftwarePanelOnce();
}

async function refreshLocalWindowsHost(force) {
  if (window.__securaiqLocalWinBusy) return;
  const sp = window.__securaiqLastSoftwarePosture || {};
  const win = sp.windows_host || {};
  const cov = sp.coverage || {};
  const plat = String(win.platform || "").toLowerCase();
  const knownApps = Number(win.installed_apps || 0) || Number(cov.control_panel || 0);
  if (!force && plat && plat !== "windows") return;
  if (!force && knownApps > 0 && !win.needs_refresh) return;
  window.__securaiqLocalWinBusy = true;
  if (typeof pulseMcLiveLine === "function") {
    pulseMcLiveLine("Reading Control Panel registry…");
  }
  if (typeof window.setSoftwareSyncLive === "function") {
    window.setSoftwareSyncLive("● Reading Control Panel registry…", true);
  }
  try {
    const res = await fetch("/api/software/local-refresh", { method: "POST", headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    if (data.posture && typeof renderMcSoftwarePosturePanel === "function") {
      window.__securaiqLastSoftwarePosture = data.posture;
      renderMcSoftwarePosturePanel(data.posture);
    }
    const p = data.windows_host || (data.posture || {}).windows_host || {};
    if (typeof pulseSoftwareFromPush === "function") {
      pulseSoftwareFromPush({
        message: `This PC · ${p.installed_apps || 0} Control Panel apps · ${p.pending_updates || 0} update(s) pending`,
        issues: (data.posture || {}).issues,
        health_score: (data.posture || {}).health_score,
        total_products: (data.posture || {}).total_products,
        ts: Date.now() / 1000,
      });
    }
    if (typeof window.refreshSoftwareFromPush === "function") {
      window.refreshSoftwareFromPush({}, { partial: true, skipPulse: true });
    } else if (typeof window.renderSoftwarePage === "function") {
      window.renderSoftwarePage({ quiet: true });
    }
  } catch (err) {
    if (typeof pulseMcLiveLine === "function") {
      pulseMcLiveLine(`Local inventory failed: ${err.message || err}`);
    }
    if (typeof window.setSoftwareSyncLive === "function") {
      window.setSoftwareSyncLive(`Local inventory failed: ${err.message || err}`, true);
    }
  } finally {
    window.__securaiqLocalWinBusy = false;
  }
}
window.refreshLocalWindowsHost = refreshLocalWindowsHost;

function wireMcToolUpdatesOnce() {
  wireMcSoftwarePanelOnce();
}

function renderMcSoftwarePosturePanel(sp) {
  const el = document.getElementById("mcSoftwarePostureBody");
  if (!el) return;
  sp = sp || {};
  const counts = sp.counts || {};
  const patch = sp.patch_compliance || {};
  const total = Number(sp.total_products || 0);
  const issues = Number(sp.issues || 0);
  const hosts = Number(sp.hosts_with_issues || 0);
  const missingXdr = Number(patch.total_missing_patches || 0);
  const health = Number(sp.health_score ?? (total ? Math.round(((sp.healthy || 0) / total) * 100) : 100));
  const win = sp.windows_host || {};
  const cov = sp.coverage || {};
  const installedApps = Math.max(Number(win.installed_apps || 0), Number(cov.control_panel || 0));
  const pendingUpd = Number(win.pending_updates || 0);

  const top = (sp.top_issues || [])
    .map(
      (it) =>
        `<li class="sw-issue-row">${softwareStatusChip(it)}
          <div class="sw-issue-main">
            <strong>${escapeHtml(it.product || "?")}</strong>
            <span class="hint">${escapeHtml(it.version || "—")} · ${escapeHtml(it.asset_name || "—")}${
              it.cve ? ` · ${escapeHtml(it.cve)}` : ""
            }${it.port ? ` · :${it.port}` : ""}</span>
          </div></li>`
    )
    .join("");

  const pendingList = (win.pending_preview || [])
    .map(
      (p) =>
        `<li class="sw-issue-row"><span class="sw-status-chip status-error">Update</span>
          <div class="sw-issue-main"><strong>${escapeHtml(p.title || "Windows Update")}</strong>
          <span class="hint">${escapeHtml(p.kb || "pending")}${p.severity ? ` · ${escapeHtml(p.severity)}` : ""}</span></div></li>`
    )
    .join("");
  const programList = (win.programs_preview || [])
    .slice(0, 6)
    .map(
      (p) =>
        `<li class="sw-issue-row"><span class="sw-status-chip status-done">Installed</span>
          <div class="sw-issue-main"><strong>${escapeHtml(p.name || "?")}</strong>
          <span class="hint">${escapeHtml(p.version || "—")}${p.publisher ? ` · ${escapeHtml(p.publisher)}` : ""}</span></div></li>`
    )
    .join("");

  const sources = Object.entries(sp.by_source_label || sp.by_source || {})
    .map(([k, v]) => `${escapeHtml(k)} ${v}`)
    .join(" · ");
  const covLine = [
    ["scan", cov.scans],
    ["xdr", cov.xdr],
    ["siem", cov.siem],
    ["inv", cov.inventory],
    ["code", cov.code],
    ["tools", cov.local_tools],
    ["control panel", cov.control_panel],
    ["os", cov.os_patches],
  ]
    .filter(([, n]) => Number(n) > 0)
    .map(([k, n]) => `${k} ${n}`)
    .join(" · ");

  const winLine =
    win.platform === "windows" || installedApps || pendingUpd
      ? `<p class="hint sw-server-line"><strong>${installedApps}</strong> Control Panel apps · <strong>${pendingUpd}</strong> Windows Update(s) pending${
          win.last_patch ? ` · last hotfix ${escapeHtml(win.last_patch)}` : ""
        }${win.host ? ` · ${escapeHtml(win.host)}` : ""}</p>`
      : "";

  el.innerHTML = `
    <div class="sw-health-row">
      <div class="sw-health-gauge" style="--p:${health}"><span>${health}%</span></div>
      <div class="sw-health-copy">
            <strong>${issues ? `${issues} issue(s) on ${hosts} host(s)` : "No patch or EOL gaps detected"}</strong>
            <p class="hint">${total ? `${total} products from registry, scans, and connected sources` : "Sync this PC to load Control Panel software and Windows Updates."}${
          covLine ? ` · ${escapeHtml(covLine)}` : sources ? ` · ${sources}` : ""
        }</p>
            ${winLine}
            ${
              (sp.server_summary || {}).total
                ? `<p class="hint sw-server-line"><strong>${Number(sp.server_summary.up_to_date || 0)}</strong> systems up to date · <strong>${Number(sp.server_summary.needs_update || 0)}</strong> need update · <strong>${Number(sp.server_summary.unknown || 0)}</strong> unknown</p>`
                : ""
            }
      </div>
    </div>
    <div class="vuln-summary-metrics mc-sw-metrics">
      <article class="cc-kpi"><span>Products</span><strong>${total}</strong></article>
      <article class="cc-kpi"><span>Control Panel</span><strong>${installedApps}</strong></article>
      <article class="cc-kpi"><span>Pending updates</span><strong>${pendingUpd}</strong></article>
      <article class="cc-kpi"><span>Outdated / patch</span><strong>${issues}</strong></article>
    </div>
    ${
      total
        ? `<p class="hint sw-counts-line">${counts.current || 0} current · ${counts.installed || 0} installed · ${counts.outdated || 0} outdated · ${counts.eol || 0} EOL · ${counts.missing_patch || 0} missing patch · ${counts.unknown || 0} unknown</p>`
        : ""
    }
    ${pendingList ? `<p class="hint"><strong>Pending Windows Updates</strong></p><ul class="cc-list mc-sw-list">${pendingList}</ul>` : ""}
    ${programList ? `<p class="hint"><strong>Installed from Control Panel</strong></p><ul class="cc-list mc-sw-list">${programList}</ul>` : ""}
    <ul class="cc-list mc-sw-list">${top || `<li class="hint">No outdated software detected yet.</li>`}</ul>
    <div class="cc-action-row">
      <button type="button" class="btn-secondary" id="mcSoftwareLocalRefresh">Refresh this PC</button>
      <button type="button" class="btn-secondary" data-workspace="software">Open full inventory</button>
      <button type="button" class="btn-secondary" data-workspace="vulns">Vulnerabilities</button>
    </div>`;
  wireMcAssetNav(el);
  el.querySelector("#mcSoftwareLocalRefresh")?.addEventListener("click", () => refreshLocalWindowsHost(true));
}

let __mcToolUpdatesLoading = false;

async function refreshMcToolUpdates(force) {
  const el = document.getElementById("mcToolUpdatesBody");
  if (!el || __mcToolUpdatesLoading) return;
  __mcToolUpdatesLoading = true;
  try {
    const res = await fetch(`/api/tools/versions${force ? "?refresh=true" : ""}`, { headers: authHeaders() });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderMcToolUpdatesPanel(data);
  } catch {
    el.innerHTML = `<p class="hint">Couldn't check tool versions right now.</p>`;
  } finally {
    __mcToolUpdatesLoading = false;
  }
}

function renderMcToolUpdatesPanel(data) {
  const el = document.getElementById("mcToolUpdatesBody");
  if (!el) return;
  data = data || {};
  const product = data.product || {};
  const tools = data.tools || [];
  const counts = data.counts || {};
  const outdated = tools.filter((t) => t.status === "outdated");

  const chipFor = (status) => {
    if (status === "outdated") return `<span class="auto-job-status status-error">Outdated</span>`;
    if (status === "up_to_date") return `<span class="auto-job-status status-done">Up to date</span>`;
    if (status === "installed") return `<span class="auto-job-status status-running">Installed</span>`;
    if (status === "not_installed") return `<span class="auto-job-status status-planned">Not installed</span>`;
    return `<span class="auto-job-status status-planned">Unknown</span>`;
  };

  const productWhen = product.commit_date ? new Date(product.commit_date).toLocaleString() : "";
  const rows = tools
    .filter((t) => t.status !== "not_installed")
    .map(
      (t) => `
      <li data-tool-id="${escapeHtml(t.id || t.name || "")}" class="mc-tool-row">
        ${chipFor(t.status)}
        <strong>${escapeHtml(t.name || t.id)}</strong>
        <span class="hint">${escapeHtml(t.installed_version || "?")}${
          t.latest_version ? ` &rarr; latest ${escapeHtml(t.latest_version)}` : ""
        }</span>
      </li>`
    )
    .join("");
  const notInstalledCount = counts.not_installed || 0;

  el.innerHTML = `
    <div class="sw-tools-note">
      <span class="sw-status-chip status-done">Local tools</span>
      <p class="hint">Versions of nmap, nuclei, and other scanners on <em>this</em> SecuraIQ machine — not remote host inventory.</p>
    </div>
    <div class="hk-status mc-hk-status">
      <span class="auto-job-status status-done">SecuraIQ v${escapeHtml(product.version || "?")}</span>
      <p class="hint">${
        product.commit ? `build ${escapeHtml(product.commit)}` : ""
      }${
        productWhen ? ` · updated ${escapeHtml(productWhen)}` : ""
      }${product.uncommitted_changes ? " · local changes not committed" : ""}</p>
    </div>
    ${
      outdated.length
        ? `<p class="hint"><strong>${outdated.length}</strong> tool(s) have a newer version available.</p>`
        : `<p class="hint">No installed tool is known to be outdated.</p>`
    }
    <ul class="cc-list mc-tool-updates">
      ${rows || `<li class="hint">No third-party tools detected on PATH yet — SecuraIQ's builtins need no install.</li>`}
    </ul>
    <p class="hint">${notInstalledCount} third-party tool(s) not installed — SecuraIQ's builtin scanners cover the same ground with zero install.</p>
    <div class="cc-action-row">
      <button type="button" class="btn-secondary" data-workspace="integrations">Manage tools</button>
    </div>`;
  wireMcAssetNav(el);
}

function renderSqPostureBars(data, index, compliance) {
  const assets = Number(data.assets_total || 0);
  const vulnOpen = Number(data.vulnerabilities_open || 0);
  const vulnScore = Math.max(0, 100 - Math.min(100, vulnOpen * 3));
  const expScore = Math.max(0, 100 - Number(data.vulnerabilities_critical_high || 0) * 8);
  const setBar = (barId, valId, pct, label) => {
    const bar = document.getElementById(barId);
    const val = document.getElementById(valId);
    if (bar) bar.style.width = `${Math.min(100, Math.max(0, pct))}%`;
    if (val) val.textContent = String(label ?? Math.round(pct));
  };
  setBar("sqBarAssets", "sqBarAssetsVal", Math.min(100, assets * 2), assets);
  setBar("sqBarVulns", "sqBarVulnsVal", vulnScore, vulnScore);
  setBar("sqBarExposure", "sqBarExposureVal", expScore, expScore);
  setBar("sqBarCompliance", "sqBarComplianceVal", compliance, `${compliance}%`);
}

function vulnRiskScore(v) {
  const s = (v.severity || "medium").toLowerCase();
  if (s === "critical") return 94;
  if (s === "high") return 84;
  if (s === "medium") return 61;
  if (s === "low") return 40;
  return 50;
}

function renderSqTopRisksTable(data) {
  const el = document.getElementById("sqTopRisksTable");
  if (!el) return;
  const risks = (data.findings?.top_risks || []).map((r) => ({
    sev: Number(r.risk_score || 0) >= 20 ? "critical" : Number(r.risk_score || 0) >= 15 ? "high" : "medium",
    title: r.threat || r.vulnerability || "Risk",
    asset: r.asset_name || r.asset_id || "—",
    score: Math.min(99, Math.round(Number(r.risk_score || 0) * 4)),
    action: "Investigate",
    ws: "risks",
  }));
  const vulns = (data.findings?.top_vulns || []).map((v) => ({
    sev: (v.severity || "medium").toLowerCase(),
    title: v.title || v.cve || "Finding",
    asset: v.asset_name || "—",
    score: vulnRiskScore(v),
    action: /critical|high/i.test(v.severity || "") ? "Investigate" : "Remediate",
    ws: "vulns",
  }));
  const rows = [...vulns, ...risks].sort((a, b) => b.score - a.score).slice(0, 8);
  if (!rows.length) {
    el.innerHTML = `<p class="hint">No open risks — run a scan or import findings to populate this table.</p>`;
    return;
  }
  el.innerHTML = `<table class="sq-risks-table"><thead><tr>
    <th>Severity</th><th>Finding</th><th class="sq-hide-sm">Asset</th><th>Risk</th><th>Action</th>
  </tr></thead><tbody>${rows
    .map(
      (r) => `<tr data-workspace="${escapeHtml(r.ws)}">
        <td><span class="sq-sev-pill sq-sev-${escapeHtml(r.sev)}">${escapeHtml(r.sev)}</span></td>
        <td><strong>${escapeHtml(r.title)}</strong></td>
        <td class="hint sq-hide-sm">${escapeHtml(r.asset)}</td>
        <td class="sq-risk-num">${r.score}</td>
        <td><button type="button" class="sq-action" data-workspace="${escapeHtml(r.ws)}">${escapeHtml(r.action)}</button></td>
      </tr>`
    )
    .join("")}</tbody></table>`;
  el.querySelectorAll("[data-workspace]").forEach((node) => {
    node.addEventListener("click", (ev) => {
      if (ev.target.closest(".sq-action")) ev.stopPropagation();
      window.showWorkspace?.(node.getAttribute("data-workspace"));
    });
  });
}

function scanProgressPct(scan) {
  const steps = scan.progress || [];
  if (!steps.length) {
    const st = (scan.status || "").toLowerCase();
    if (st === "completed") return 100;
    if (st === "running" || st === "queued") return 35;
    return 0;
  }
  const done = steps.filter((s) => s.status === "done").length;
  const active = steps.some((s) => s.status === "running" || s.status === "active");
  return Math.round(((done + (active ? 0.5 : 0)) / steps.length) * 100);
}

function renderSqRecentScans(scans) {
  const el = document.getElementById("sqScansBody");
  if (!el) return;
  const list = (scans || []).slice(0, 4);
  if (!list.length) {
    el.innerHTML = `<p class="hint">No scans yet — use <strong>+ New Scan</strong> on authorized targets.</p>`;
    return;
  }
  el.innerHTML = list
    .map((s) => {
      const pct = scanProgressPct(s);
      const running = /running|queued|active/i.test(s.status || "");
      const steps = (s.progress || [])
        .slice(0, 6)
        .map((st) => {
          const status = st.status || "pending";
          const cls =
            status === "done" ? "sq-scan-step-done" : status === "running" || status === "active" ? "sq-scan-step-active" : "";
          const mark = status === "done" ? "✓" : status === "running" || status === "active" ? "●" : "○";
          return `<li class="${cls}">${mark} ${escapeHtml(st.label || st.id || "")}</li>`;
        })
        .join("");
      const summary = s.summary || {};
      const findings = summary.findings_count ?? summary.findings ?? "—";
      const assets = summary.assets_count ?? summary.assets ?? "—";
      const scanner = (s.scanner || "scan").toUpperCase();
      const label = s.target || s.id || "Scan";
      return `<article class="sq-scan-card${running ? " is-running" : ""}" data-scan-id="${escapeHtml(s.id || "")}">
        <div class="sq-scan-head"><div><strong>${escapeHtml(label)}</strong>
        <div class="sq-scan-meta">${escapeHtml(scanner)} · ${escapeHtml(s.profile || "discovery")}</div></div>
        <span class="hint">${running ? "Running" : escapeHtml(s.status || "done")}</span></div>
        <div class="sq-scan-bar"><i style="width:${pct}%"></i></div>
        ${running && steps ? `<ul class="sq-scan-steps">${steps}</ul>` : `<p class="hint sq-scan-meta">${pct}% · ${assets} assets · ${findings} findings</p>`}
        <button type="button" class="sq-action" data-scan-view="${escapeHtml(s.id || "")}">${running ? "View scan" : "View results"}</button>
      </article>`;
    })
    .join("");
  el.querySelectorAll("[data-scan-view]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-scan-view");
      if (id && typeof watchScanRealtime === "function") watchScanRealtime(id);
      window.showWorkspace?.("vulns");
    });
  });
}

function renderSqAiAnalyst(data, brief) {
  const el = document.getElementById("sqAiAnalystBody");
  if (!el) return;
  const vulns = (data.findings?.top_vulns || []).slice(0, 3);
  const wq = (data.work_queue || []).slice(0, 2);
  const items = [
    ...vulns.map((v) => ({
      dot: /critical/i.test(v.severity || "") ? "🔴" : "🟠",
      title: v.asset_name || v.title || "Finding",
      sub: v.title || v.cve || v.severity || "",
      ws: "vulns",
    })),
    ...wq.map((w) => ({
      dot: /critical|high/i.test(w.priority || "") ? "🟠" : "🟡",
      title: w.title || "Work item",
      sub: w.owner || w.kind || "",
      ws: w.kind === "incident" ? "soc" : "remediations",
    })),
  ].slice(0, 4);
  const n = items.length || Number(data.vulnerabilities_critical_high || 0);
  const lead =
    brief?.attention ||
    (n
      ? `I found ${n} thing${n === 1 ? "" : "s"} that need attention today.`
      : "Posture is quiet — run a scan to discover new risks.");
  el.innerHTML = `<p class="sq-ai-lead">${escapeHtml(lead)}</p>${
    items.length
      ? items
          .map(
            (it) => `<div class="sq-ai-item" data-workspace="${escapeHtml(it.ws)}">
              <span class="sq-ai-dot">${it.dot}</span>
              <div><strong>${escapeHtml(it.title)}</strong><span>${escapeHtml(it.sub)}</span></div>
            </div>`
          )
          .join("")
      : `<p class="hint">Run <strong>+ New Scan</strong> on authorized targets to populate analyst insights.</p>`
  }`;
  el.querySelectorAll("[data-workspace]").forEach((node) => {
    node.addEventListener("click", () => window.showWorkspace?.(node.getAttribute("data-workspace")));
  });
}

function renderSqExposureMap(data) {
  const el = document.getElementById("sqExposureMap");
  if (!el) return;
  const vulns = (data.findings?.top_vulns || []).slice(0, 4);
  const assets = (data.recent_assets || []).slice(0, 4);
  const nodes = vulns.length
    ? vulns.map((v) => ({
        name: v.asset_name || (v.title || "").slice(0, 20) || "asset",
        score: vulnRiskScore(v),
      }))
    : assets.map((a) => ({ name: a.name || "host", score: 55 }));
  if (!nodes.length) {
    el.innerHTML = `<p class="hint">Run a scan to map internet-facing assets.</p>`;
    return;
  }
  el.innerHTML = `<div class="sq-exposure-hub">Internet</div>
    <div class="sq-exposure-row">${nodes
      .map(
        (n) => `<div class="sq-exposure-node" data-workspace="assets">
          <strong>${escapeHtml(n.name)}</strong>
          <span class="sq-exposure-score" style="color:${n.score >= 90 ? "var(--sq-crit)" : n.score >= 75 ? "var(--sq-high)" : "var(--sq-med)"}">${n.score}</span>
        </div>`
      )
      .join("")}</div>`;
  el.querySelectorAll("[data-workspace]").forEach((node) => {
    node.addEventListener("click", () => window.showWorkspace?.(node.getAttribute("data-workspace")));
  });
}

function renderSqNeedsAttention(data) {
  const list = document.getElementById("ccApprovals");
  if (!list) return;
  const crit = Number(data.vulnerabilities_critical_high || 0);
  const sev = data.severity_counts || {};
  const inc = Number(data.incidents_open || 0);
  const rems = Number(data.remediations_open || 0);
  const stats = data.framework_control_stats || [];
  const missingEvidence = stats.reduce((n, f) => n + Number(f.counts?.missing || 0), 0);
  const items = [];
  if (crit) items.push({ dot: "🔴", text: `${crit} critical vulnerabilities`, ws: "vulns" });
  if (Number(sev.high || 0)) items.push({ dot: "🟠", text: `${sev.high} high-severity findings`, ws: "vulns" });
  if (inc) items.push({ dot: "🟠", text: `${inc} open incidents`, ws: "soc" });
  if (rems) items.push({ dot: "🟠", text: `${rems} open remediation actions`, ws: "remediations" });
  if (missingEvidence) items.push({ dot: "🟡", text: `${missingEvidence} controls missing evidence`, ws: "evidence" });
  (data.pending_approvals || []).slice(0, 3).forEach((a) => {
    items.push({ dot: "🟡", text: a.title || a.kind || "Approval needed", ws: "remediations" });
  });
  list.innerHTML = items.length
    ? items
        .map(
          (it) => `<li class="cc-clickable" data-workspace="${escapeHtml(it.ws)}">${it.dot} ${escapeHtml(it.text)}</li>`
        )
        .join("")
    : `<li class="hint">Nothing flagged — posture looks clear.</li>`;
  list.querySelectorAll("[data-workspace]").forEach((li) =>
    li.addEventListener("click", () => window.showWorkspace?.(li.getAttribute("data-workspace")))
  );
  const evEl = document.getElementById("sqComplianceEvidence");
  if (evEl) {
    evEl.textContent = missingEvidence
      ? `${missingEvidence} control${missingEvidence === 1 ? "" : "s"} need evidence`
      : "Evidence collection on track";
  }
}

function renderSqRiskTrend(data, index) {
  const el = document.getElementById("sqRiskTrendChart");
  if (!el) return;
  const trends = data.kpi_trends || {};
  let history = [];
  try {
    history = JSON.parse(localStorage.getItem("securaiq.risk.history") || "[]");
  } catch {
    history = [];
  }
  history.push({ ts: Date.now(), score: index });
  if (history.length > 14) history = history.slice(-14);
  try {
    localStorage.setItem("securaiq.risk.history", JSON.stringify(history));
  } catch {
    /* ignore */
  }
  const scores = history.map((h) => h.score);
  const max = Math.max(100, ...scores, 1);
  const min = Math.min(...scores, 0);
  const range = Math.max(1, max - min);
  el.innerHTML = scores
    .map((s) => {
      const h = Math.round(((s - min) / range) * 100);
      return `<div class="sq-trend-bar" style="height:${Math.max(8, h)}%" title="Score ${s}"></div>`;
    })
    .join("");
  if (trends.has_baseline && trends.security_index_delta) {
    const d = Number(trends.security_index_delta);
    const note = document.createElement("p");
    note.className = "hint";
    note.style.marginTop = "0.35rem";
    note.textContent =
      d > 0 ? `▲ ${d} points from baseline` : d < 0 ? `▼ ${Math.abs(d)} points from baseline` : "Stable vs baseline";
    el.appendChild(note);
  }
}

function renderAttentionDashboard(data, scans) {
  const brief = data.morning_brief || {};
  renderSqTopRisksTable(data);
  renderSqRecentScans(scans || []);
  renderSqAiAnalyst(data, brief);
  renderSqExposureMap(data);
  renderSqNeedsAttention(data);
  const index = Number(data.security_index != null ? data.security_index : data.mission_control?.security_score) || 0;
  renderSqRiskTrend(data, index);
  const total = Number(data.assets_total || 0);
  const lu = document.getElementById("wzLastUpdate");
  if (lu) lu.textContent = `Updated ${new Date().toLocaleTimeString()} · ${total} asset(s) · live SSE`;
  document.getElementById("viewCommand")?.classList.remove("wz-dashboard");
  document.getElementById("viewCommand")?.classList.add("sq-dashboard");
}
window.renderAttentionDashboard = renderAttentionDashboard;

function renderWazuhDashboard(data, scans) {
  renderAttentionDashboard(data, scans || window.__securaiqRecentScans || []);
}
window.renderWazuhDashboard = renderWazuhDashboard;

function renderMcCharts(data) {
  const sev = document.getElementById("ccSevBars");
  if (sev) {
    const counts = data.severity_counts || {};
    const buckets = {
      critical: Number(counts.critical || 0),
      high: Number(counts.high || 0),
      medium: Number(counts.medium || 0),
      low: Number(counts.low || 0),
    };
    if (!(buckets.critical + buckets.high + buckets.medium + buckets.low)) {
      (data.findings?.top_vulns || []).forEach((v) => {
        const s = (v.severity || "medium").toLowerCase();
        if (buckets[s] != null) buckets[s] += 1;
      });
    }
    const max = Math.max(1, ...Object.values(buckets));
    sev.innerHTML = Object.entries(buckets)
      .map(
        ([k, v]) =>
          `<div class="sev-row"><span>${k}</span><i style="width:${Math.round((v / max) * 100)}%"></i><em>${v}</em></div>`
      )
      .join("");
  }
  const assetChart = document.getElementById("ccAssetChart");
  const ab = data.asset_breakdown || {};
  if (assetChart) {
    const entries = Object.entries(ab).filter(([, v]) => Number(v) > 0);
    if (!entries.length) {
      assetChart.innerHTML = `<p class="hint">No live hosts yet — Refresh LAN or Queue engine scan.</p>`;
    } else {
      assetChart.innerHTML = entries
        .map(
          ([k, v]) =>
            `<button type="button" class="ab-tile category-tile" data-workspace="assets" data-category="${escapeHtml(
              k
            )}"><span>${escapeHtml(ASSET_CATEGORY_LABELS[k] || k)}</span><strong>${v}</strong></button>`
        )
        .join("");
      assetChart.querySelectorAll("[data-workspace]").forEach((b) =>
        b.addEventListener("click", () => {
          const cat = b.getAttribute("data-category");
          if (cat) window.__inventoryCategoryFilter = cat;
          window.showWorkspace?.("assets");
        })
      );
    }
  }
}

async function refreshMcIntegrations() {
  const list = document.getElementById("ccIntegStatus");
  const sync = document.getElementById("ccIntegSync");
  if (!list) return;
  try {
    const rt = window.__securaiqRealtime || {};
    const settled = await Promise.allSettled([
      fetch("/api/settings", { headers: authHeaders() }),
      fetch("/api/tools", { headers: authHeaders() }),
      fetch("/api/webhooks", { headers: authHeaders() }),
      fetch("/api/siem/status", { headers: authHeaders() }),
      fetch("/api/thehive/status", { headers: authHeaders() }),
      fetch("/api/cloud/status", { headers: authHeaders() }),
    ]);
    const jsonOf = async (i) => {
      const r = settled[i].status === "fulfilled" ? settled[i].value : null;
      return r && r.ok ? r.json().catch(() => ({})) : {};
    };
    const settings = await jsonOf(0);
    const tools = await jsonOf(1);
    const hooks = await jsonOf(2);
    const wz = await jsonOf(3);
    const th = await jsonOf(4);
    const cloud = await jsonOf(5);
    const hkLive = rt.hardeningkitty || {};
    const invLive = rt.inventory || {};
    const rows = [
      ["Local tools", (tools.available_count || 0) > 0],
      ["Jira", Boolean(settings.jira_base_url && settings.jira_api_token_set)],
      [
        "Inventory",
        true,
      ],
      [
        "HardeningKitty",
        Boolean(hkLive.installed || settings.hardeningkitty_module_path),
      ],
      ["SecuraIQ SIEM", Boolean(wz.configured)],
      ["TheHive", Boolean(th.configured)],
      ["Cloud posture", (cloud.configured_count || 0) > 0],
      ["Webhooks", (hooks.webhooks || []).length > 0],
      ["Web search", settings.web_search_enabled !== false],
      ["AI backend", Boolean(settings.model_backend)],
    ];
    list.innerHTML = rows
      .slice(0, 6)
      .map(
        ([name, ok]) =>
          `<li><span class="sq-integ-dot${ok ? "" : " off"}"></span><span>${escapeHtml(name)}</span></li>`
      )
      .join("");
    if (sync) {
      const healthy = rows.filter((r) => r[1]).length;
      const needs = rows.length - healthy;
      sync.textContent = `${healthy} healthy${needs ? ` · ${needs} need attention` : ""}`;
    }
  } catch {
    list.innerHTML = `<li class="hint">Status unavailable</li>`;
  }
}

async function renderRiskHeatMap() {
  const el = document.getElementById("ccRiskHeat");
  if (!el) return;
  try {
    const res = await fetch("/api/risks", { headers: authHeaders() });
    const data = await res.json();
    const risks = (data.risks || []).filter((r) => (r.status || "") !== "mitigated" && (r.status || "") !== "closed");
    const grid = Array.from({ length: 5 }, () => Array(5).fill(0));
    const cells = Array.from({ length: 5 }, () => Array.from({ length: 5 }, () => []));
    risks.forEach((r) => {
      const i = Math.min(5, Math.max(1, Number(r.impact) || 1)) - 1;
      const l = Math.min(5, Math.max(1, Number(r.likelihood) || 1)) - 1;
      // matrix: rows = impact high→low (4→0), cols = likelihood 1→5
      const row = 4 - i;
      grid[row][l] += 1;
      cells[row][l].push(r);
    });
    const head = `<div class="risk-heat-corner"></div>${[1, 2, 3, 4, 5]
      .map((n) => `<div class="risk-heat-label">L${n}</div>`)
      .join("")}`;
    const rows = grid
      .map((row, ri) => {
        const impact = 5 - ri;
        const cellsHtml = row
          .map((count, ci) => {
            const score = impact * (ci + 1);
            const band = score >= 15 ? "crit" : score >= 10 ? "high" : score >= 6 ? "med" : "low";
            const titles = (cells[ri][ci] || []).map((r) => r.threat).slice(0, 3).join("; ");
            return `<button type="button" class="risk-heat-cell band-${band}" data-impact="${impact}" data-likelihood="${
              ci + 1
            }" title="${count ? escapeHtml(titles) : "Empty"}">${count || ""}</button>`;
          })
          .join("");
        return `<div class="risk-heat-label">I${impact}</div>${cellsHtml}`;
      })
      .join("");
    if (!risks.length) {
      el.innerHTML = `<p class="hint">No open risks yet — add risks to populate the impact × likelihood matrix.</p>
        <button type="button" class="cc-action" id="ccRiskHeatOpen">Open risk register</button>`;
      el.querySelector("#ccRiskHeatOpen")?.addEventListener("click", () => window.showWorkspace?.("risks"));
      return;
    }
    el.innerHTML = `${head}${rows}`;
    el.querySelectorAll(".risk-heat-cell").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (typeof window.showWorkspace === "function") window.showWorkspace("risks");
      });
    });
  } catch {
    el.innerHTML = `<p class="hint">Risk matrix unavailable</p>`;
  }
}

function runNavPrompt(mode, prompt, opts = {}) {
  const stayOnPage =
    opts.stay === true ||
    (opts.stay !== false &&
      composerWrapEl?.classList.contains("is-floating") &&
      currentView !== "chat");
  if (stayOnPage) {
    openAiAssistant();
    if (mode && modeEl) {
      modeEl.value = mode;
      modeEl.dispatchEvent(new Event("change"));
    }
    if (prompt && inputEl) {
      inputEl.value = prompt;
      resizeInput();
      inputEl.focus();
    }
    syncAiAssistThread();
    if (opts.autoSend !== false && prompt && typeof sendMessage === "function") {
      setTimeout(() => sendMessage(), 80);
    }
    return;
  }
  showView("chat");
  if (mode && modeEl) {
    modeEl.value = mode;
    modeEl.dispatchEvent(new Event("change"));
  }
  if (prompt && inputEl) {
    inputEl.value = prompt;
    resizeInput();
    inputEl.focus();
  }
  if (opts.autoSend !== false && prompt && typeof sendMessage === "function") {
    setTimeout(() => sendMessage(), 80);
  }
}
window.runNavPrompt = runNavPrompt;

function openAiAssistant() {
  if (!composerWrapEl) return;
  if (currentView === "chat") {
    inputEl?.focus();
    return;
  }
  composerWrapEl.classList.add("is-floating", "is-open");
  document.getElementById("aiFab")?.classList.add("hidden");
  document.getElementById("aiFab")?.setAttribute("aria-expanded", "true");
  const ctx = document.getElementById("aiAssistContext");
  if (ctx) {
    const labels = {
      command: "Mission Control",
      page: "Module context",
      chat: "AI Workspace",
    };
    ctx.textContent = `${labels[currentView] || "SecuraIQ"} · authorized labs`;
  }
  syncAiAssistThread();
  inputEl?.focus();
}
window.openAiAssistant = openAiAssistant;

function closeAiAssistant() {
  if (!composerWrapEl) return;
  composerWrapEl.classList.remove("is-open");
  if (composerWrapEl.classList.contains("is-floating") && currentView !== "chat") {
    document.getElementById("aiFab")?.classList.remove("hidden");
    document.getElementById("aiFab")?.setAttribute("aria-expanded", "false");
  }
}
window.closeAiAssistant = closeAiAssistant;

function syncAiAssistThread() {
  const thread = document.getElementById("aiAssistThread");
  if (!thread || !chatEl) return;
  const msgs = [...chatEl.querySelectorAll(".message")].slice(-6);
  if (!msgs.length) {
    thread.classList.add("hidden");
    thread.innerHTML = "";
    return;
  }
  thread.classList.remove("hidden");
  thread.innerHTML = msgs
    .map((m) => {
      const role = m.classList.contains("user") ? "You" : "SecuraIQ";
      const bubble = m.querySelector(".bubble");
      const text = (bubble?.innerText || bubble?.textContent || "").trim().slice(0, 480);
      return `<div class="ai-assist-msg ${m.classList.contains("user") ? "is-user" : "is-ai"}"><span>${role}</span><p>${escapeHtml(
        text
      )}${text.length >= 480 ? "…" : ""}</p></div>`;
    })
    .join("");
  thread.scrollTop = thread.scrollHeight;
}

function wireAiAssistantChrome() {
  if (window.__securaiqAiFabWired) return;
  window.__securaiqAiFabWired = true;
  document.getElementById("aiFab")?.addEventListener("click", () => openAiAssistant());
  document.getElementById("aiAssistClose")?.addEventListener("click", () => closeAiAssistant());
  document.getElementById("aiAssistOpenWorkspace")?.addEventListener("click", () => {
    closeAiAssistant();
    showView("chat");
  });
}
wireAiAssistantChrome();

function handleModuleAction(module) {
  const go = (ws) => {
    if (typeof window.showWorkspace === "function") window.showWorkspace(ws);
  };
  if (module === "gap") {
    go("frameworks");
    openGap();
  } else if (module === "risks") go("risks");
  else if (module === "vulns") go("vulns");
  else if (module === "assets") go("assets");
  else if (module === "rems") go("remediations");
  else if (module === "playbooks") go("playbooks");
  else if (module === "campaigns") go("campaigns");
  else if (module === "dashboard") openDash();
}

function handleGlobalSearch(q) {
  const query = (q || "").trim();
  if (!query) return;
  const searchEl = document.getElementById("globalSearch");
  if (searchEl && window.__securaiqSearchWired) {
    searchEl.value = query;
    searchEl.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    return;
  }
  const lower = query.toLowerCase();
  if (lower.startsWith("cve") || /CVE-\d{4}-\d+/i.test(query)) {
    runNavPrompt("research", `Threat intel brief on ${query}`);
    return;
  }
  if (typeof window.showWorkspace === "function") {
    if (lower.includes("risk")) return window.showWorkspace("risks");
    if (lower.includes("vuln") || lower.includes("scan")) return window.showWorkspace("vulns");
    if (lower.includes("asset")) return window.showWorkspace("assets");
    if (lower.includes("gap") || lower.includes("iso") || lower.includes("nist"))
      return window.showWorkspace("frameworks");
    if (lower.includes("playbook") || lower.includes("incident")) return window.showWorkspace("soc");
  }
  runNavPrompt(modeEl?.value || "default", `Find and explain: ${query}`);
}

function syncEmptyState() {
  if (!emptyStateEl) return;
  const hasMessages = !!(chatEl && chatEl.children.length > 0);
  const onChat = currentView === "chat";
  emptyStateEl.classList.toggle("hidden", hasMessages || !onChat);
  document.getElementById("aiTab-chat")?.classList.toggle("is-empty", onChat && !hasMessages);
  document.getElementById("viewChat")?.classList.toggle("is-empty", onChat && !hasMessages);
  if (onChat) {
    document.getElementById("aiAssistThread")?.classList.add("hidden");
  }
}

function appendMessage(role, content, isHtml = false) {
  const div = document.createElement("div");
  div.className = `message ${role}`;

  const avatar = document.createElement("div");
  avatar.className = "avatar";
  avatar.setAttribute("aria-hidden", "true");
  avatar.textContent = role === "user" ? "Y" : "H";

  const bubble = document.createElement("div");
  bubble.className = "bubble";
  if (isHtml) {
    bubble.innerHTML = content;
  } else {
    bubble.textContent = content;
  }

  const label = document.createElement("div");
  label.className = "role";
  label.textContent = role;

  div.append(avatar, label, bubble);
  chatEl.appendChild(div);
  syncEmptyState();
  chatEl.scrollTop = chatEl.scrollHeight;
  if (composerWrapEl?.classList.contains("is-open")) syncAiAssistThread();
  return bubble;
}

function resizeInput() {
  if (!inputEl) return;
  inputEl.style.height = "auto";
  const vh = window.visualViewport?.height || window.innerHeight;
  const isChat = composerWrapEl?.classList.contains("is-chat");
  const maxFrac = isChat ? 0.14 : 0.28;
  const minPx = isChat ? 28 : 0;
  const cap = Math.max(minPx, Math.min(inputEl.scrollHeight, vh * maxFrac));
  inputEl.style.height = `${cap}px`;
}

function syncFloatingComposerToViewport() {
  const wrap = composerWrapEl;
  if (!wrap || !wrap.classList.contains("is-floating") || wrap.classList.contains("is-chat")) return;
  const vv = window.visualViewport;
  if (!vv) return;
  const keyboardPad = Math.max(0, window.innerHeight - vv.height - vv.offsetTop);
  wrap.style.setProperty("--vv-keyboard", `${keyboardPad}px`);
  wrap.style.bottom = `calc(1rem + var(--safe-bottom) + ${keyboardPad}px)`;
}

function closeSidebar() {
  sidebarEl?.classList.remove("open");
  sidebarBackdrop?.classList.remove("show");
  if (sidebarBackdrop) sidebarBackdrop.hidden = true;
  menuToggle?.setAttribute("aria-expanded", "false");
  document.body.classList.remove("sidebar-open");
}

function openSidebar() {
  sidebarEl?.classList.add("open");
  if (sidebarBackdrop) {
    sidebarBackdrop.hidden = false;
    requestAnimationFrame(() => sidebarBackdrop.classList.add("show"));
  }
  menuToggle?.setAttribute("aria-expanded", "true");
  document.body.classList.add("sidebar-open");
}

function updateModeLabel() {
  if (!topbarModeEl || !modeEl) return;
  const opt = modeEl.selectedOptions[0];
  topbarModeEl.textContent = opt ? opt.textContent : modeEl.value;
}

function showSetupPanel(title, text, options = {}) {
  const {
    command = "",
    action = command ? "copy" : "docs",
    tone = "error",
    key = "",
  } = typeof options === "string"
    ? { command: options, action: options ? "copy" : "docs", tone: "error", key: "" }
    : options;

  // Soft info banners can be dismissed for the session
  if (tone === "info" && key && setupDismissedKey === key) {
    hideSetupPanel();
    return;
  }

  setupTitleEl.textContent = title;
  setupTextEl.textContent = text;
  lastSetupCommand = command;
  setupAction = action;
  setupPanelEl.dataset.tone = tone;
  setupPanelEl.dataset.key = key || "";

  if (action === "preload") setupPrimaryEl.textContent = "Preload model";
  else if (action === "settings") setupPrimaryEl.textContent = "Open Settings";
  else if (action === "copy" && command) setupPrimaryEl.textContent = "Copy command";
  else setupPrimaryEl.textContent = "Open docs";

  if (setupDismissEl) {
    setupDismissEl.classList.toggle("hidden", tone === "error");
  }

  setupPanelEl.classList.remove("hidden");
}

function hideSetupPanel() {
  setupPanelEl.classList.add("hidden");
  lastSetupCommand = "";
  setupAction = "";
}

function openSettings() {
  settingsModal.classList.remove("hidden");
  document.body.style.overflow = "hidden";
  loadSettingsForm();
  refreshFinetuneHint();
  loadPlatformTip();
  refreshHermesStatus();
  refreshSettingsToolsHint();
  refreshApiKeysPanel();
  refreshAuditPanel();
  refreshBillingUsage();
}

async function refreshBillingUsage() {
  const box = document.getElementById("billingUsageBox");
  if (!box) return;
  box.textContent = "Loading…";
  try {
    const res = await fetch("/api/billing/usage", { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      box.textContent = data.detail || `Usage unavailable (${res.status})`;
      return;
    }
    const limit = data.messages_limit == null ? "unlimited" : data.messages_limit;
    const remaining = data.messages_remaining == null ? "—" : data.messages_remaining;
    box.innerHTML = `
      <strong>${escapeHtml(data.plan_label || data.plan || "Community")}</strong> plan ·
      ${escapeHtml(String(data.messages_used_this_month ?? 0))} / ${escapeHtml(String(limit))} messages this month
      (${escapeHtml(String(remaining))} remaining)
      ${data.enforcement_enabled ? "" : ' <span class="hint">— soft limit, not enforced yet</span>'}
      ${data.over_limit ? '<div class="hint" style="color:#f85149">Over limit</div>' : ""}
    `;
  } catch {
    box.textContent = "Usage unavailable";
  }
}
on(document.getElementById("billingRefreshBtn"), "click", refreshBillingUsage);

async function refreshApiKeysPanel() {
  const list = document.getElementById("apiKeyList");
  if (!list) return;
  try {
    const res = await fetch("/api/auth/api-keys", { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    const keys = data.api_keys || [];
    if (!keys.length) {
      list.innerHTML = `<li class="hint">No API keys yet${res.ok ? "" : " — enable AUTH_ENABLED to create"}</li>`;
      return;
    }
    list.innerHTML = keys
      .map(
        (k) => `<li class="settings-list-item">
          <span><strong>${escapeHtml(k.name || "key")}</strong> · <code>${escapeHtml(k.key_prefix || k.prefix || k.id || "")}</code></span>
          <button type="button" class="btn-ghost api-key-revoke" data-id="${escapeHtml(k.id)}">Revoke</button>
        </li>`
      )
      .join("");
    list.querySelectorAll(".api-key-revoke").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm("Revoke this API key?")) return;
        const r = await fetch(`/api/auth/api-keys/${btn.getAttribute("data-id")}`, {
          method: "DELETE",
          headers: authHeaders(),
        });
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          alert(err.detail || `HTTP ${r.status}`);
          return;
        }
        refreshApiKeysPanel();
      });
    });
  } catch {
    list.innerHTML = `<li class="hint">API keys unavailable</li>`;
  }
}

async function refreshAuditPanel() {
  const box = document.getElementById("auditLogList");
  if (!box) return;
  try {
    const res = await fetch("/api/audit?limit=40", { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      box.textContent = data.detail || `Audit unavailable (${res.status})`;
      return;
    }
    const events = data.events || [];
    if (!events.length) {
      box.textContent = "No audit events yet";
      return;
    }
    box.innerHTML = `<ul class="settings-list">${events
      .slice(0, 40)
      .map(
        (e) =>
          `<li><code>${escapeHtml(e.action || e.event || "event")}</code> · ${escapeHtml(
            e.username || e.user_id || "—"
          )} · ${escapeHtml(String(e.created_at || e.ts || "").slice(0, 19))}</li>`
      )
      .join("")}</ul>`;
  } catch {
    box.textContent = "Audit unavailable";
  }
}

function closeSettings() {
  settingsModal.classList.add("hidden");
  document.body.style.overflow = "";
}

async function refreshSettingsToolsHint() {
  const hint = document.getElementById("settingsToolsHint");
  if (!hint) return;
  try {
    const res = await fetch("/api/tools", { headers: authHeaders() });
    const data = await res.json();
    const ready = (data.tools || []).filter((t) => t.available).map((t) => t.id);
    hint.textContent = `${data.available_count || 0}/${data.count || 0} tools ready — ${ready.join(", ") || "none"}`;
  } catch {
    hint.textContent = "Tools status unavailable";
  }
}

function syncThemeSelect() {
  const el = document.getElementById("setTheme");
  if (!el) return;
  let saved = null;
  try {
    saved = localStorage.getItem(THEME_KEY);
  } catch {
    /* ignore */
  }
  if (saved === "light" || saved === "dark") el.value = saved;
  else el.value = "system";
}

function applyThemeFromSettings() {
  const el = document.getElementById("setTheme");
  if (!el) return;
  const v = el.value;
  if (v === "system") {
    try {
      localStorage.removeItem(THEME_KEY);
    } catch {
      /* ignore */
    }
    const dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(dark ? "dark" : "light");
    try {
      localStorage.removeItem(THEME_KEY);
    } catch {
      /* ignore */
    }
  } else {
    applyTheme(v);
  }
}

function toggleMenu() {
  if (sidebarEl?.classList.contains("open")) closeSidebar();
  else openSidebar();
}

function shortScopeLabel(text, maxLen = 16) {
  const t = String(text || "")
    .trim()
    .replace(/\s*\(no engagement\)/i, "")
    .replace(/\s+workspace$/i, "")
    .trim();
  if (!t) return "—";
  if (t.length <= maxLen) return t;
  return `${t.slice(0, Math.max(1, maxLen - 1))}…`;
}

function shortLanHost(url) {
  const raw = String(url || "").trim();
  if (!raw) return "";
  try {
    const u = new URL(raw);
    return u.hostname || u.host;
  } catch {
    return raw.replace(/^https?:\/\//i, "").split(/[/?#]/)[0] || raw.slice(0, 20);
  }
}

function isLocalHostClient() {
  const h = (location.hostname || "").toLowerCase();
  return h === "localhost" || h === "127.0.0.1" || h === "[::1]" || h === "::1";
}

function paintLanShareBar(platform) {
  const bar = document.getElementById("lanShareBar");
  const urlEl = document.getElementById("lanShareUrl");
  const copyBtn = document.getElementById("lanShareCopy");
  if (!bar || !urlEl) return;
  const urls = (platform && platform.lan_urls) || [];
  const lanMode = !!(platform && platform.lan_mode);
  const share = (platform && platform.share_url) || urls[0] || "";
  const show = lanMode && isLocalHostClient() && !!share;
  bar.hidden = !show;
  if (!show) return;
  urlEl.textContent = shortLanHost(share);
  urlEl.title = share;
  bar.title = `Share on LAN: ${share}`;
  if (copyBtn && !copyBtn.dataset.wired) {
    copyBtn.dataset.wired = "1";
    copyBtn.addEventListener("click", async () => {
      const text = bar.title.replace(/^Share on LAN:\s*/i, "") || urlEl.title || share;
      try {
        await navigator.clipboard.writeText(text);
        copyBtn.textContent = "Copied";
        setTimeout(() => {
          copyBtn.textContent = "Copy";
        }, 1600);
      } catch {
        copyBtn.textContent = "Select URL";
      }
    });
  }
}

function setVaScanLive(text, show) {
  const el = document.getElementById("vaScanLive");
  if (el) {
    el.hidden = !show;
    el.textContent = text || "";
  }
  const assetsLive = document.getElementById("assetsScanLive");
  if (assetsLive) {
    assetsLive.hidden = !show;
    if (show) assetsLive.textContent = text || "";
  }
}

function pulseVaScanFromPush(push) {
  if (!push) return;
  const st = String(push.status || "").toLowerCase();
  const step = push.step || "";
  const findings = push.findings ?? push.summary?.findings_created ?? push.summary?.findings;
  if (["completed", "failed", "blocked"].includes(st)) {
    setVaScanLive("", false);
    if (typeof setLiveState === "function" && !streaming && !window.__securaiqStreaming) {
      setLiveState("live-on", "Ready", st === "completed" ? "Scan done" : st);
    }
    return;
  }
  const bits = [];
  if (st) bits.push(st.toUpperCase());
  if (step) bits.push(String(step).replace(/_/g, " "));
  if (findings != null) bits.push(`${findings} finding(s)`);
  const label = bits.length ? `VA scan · ${bits.join(" · ")}` : "VA scan running…";
  setVaScanLive(label, true);
  if (typeof setLiveState === "function") {
    setLiveState("live-busy", "VA scan", bits.slice(-2).join(" · ") || "");
  }
}

function isSoftwarePushType(t) {
  return (
    t === "software_inventory" ||
    t === "software.inventory.updated" ||
    t === "software.inventory.updated" ||
    t === "software.vulnerability.changed" ||
    t === "software.vulnerability.changed"
  );
}
window.isSoftwarePushType = isSoftwarePushType;

function isToolPushType(t) {
  return t === "tool" || t === "tool_progress";
}
window.isToolPushType = isToolPushType;

function toolActivityMessage(push) {
  push = push || {};
  if (push.message) return String(push.message);
  const kind = push.kind || push.tool || "tool";
  const st = String(push.status || "running").toLowerCase();
  const findings = push.findings != null && Number(push.findings) > 0 ? ` · ${push.findings} finding(s)` : "";
  const target = push.target ? ` on ${String(push.target).slice(0, 48)}` : "";
  const tools = Array.isArray(push.tools) && push.tools.length ? push.tools.slice(0, 4).join(", ") : kind;
  if (st === "done") return `${tools} finished${target}${findings}`;
  if (st === "error") return `${tools} failed${target}`;
  if (push.file) return `Code scan · ${push.file}`;
  return `${tools} ${st}${target}`;
}

function pulseMcLiveLine(text) {
  const liveLine = document.getElementById("mcSoftwareLiveLine");
  const liveDot = document.getElementById("mcSoftwareLiveDot");
  if (liveLine && text) {
    liveLine.hidden = false;
    liveLine.textContent = text;
    clearTimeout(window.__securaiqMcSwLiveTimer);
    window.__securaiqMcSwLiveTimer = setTimeout(() => {
      if (!window.__securaiqSoftwareSyncBusy) {
        liveLine.hidden = true;
        liveLine.textContent = "";
      }
    }, 14000);
  }
  if (liveDot) {
    liveDot.classList.add("is-live");
    clearTimeout(window.__securaiqMcSwDotTimer);
    window.__securaiqMcSwDotTimer = setTimeout(() => liveDot.classList.remove("is-live"), 4000);
  }
}

function pulseToolFromPush(push) {
  if (!push) return;
  const kind = push.kind || push.tool || "tool";
  const st = String(push.status || "done").toLowerCase();
  const label = toolActivityMessage(push);
  if (typeof setLiveState === "function") {
    setLiveState(st === "done" ? "live-on" : st === "error" ? "live-off" : "live-busy", kind, st);
  }
  pulseMcLiveLine(label);
  const vaLive = document.getElementById("vaScanLive");
  if (vaLive) {
    vaLive.hidden = false;
    vaLive.textContent = label;
  }
  const swLive = document.getElementById("softwareScanLive");
  if (swLive) {
    swLive.hidden = false;
    swLive.textContent = label;
    clearTimeout(window.__securaiqSwLiveTimer);
    window.__securaiqSwLiveTimer = setTimeout(() => {
      if (!window.__securaiqSoftwareSyncBusy) {
        swLive.hidden = true;
        swLive.textContent = "";
      }
    }, 12000);
  }
  const assetsLive = document.getElementById("assetsScanLive");
  if (assetsLive && /sync|inventory|lan|audit|scan|wazuh|xdr|openaudit|software|tool/.test(String(kind))) {
    assetsLive.hidden = false;
    assetsLive.textContent = label;
  }
  if (typeof window.pushSoftwareActivity === "function") {
    window.pushSoftwareActivity({
      ...push,
      message: label,
      ts: push.ts || Date.now() / 1000,
      action: st === "error" ? "vuln" : "tool",
    });
  }
  const toolsPane = document.getElementById("mcToolUpdatesBody");
  if (toolsPane && !toolsPane.classList.contains("hidden")) {
    toolsPane.querySelectorAll("[data-tool-id]").forEach((row) => {
      const id = row.getAttribute("data-tool-id") || "";
      if (id && String(kind).toLowerCase().includes(id.toLowerCase())) {
        row.classList.add("sw-row-updated");
        setTimeout(() => row.classList.remove("sw-row-updated"), 2200);
      }
    });
  }
  if (st === "done" || st === "error") {
    clearTimeout(window.__securaiqMcToolRtTimer);
    window.__securaiqMcToolRtTimer = setTimeout(() => {
      if (typeof refreshMcToolUpdates === "function") refreshMcToolUpdates(false);
    }, 400);
  }
}
window.pulseToolFromPush = pulseToolFromPush;

const SOFTWARE_RT_TYPES = new Set([
  "software_inventory",
  "software.inventory.updated",
  "software.inventory.updated",
  "software.vulnerability.changed",
  "software.vulnerability.changed",
]);
window.SOFTWARE_RT_TYPES = SOFTWARE_RT_TYPES;

function patchSoftwareMcKpis(push) {
  if (!push) return;
  const issues = push.issues != null ? Number(push.issues) || 0 : null;
  const health = push.health_score != null ? Number(push.health_score) || 0 : null;
  const swIssuesEl = document.getElementById("ccSoftwareIssues");
  const swBarEl = document.getElementById("ccSoftwareHealthBar");
  const swTrendEl = document.getElementById("ccSoftwareTrend");
  const swHealthPct = document.getElementById("ccSoftwareHealthPct");
  const wzPatchEl = document.getElementById("wzPatchHealthPct");
  if (issues != null && swIssuesEl) {
    const prev = Number(swIssuesEl.textContent || 0);
    swIssuesEl.textContent = String(issues);
    if (swTrendEl && prev !== issues) {
      const d = issues - prev;
      swTrendEl.textContent = d === 0 ? "" : d > 0 ? `↑ ${d}` : `↓ ${Math.abs(d)}`;
      swTrendEl.classList.toggle("up-bad", d > 0);
      swTrendEl.classList.toggle("down-good", d < 0);
    }
  }
  if (health != null) {
    const pct = Math.min(100, Math.max(0, health));
    if (swBarEl) swBarEl.style.width = `${pct}%`;
    const label = `${Math.round(pct)}%`;
    if (swHealthPct) swHealthPct.textContent = label;
    if (wzPatchEl) wzPatchEl.textContent = label;
  }
}
window.patchSoftwareMcKpis = patchSoftwareMcKpis;

async function refreshMcSoftwareFromPush(push) {
  patchSoftwareMcKpis(push || {});
  const liveLine = document.getElementById("mcSoftwareLiveLine");
  const liveDot = document.getElementById("mcSoftwareLiveDot");
  const msg = (push && push.message) || "";
  if (liveLine && msg) {
    pulseMcLiveLine(msg);
  } else if (liveDot) {
    liveDot.classList.add("is-live");
    clearTimeout(window.__securaiqMcSwDotTimer);
    window.__securaiqMcSwDotTimer = setTimeout(() => liveDot.classList.remove("is-live"), 4000);
  }
  const panel = document.getElementById("mcSoftwarePostureBody");
  if (!panel) return;
  clearTimeout(window.__securaiqMcSwPanelTimer);
  window.__securaiqMcSwPanelTimer = setTimeout(async () => {
    try {
      const res = await fetch("/api/software/summary", { headers: authHeaders() });
      if (!res.ok) return;
      const data = await res.json().catch(() => ({}));
      if (typeof renderMcSoftwarePosturePanel === "function") {
        renderMcSoftwarePosturePanel(data.posture || {});
      }
    } catch {
      /* ignore */
    }
  }, 350);
}
window.refreshMcSoftwareFromPush = refreshMcSoftwareFromPush;

function pulseSoftwareFromPush(push) {
  if (!push) return;
  patchSoftwareMcKpis(push);
  refreshMcSoftwareFromPush(push);
  if (typeof window.pushSoftwareActivity === "function") {
    window.pushSoftwareActivity(push);
  }
  const bits = ["Software inventory"];
  if (push.needs_update != null) bits.push(`${push.needs_update} need update`);
  if (push.up_to_date != null) bits.push(`${push.up_to_date} up to date`);
  if (push.total_products != null) bits.push(`${push.total_products} products`);
  if (push.issues != null) bits.push(`${push.issues} issue(s)`);
  if (push.health_score != null) bits.push(`${push.health_score}% health`);
  const label = push.message || bits.join(" · ");
  const swLive = document.getElementById("softwareScanLive");
  if (swLive) {
    swLive.hidden = false;
    swLive.textContent = label;
    clearTimeout(window.__securaiqSwLiveTimer);
    window.__securaiqSwLiveTimer = setTimeout(() => {
      if (!window.__securaiqSoftwareSyncBusy) {
        swLive.hidden = true;
        swLive.textContent = "";
      }
    }, 12000);
  }
  if (typeof setLiveState === "function") {
    setLiveState("live-on", "Software", push.needs_update ? `${push.needs_update} patch gap(s)` : "updated");
  }
}
window.pulseSoftwareFromPush = pulseSoftwareFromPush;

function pulseInventoryFromPush(push) {
  if (!push) return;
  const action = String(push.action || "").toLowerCase();
  const bits = ["Inventory"];
  if (action === "queued") bits.push("queued");
  if (action === "host" || action === "upsert") bits.push("live");
  if (push.ip) bits.push(String(push.ip));
  if (push.hostname) bits.push(String(push.hostname));
  if (push.ports != null) bits.push(`${push.ports} port(s)`);
  if (push.shares != null && Number(push.shares) > 0) bits.push(`${push.shares} share(s)`);
  if (push.count != null) bits.push(`${push.count} host(s)`);
  if (push.devices_total != null) bits.push(`${push.devices_total} cached`);
  const label = bits.join(" · ");
  const assetsLive = document.getElementById("assetsScanLive");
  if (assetsLive) {
    assetsLive.hidden = false;
    assetsLive.textContent = label;
  }
  if (typeof setLiveState === "function") {
    setLiveState("live-busy", "Inventory", push.ip || action || "live");
  }
}

function pulseToolProgress(push) {
  if (!push) return;
  const scanned = Number(push.scanned || 0);
  const total = Number(push.total || 0);
  const findings = Number(push.findings || 0);
  const label = `Code scan ${scanned}/${total || "?"} · ${findings} finding(s)${push.file ? ` · ${push.file}` : ""}`;
  const live = document.getElementById("codeScanLive");
  if (live) {
    live.hidden = false;
    live.textContent = label;
  }
  setVaScanLive(label, true);
  if (typeof setLiveState === "function") {
    setLiveState("live-busy", `Code scan ${scanned}/${total || "?"}`, `${findings} findings`);
  }
  if (findings > 0 && typeof syncLiveWorkspace === "function") {
    clearTimeout(window.__securaiqToolProgTimer);
    window.__securaiqToolProgTimer = setTimeout(() => syncLiveWorkspace({ pushType: "vuln" }), 350);
  }
}

async function refreshIntelStrip() {
  const intelEl = document.getElementById("ccIntel");
  if (!intelEl) return;
  try {
    const res = await fetch("/api/intel/watch", { headers: authHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    const watch = data.watch || [];
    if (watch.length) {
      intelEl.innerHTML = watch
        .slice(0, 6)
        .map(
          (w) =>
            `<li class="cc-clickable" data-workspace="intel"><strong>${escapeHtml(
              w.value || ""
            )}</strong> <span class="hint">${escapeHtml(w.kind || "")} · ${escapeHtml(
              (w.notes || "").slice(0, 60)
            )}</span></li>`
        )
        .join("");
    } else {
      intelEl.innerHTML = `<li class="hint">No watchlist items — open Threat intel to add CVEs or sync CISA KEV.</li>
        <li><button type="button" class="cc-action" data-workspace="intel">Open threat intel</button></li>`;
    }
    intelEl.querySelectorAll("[data-workspace]").forEach((el) =>
      el.addEventListener("click", () => window.showWorkspace?.(el.getAttribute("data-workspace")))
    );
  } catch {
    /* ignore */
  }
}
window.refreshIntelStrip = refreshIntelStrip;
window.pulseVaScanFromPush = pulseVaScanFromPush;
window.pulseInventoryFromPush = pulseInventoryFromPush;
window.pulseToolProgress = pulseToolProgress;

function syncLiveWorkspace(opts) {
  opts = opts || {};
  const pushType = opts.pushType || "";
  const isSwPush = typeof isSoftwarePushType === "function" ? isSoftwarePushType(pushType) : SOFTWARE_RT_TYPES.has(pushType);
  const isToolPush = typeof isToolPushType === "function" ? isToolPushType(pushType) : pushType === "tool" || pushType === "tool_progress";
  const isLivePush = REALTIME_LIVE_TYPES.has(pushType) || pushType === "job";
  try {
    if (isLivePush && !isSwPush && !isToolPush) {
      if (typeof loadAssets === "function") loadAssets();
      if (typeof loadVulns === "function") loadVulns();
      if (typeof loadCommandCenter === "function") loadCommandCenter();
    } else if (isSwPush) {
      if (typeof refreshMcSoftwareFromPush === "function") refreshMcSoftwareFromPush(opts.push || {});
      if (typeof window.refreshSoftwareFromPush === "function") {
        window.refreshSoftwareFromPush(opts.push || {}, { partial: true });
      }
    } else if (isToolPush) {
      /* Tool UI is pulsed in applyRealtimeWorkspaceRefresh — avoid duplicate activity rows. */
    }
  } catch {
    /* ignore */
  }
  if (pushType === "intel" || pushType === "intel_watch") {
    refreshIntelStrip();
  }
  const view = window.__securaiqWorkspaceView || "";
  const rt = (fn) => {
    if (typeof fn !== "function") return;
    try {
      fn({ quiet: true, pushType });
    } catch {
      /* ignore */
    }
  };
  try {
    if (isLivePush || view === "assets") rt(window.renderAssetsPage);
    if ((isLivePush || view === "software") && !isSwPush) rt(window.renderSoftwarePage);
    if (isLivePush || view === "vulns") rt(window.renderVulnsPage);
    if (isLivePush || view === "soc") rt(window.renderSocPage);
    if (isLivePush || view === "intel") rt(window.renderIntelPage);
    if (isLivePush || view === "risks") rt(window.renderRisksPage);
    if (isLivePush || view === "remediations") rt(window.renderRemsPage);
    if (isLivePush || view === "playbooks") rt(window.renderPlaybooksPage);
    if (isLivePush || view === "campaigns") rt(window.renderCampaignsPage);
    if (isLivePush || view === "evidence") rt(window.renderEvidencePage);
    if (isLivePush || view === "graph") rt(window.renderGraphPage);
    if (isLivePush || view === "integrations") rt(window.renderIntegrationsPage);
    if (isLivePush || view === "automation") rt(window.refreshAutomationPage);
    if (isLivePush || view === "frameworks") {
      rt(window.renderFrameworksPage);
      if (typeof window.renderHardeningPanel === "function") window.renderHardeningPanel();
    }
    if (isLivePush || view === "reports") rt(window.renderReportsPage);
    if (isLivePush || view === "command") rt(loadCommandCenter);
    if (isLivePush && typeof window.renderWazuhDashboard === "function" && view === "command") {
      /* loadCommandCenter calls renderWazuhDashboard */
    }
  } catch {
    /* ignore */
  }
}
window.syncLiveWorkspace = syncLiveWorkspace;
window.refreshMissionControl = loadCommandCenter;

async function loadPlatformTip() {
  let platform = null;
  try {
    const res = await fetch("/api/platform", { headers: authHeaders() });
    platform = await res.json();
    paintLanShareBar(platform);
    if (lanTipEl) {
      const urls = (platform.lan_urls || []).map((u) => `<code>${u}</code>`).join(" · ");
      lanTipEl.innerHTML =
        `${platform.client_note || ""}` +
        (urls ? `<br/><strong>LAN:</strong> ${urls}` : "") +
        (platform.os ? `<br/><strong>Host OS:</strong> ${platform.os} · Python ${platform.python}` : "") +
        (platform.lan_mode
          ? `<br/><strong>Devices:</strong> same live workspace — scans and assets appear on every phone/PC.`
          : "");
    }
  } catch {
    if (lanTipEl) {
      lanTipEl.textContent =
        "Phones/tablets: open this app via your host LAN IP on port 8080 (same Wi‑Fi). Backends run on the host.";
    }
  }
  return platform;
}

function renderQuickPrompts() {
  if (!quickEl) return;
  // Empty-start: do not auto-fill suggested prompts on the welcome screen
  quickEl.innerHTML = "";
  quickEl.classList.add("hidden");
  quickEl.setAttribute("aria-hidden", "true");
  updateModeLabel();
}

async function loadModes() {
  try {
    const res = await fetch("/api/modes", { headers: authHeaders() });
    const data = await res.json();
    quickPrompts = data.quick_prompts || {};
    renderQuickPrompts();
  } catch {
    quickEl.innerHTML = "";
  }
}

async function loadBackend() {
  try {
    const res = await fetch("/api/backend", { headers: authHeaders() });
    const data = await res.json();
    backendEl.value = data.backend;
  } catch {
    backendEl.value = "ollama";
  }
}

async function loadModels() {
  try {
    const res = await fetch("/api/models", { headers: authHeaders() });
    const data = await res.json();
    modelEl.innerHTML = "";
    const backend = data.backend || backendEl.value;

    if (
      backend === "huggingface" ||
      backend === "unsloth" ||
      backend === "openai_compat" ||
      backend === "hermes" ||
      backend === "openai" ||
      backend === "openrouter" ||
      backend === "groq" ||
      backend === "together" ||
      backend === "fireworks"
    ) {
      const opt = document.createElement("option");
      opt.value = data.current;
      opt.textContent = data.current;
      modelEl.appendChild(opt);
      modelEl.value = data.current;
      refreshModelStatusBar(backend, data.current, true);
      return;
    }

    const added = new Set();

    for (const name of data.installed || []) {
      const opt = document.createElement("option");
      opt.value = name;
      opt.textContent = name;
      modelEl.appendChild(opt);
      added.add(name);
    }

    for (const rec of data.recommended || []) {
      if (added.has(rec.pull)) continue;
      const opt = document.createElement("option");
      opt.value = rec.pull;
      opt.textContent = `${rec.name} (not installed)`;
      opt.dataset.notInstalled = "1";
      modelEl.appendChild(opt);
    }

    if (data.current) {
      const match = [...modelEl.options].find(
        (o) => o.value === data.current || o.value.startsWith(data.current)
      );
      if (match) modelEl.value = match.value;
    }
    refreshModelStatusBar(backend, modelEl.value || data.current || "", Boolean((data.installed || []).length || data.current));
  } catch {
    modelEl.innerHTML = '<option value="">Models unavailable</option>';
    refreshModelStatusBar("—", "", false);
  }
}

function refreshModelStatusBar(backend, model, ready) {
  if (window.__securaiqStreaming) return;
  const b = backend || backendEl?.value || "—";
  const m = model || modelEl?.value || "";
  setLiveState(ready ? "live-on" : "live-off", ready ? `Ready · ${b}` : "Connect a model", m || "");
}

async function loadSettingsForm() {
  try {
    const res = await fetch("/api/settings", { headers: authHeaders() });
    const s = await res.json();
    if (!res.ok) throw new Error(formatApiDetail(s.detail, `HTTP ${res.status}`));
    syncThemeSelect();
    const setChecked = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.checked = Boolean(val);
    };
    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.value = val ?? "";
    };
    setChecked("setWebSearchEnabled", s.web_search_enabled !== false);
    setVal("setWebSearchMax", s.web_search_max_results ?? 8);
    setVal("setWebSearchTimeout", s.web_search_timeout_sec ?? 5);
    setVal("setSearxngUrl", s.searxng_url || "");
    setChecked("setLocalToolsEnabled", s.local_tools_enabled !== false);
    setChecked("setLocalToolsAuto", s.local_tools_auto !== false);
    setChecked("setLocalToolsHeavy", Boolean(s.local_tools_allow_heavy));
    setChecked("setNetAssessEnabled", s.net_assess_enabled !== false);
    setChecked("setNetAssessNmap", s.net_assess_use_nmap !== false);
    setVal("setJiraUrl", s.jira_base_url || "");
    setVal("setJiraEmail", s.jira_email || "");
    setVal("setJiraProject", s.jira_project_key || "");
    setVal("setJiraToken", "");
    const jiraHint = document.getElementById("jiraTokenHint");
    if (jiraHint) {
      jiraHint.textContent = s.jira_api_token_set
        ? "Saved: •••••••• (hidden)"
        : "Not set — required to create Jira issues";
    }
    document.getElementById("setOllamaUrl").value = s.ollama_base_url || "";
    document.getElementById("setOllamaModel").value = s.ollama_model || "";
    document.getElementById("setHfModel").value = s.hf_model || "";
    setVal("setHfApiModel", s.huggingface_api_model || "");
    document.getElementById("setHfToken").value = "";
    document.getElementById("hfTokenHint").textContent = s.hf_token_set
      ? "Saved: •••••••• (hidden)"
      : "Not set — required for gated Hugging Face / Unsloth models";
    document.getElementById("setUnslothModel").value = s.unsloth_model || "";
    document.getElementById("setUnslothAdapter").value = s.unsloth_adapter_dir || "";
    document.getElementById("setUnslothSeq").value = s.unsloth_max_seq_length || 2048;
    document.getElementById("setUnsloth4bit").checked = Boolean(s.unsloth_load_in_4bit);
    document.getElementById("setHermesUrl").value = s.hermes_base_url || "";
    document.getElementById("setHermesModel").value = s.hermes_model || "";
    document.getElementById("setHermesKey").value = "";
    document.getElementById("hermesKeyHint").textContent = s.hermes_api_key_set
      ? "Saved: •••••••• (hidden)"
      : "Not set";
    document.getElementById("setHermesSessionKey").value = "";
    const sessionHint = document.getElementById("hermesSessionKeyHint");
    if (sessionHint) {
      sessionHint.textContent = s.hermes_session_key_set
        ? "Saved: •••••••• (hidden)"
        : "Optional — leave blank to keep";
    }
    document.getElementById("setHermesTools").checked = s.hermes_show_tool_progress !== false;
    document.getElementById("setCompatUrl").value = s.openai_compat_base_url || "";
    document.getElementById("setCompatModel").value = s.openai_compat_model || "";
    document.getElementById("setCompatKey").value = "";
    document.getElementById("compatKeyHint").textContent = s.openai_compat_api_key_set
      ? "Saved: •••••••• (hidden)"
      : "Not set";
    setChecked("setRouterEnabled", s.router_enabled !== false);
    setVal("setOpenaiKey", "");
    setVal("setOpenaiModel", s.openai_model || "gpt-4o-mini");
    setVal("setOpenrouterKey", "");
    setVal("setOpenrouterModel", s.openrouter_model || "");
    setVal("setGroqKey", "");
    setVal("setGroqModel", s.groq_model || "");
    setVal("setTogetherKey", "");
    setVal("setFireworksKey", "");
    setVal("setOllamaCoder", s.ollama_coder_model || "");
    const setHint = (id, set) => {
      const el = document.getElementById(id);
      if (el) el.textContent = set ? "Saved: •••••••• (hidden)" : "Not set";
    };
    setHint("openaiKeyHint", s.openai_api_key_set);
    setHint("openrouterKeyHint", s.openrouter_api_key_set);
    setHint("groqKeyHint", s.groq_api_key_set);
    setVal("setTogetherModel", s.together_model || "");
    setVal("setFireworksModel", s.fireworks_model || "");
    setHint("togetherKeyHint", s.together_api_key_set);
    setHint("fireworksKeyHint", s.fireworks_api_key_set);
    const intelKeys = [
      ["setAbuseipdbKey", "abuseipdbKeyHint", "abuseipdb_api_key_set"],
      ["setVirustotalKey", "virustotalKeyHint", "virustotal_api_key_set"],
      ["setShodanKey", "shodanKeyHint", "shodan_api_key_set"],
      ["setOtxKey", "otxKeyHint", "otx_api_key_set"],
      ["setUrlscanKey", "urlscanKeyHint", "urlscan_api_key_set"],
      ["setHibpKey", "hibpKeyHint", "hibp_api_key_set"],
      ["setGreynoiseKey", "greynoiseKeyHint", "greynoise_api_key_set"],
      ["setPulsediveKey", "pulsediveKeyHint", "pulsedive_api_key_set"],
      ["setMalwarebazaarKey", "malwarebazaarKeyHint", "malwarebazaar_api_key_set"],
      ["setEmailrepKey", "emailrepKeyHint", "emailrep_api_key_set"],
      ["setUrlhausKey", "urlhausKeyHint", "urlhaus_api_key_set"],
    ];
    for (const [inputId, hintId, setKey] of intelKeys) {
      setVal(inputId, "");
      setHint(hintId, s[setKey]);
    }
    setChecked("setMfaRequiredAdmin", Boolean(s.mfa_required_for_admin));
    setChecked("setOidcEnabled", Boolean(s.oidc_enabled));
    setVal("setOidcIssuer", s.oidc_issuer || "");
    setVal("setOidcClientId", s.oidc_client_id || "");
    setVal("setOidcClientSecret", "");
    setVal("setOidcRedirect", s.oidc_redirect_uri || "");
    setVal("setOidcScopes", s.oidc_scopes || "openid profile email");
    setChecked("setScimEnabled", Boolean(s.scim_enabled));
    setVal("setScimToken", "");
    setHint("scimHint", s.scim_token_set);
    const scimHintEl = document.getElementById("scimHint");
    if (scimHintEl) {
      scimHintEl.textContent = s.scim_enabled
        ? s.scim_token_set
          ? "SCIM ready — IdP base URL /scim/v2 (Users + minimal PATCH/DELETE; no Groups)"
          : "SCIM enabled but token not set"
        : "IdP base URL: /scim/v2 — Users CRUD when enabled (no Groups/Bulk yet)";
    }
    setVal("setGithubWebhookSecret", "");
    setVal("setGitlabWebhookSecret", "");
    setVal("setTaxiiApiRoot", s.taxii_api_root || "");
    setVal("setTaxiiCollectionId", s.taxii_collection_id || "");
    setVal("setTaxiiUsername", s.taxii_username || "");
    setVal("setTaxiiPassword", "");
    setVal("setDatabaseUrl", "");
    setVal("setRedisUrl", "");
    setVal("setWazuhUrl", s.wazuh_base_url || "");
    setVal("setWazuhUser", s.wazuh_user || "");
    setVal("setWazuhPassword", "");
    setVal("setWazuhSyncInterval", s.wazuh_sync_interval_sec ?? 1800);
    setVal("setWazuhIndexerUrl", s.wazuh_indexer_url || "");
    setVal("setWazuhIndexerUser", s.wazuh_indexer_user || "");
    setVal("setWazuhIndexerPassword", "");
    setChecked("setWazuhVerifySsl", !!s.wazuh_verify_ssl);
    setHint("wazuhPasswordHint", s.wazuh_password_set);
    setHint("wazuhIndexerPasswordHint", s.wazuh_indexer_password_set);
    setVal("setOaUrl", s.openaudit_base_url || "");
    setVal("setOaUser", s.openaudit_user || "");
    setVal("setOaPassword", "");
    setVal("setOaPrefix", s.openaudit_api_prefix || "/open-audit/index.php");
    setVal("setOaSyncInterval", s.openaudit_sync_interval_sec ?? 3600);
    setChecked("setSoftwareSyncAuto", s.software_sync_auto_enabled !== false);
    setVal("setSoftwareSyncInterval", s.software_sync_interval_sec ?? 3600);
    setChecked("setSshPatchEnabled", !!s.ssh_patch_enabled);
    setVal("setSshPatchUser", s.ssh_patch_user || "root");
    setVal("setSshPatchKey", s.ssh_patch_key_path || "");
    setVal("setSshPatchMaxHosts", s.ssh_patch_max_hosts ?? 15);
    setChecked("setOaVerifySsl", !!s.openaudit_verify_ssl);
    setHint("oaPasswordHint", s.openaudit_password_set);
    setVal("setHkPath", s.hardeningkitty_module_path || "");
    setVal("setHkList", s.hardeningkitty_list || "");
    setVal("setSonarUrl", s.sonarqube_base_url || "");
    setVal("setSonarToken", "");
    setHint("sonarTokenHint", s.sonarqube_token_set);
    setVal("setSonarProject", s.sonarqube_project_key || "");
    setVal("setSonarTypes", s.sonarqube_issue_types || "VULNERABILITY,SECURITY_HOTSPOT,BUG");
    setChecked("setSonarVerifySsl", s.sonarqube_verify_ssl !== false);
    setVal("setSonarSyncInterval", s.sonarqube_sync_interval_sec ?? 3600);
    setVal("setThUrl", s.thehive_base_url || "");
    setVal("setThApiKey", "");
    setChecked("setThVerifySsl", !!s.thehive_verify_ssl);
    setHint("thApiKeyHint", s.thehive_api_key_set);
    setVal("setAwsRegion", s.aws_region || "us-east-1");
    setVal("setAwsKey", "");
    setHint("awsKeyHint", s.aws_access_key_id_set);
    setVal("setAwsSecret", "");
    setHint("awsSecretHint", s.aws_secret_access_key_set);
    setVal("setAzTenant", s.azure_tenant_id || "");
    setVal("setAzClient", s.azure_client_id || "");
    setVal("setAzSecret", "");
    setHint("azSecretHint", s.azure_client_secret_set);
    setVal("setAzSub", s.azure_subscription_id || "");
    setVal("setGcpProject", s.gcp_project_id || "");
    setVal("setGcpSa", s.gcp_service_account_json || "");
    setVal("setSlackWebhook", "");
    setHint("slackWebhookHint", s.slack_webhook_url_set);
    setVal("setTeamsWebhook", "");
    setHint("teamsWebhookHint", s.teams_webhook_url_set);
    setVal("setSnUrl", s.servicenow_instance_url || "");
    setVal("setSnUser", s.servicenow_username || "");
    setVal("setSnPassword", "");
    setHint("snPasswordHint", s.servicenow_password_set);
    setVal("setSmtpHost", s.smtp_host || "");
    setVal("setSmtpPort", s.smtp_port ?? 587);
    setVal("setSmtpUser", s.smtp_username || "");
    setVal("setSmtpPassword", "");
    setHint("smtpPasswordHint", s.smtp_password_set);
    setVal("setSmtpFrom", s.smtp_from || "");
    setChecked("setSmtpTls", s.smtp_use_tls !== false);
    setVal("setSophosClientId", s.sophos_client_id || "");
    setVal("setSophosClientSecret", "");
    setHint("sophosSecretHint", s.sophos_client_secret_set);
    setVal("setCsClientId", s.crowdstrike_client_id || "");
    setVal("setCsClientSecret", "");
    setHint("csSecretHint", s.crowdstrike_client_secret_set);
    setVal("setCsBaseUrl", s.crowdstrike_base_url || "https://api.crowdstrike.com");
    setVal("setS1BaseUrl", s.sentinelone_base_url || "");
    setVal("setS1Token", "");
    setHint("s1TokenHint", s.sentinelone_api_token_set);
    setVal("setDefTenant", s.defender_tenant_id || "");
    setVal("setDefClient", s.defender_client_id || "");
    setVal("setDefSecret", "");
    setHint("defSecretHint", s.defender_client_secret_set);
    const huntSel = document.getElementById("setDefHuntingApi");
    if (huntSel) huntSel.value = s.defender_hunting_api || "auto";
    setChecked("setPrefectEnabled", !!s.prefect_enabled);
    setVal("setPrefectApiUrl", s.prefect_api_url || "");
    setHint("oidcSecretHint", s.oidc_client_secret_set);
    setHint("githubWebhookHint", s.github_webhook_secret_set ? "Saved: •••••••• (hidden)" : "Not set — enables GitHub webhook");
    setHint("gitlabWebhookHint", s.gitlab_webhook_secret_set ? "Saved: •••••••• (hidden)" : "Not set — enables GitLab webhook");
    const taxiiHintEl = document.getElementById("taxiiHint");
    if (taxiiHintEl) {
      const root = (s.taxii_api_root || "").trim();
      const cid = (s.taxii_collection_id || "").trim();
      taxiiHintEl.textContent =
        root && cid
          ? `TAXII ready${s.taxii_password_set || s.taxii_username ? " (auth set)" : ""} — poll from Threat Intel`
          : "Optional — poll from Threat Intel → STIX / TAXII";
    }
    setHint("databaseUrlHint", s.database_url_set);
    setHint("redisUrlHint", s.redis_url_set);
    await refreshMfaAccountPanel();
    await refreshSettingsToolsHint();
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**Settings load failed:** ${err.message}`), true);
  }
}

async function saveSettings(event) {
  event.preventDefault();
  applyThemeFromSettings();
  const payload = {
    web_search_enabled: document.getElementById("setWebSearchEnabled")?.checked ?? true,
    web_search_max_results: Number(document.getElementById("setWebSearchMax")?.value) || 8,
    web_search_timeout_sec: Number(document.getElementById("setWebSearchTimeout")?.value) || 5,
    searxng_url: document.getElementById("setSearxngUrl")?.value.trim() || "",
    local_tools_enabled: document.getElementById("setLocalToolsEnabled")?.checked ?? true,
    local_tools_auto: document.getElementById("setLocalToolsAuto")?.checked ?? true,
    local_tools_allow_heavy: document.getElementById("setLocalToolsHeavy")?.checked ?? false,
    net_assess_enabled: document.getElementById("setNetAssessEnabled")?.checked ?? true,
    net_assess_use_nmap: document.getElementById("setNetAssessNmap")?.checked ?? true,
    jira_base_url: document.getElementById("setJiraUrl")?.value.trim() || "",
    jira_email: document.getElementById("setJiraEmail")?.value.trim() || "",
    jira_api_token: document.getElementById("setJiraToken")?.value.trim() || "",
    jira_project_key: document.getElementById("setJiraProject")?.value.trim() || "",
    ollama_base_url: document.getElementById("setOllamaUrl").value.trim(),
    ollama_model: document.getElementById("setOllamaModel").value.trim(),
    hf_model: document.getElementById("setHfModel").value.trim(),
    huggingface_api_model: document.getElementById("setHfApiModel")?.value.trim() || "",
    hf_token: document.getElementById("setHfToken").value.trim(),
    unsloth_model: document.getElementById("setUnslothModel").value.trim(),
    unsloth_adapter_dir: document.getElementById("setUnslothAdapter").value.trim(),
    unsloth_max_seq_length: Number(document.getElementById("setUnslothSeq").value) || 2048,
    unsloth_load_in_4bit: document.getElementById("setUnsloth4bit").checked,
    hermes_base_url: document.getElementById("setHermesUrl").value.trim(),
    hermes_model: document.getElementById("setHermesModel").value.trim(),
    hermes_api_key: document.getElementById("setHermesKey").value.trim(),
    hermes_session_key: document.getElementById("setHermesSessionKey").value.trim(),
    hermes_show_tool_progress: document.getElementById("setHermesTools").checked,
    openai_compat_base_url: document.getElementById("setCompatUrl").value.trim(),
    openai_compat_model: document.getElementById("setCompatModel").value.trim(),
    openai_compat_api_key: document.getElementById("setCompatKey").value.trim(),
    router_enabled: document.getElementById("setRouterEnabled")?.checked ?? true,
    openai_api_key: document.getElementById("setOpenaiKey")?.value.trim() || "",
    openai_model: document.getElementById("setOpenaiModel")?.value.trim() || "",
    openrouter_api_key: document.getElementById("setOpenrouterKey")?.value.trim() || "",
    openrouter_model: document.getElementById("setOpenrouterModel")?.value.trim() || "",
    groq_api_key: document.getElementById("setGroqKey")?.value.trim() || "",
    groq_model: document.getElementById("setGroqModel")?.value.trim() || "",
    together_api_key: document.getElementById("setTogetherKey")?.value.trim() || "",
    together_model: document.getElementById("setTogetherModel")?.value.trim() || "",
    fireworks_api_key: document.getElementById("setFireworksKey")?.value.trim() || "",
    fireworks_model: document.getElementById("setFireworksModel")?.value.trim() || "",
    ollama_coder_model: document.getElementById("setOllamaCoder")?.value.trim() || "",
    abuseipdb_api_key: document.getElementById("setAbuseipdbKey")?.value.trim() || "",
    virustotal_api_key: document.getElementById("setVirustotalKey")?.value.trim() || "",
    shodan_api_key: document.getElementById("setShodanKey")?.value.trim() || "",
    otx_api_key: document.getElementById("setOtxKey")?.value.trim() || "",
    urlscan_api_key: document.getElementById("setUrlscanKey")?.value.trim() || "",
    hibp_api_key: document.getElementById("setHibpKey")?.value.trim() || "",
    greynoise_api_key: document.getElementById("setGreynoiseKey")?.value.trim() || "",
    pulsedive_api_key: document.getElementById("setPulsediveKey")?.value.trim() || "",
    malwarebazaar_api_key: document.getElementById("setMalwarebazaarKey")?.value.trim() || "",
    emailrep_api_key: document.getElementById("setEmailrepKey")?.value.trim() || "",
    urlhaus_api_key: document.getElementById("setUrlhausKey")?.value.trim() || "",
    mfa_required_for_admin: document.getElementById("setMfaRequiredAdmin")?.checked ?? false,
    oidc_enabled: document.getElementById("setOidcEnabled")?.checked ?? false,
    oidc_issuer: document.getElementById("setOidcIssuer")?.value.trim() || "",
    oidc_client_id: document.getElementById("setOidcClientId")?.value.trim() || "",
    oidc_client_secret: document.getElementById("setOidcClientSecret")?.value.trim() || "",
    oidc_redirect_uri: document.getElementById("setOidcRedirect")?.value.trim() || "",
    oidc_scopes: document.getElementById("setOidcScopes")?.value.trim() || "",
    scim_enabled: document.getElementById("setScimEnabled")?.checked ?? false,
    scim_token: document.getElementById("setScimToken")?.value.trim() || "",
    github_webhook_secret: document.getElementById("setGithubWebhookSecret")?.value.trim() || "",
    gitlab_webhook_secret: document.getElementById("setGitlabWebhookSecret")?.value.trim() || "",
    taxii_api_root: document.getElementById("setTaxiiApiRoot")?.value.trim() || "",
    taxii_collection_id: document.getElementById("setTaxiiCollectionId")?.value.trim() || "",
    taxii_username: document.getElementById("setTaxiiUsername")?.value.trim() || "",
    taxii_password: document.getElementById("setTaxiiPassword")?.value.trim() || "",
    database_url: document.getElementById("setDatabaseUrl")?.value.trim() || "",
    redis_url: document.getElementById("setRedisUrl")?.value.trim() || "",
    wazuh_base_url: document.getElementById("setWazuhUrl")?.value.trim() || "",
    wazuh_user: document.getElementById("setWazuhUser")?.value.trim() || "",
    wazuh_password: document.getElementById("setWazuhPassword")?.value.trim() || "",
    wazuh_verify_ssl: document.getElementById("setWazuhVerifySsl")?.checked ?? false,
    wazuh_sync_interval_sec: Number(document.getElementById("setWazuhSyncInterval")?.value) || 1800,
    wazuh_indexer_url: document.getElementById("setWazuhIndexerUrl")?.value.trim() || "",
    wazuh_indexer_user: document.getElementById("setWazuhIndexerUser")?.value.trim() || "",
    wazuh_indexer_password: document.getElementById("setWazuhIndexerPassword")?.value.trim() || "",
    openaudit_base_url: document.getElementById("setOaUrl")?.value.trim() || "",
    openaudit_user: document.getElementById("setOaUser")?.value.trim() || "",
    openaudit_password: document.getElementById("setOaPassword")?.value.trim() || "",
    openaudit_api_prefix: document.getElementById("setOaPrefix")?.value.trim() || "/open-audit/index.php",
    openaudit_verify_ssl: document.getElementById("setOaVerifySsl")?.checked ?? false,
    openaudit_sync_interval_sec: Number(document.getElementById("setOaSyncInterval")?.value) || 3600,
    software_sync_auto_enabled: document.getElementById("setSoftwareSyncAuto")?.checked ?? true,
    software_sync_interval_sec: Number(document.getElementById("setSoftwareSyncInterval")?.value) || 3600,
    ssh_patch_enabled: document.getElementById("setSshPatchEnabled")?.checked ?? false,
    ssh_patch_user: document.getElementById("setSshPatchUser")?.value.trim() || "root",
    ssh_patch_key_path: document.getElementById("setSshPatchKey")?.value.trim() || "",
    ssh_patch_max_hosts: Number(document.getElementById("setSshPatchMaxHosts")?.value) || 15,
    hardeningkitty_module_path: document.getElementById("setHkPath")?.value.trim() || "",
    hardeningkitty_list: document.getElementById("setHkList")?.value.trim() || "",
    sonarqube_base_url: document.getElementById("setSonarUrl")?.value.trim() || "",
    sonarqube_token: document.getElementById("setSonarToken")?.value.trim() || "",
    sonarqube_project_key: document.getElementById("setSonarProject")?.value.trim() || "",
    sonarqube_issue_types: document.getElementById("setSonarTypes")?.value.trim() || "VULNERABILITY,SECURITY_HOTSPOT,BUG",
    sonarqube_verify_ssl: document.getElementById("setSonarVerifySsl")?.checked ?? true,
    sonarqube_sync_interval_sec: Number(document.getElementById("setSonarSyncInterval")?.value) || 3600,
    thehive_base_url: document.getElementById("setThUrl")?.value.trim() || "",
    thehive_api_key: document.getElementById("setThApiKey")?.value.trim() || "",
    thehive_verify_ssl: document.getElementById("setThVerifySsl")?.checked ?? false,
    aws_region: document.getElementById("setAwsRegion")?.value.trim() || "us-east-1",
    aws_access_key_id: document.getElementById("setAwsKey")?.value.trim() || "",
    aws_secret_access_key: document.getElementById("setAwsSecret")?.value.trim() || "",
    azure_tenant_id: document.getElementById("setAzTenant")?.value.trim() || "",
    azure_client_id: document.getElementById("setAzClient")?.value.trim() || "",
    azure_client_secret: document.getElementById("setAzSecret")?.value.trim() || "",
    azure_subscription_id: document.getElementById("setAzSub")?.value.trim() || "",
    gcp_project_id: document.getElementById("setGcpProject")?.value.trim() || "",
    gcp_service_account_json: document.getElementById("setGcpSa")?.value.trim() || "",
    slack_webhook_url: document.getElementById("setSlackWebhook")?.value.trim() || "",
    teams_webhook_url: document.getElementById("setTeamsWebhook")?.value.trim() || "",
    servicenow_instance_url: document.getElementById("setSnUrl")?.value.trim() || "",
    servicenow_username: document.getElementById("setSnUser")?.value.trim() || "",
    servicenow_password: document.getElementById("setSnPassword")?.value.trim() || "",
    smtp_host: document.getElementById("setSmtpHost")?.value.trim() || "",
    smtp_port: Number(document.getElementById("setSmtpPort")?.value) || 587,
    smtp_username: document.getElementById("setSmtpUser")?.value.trim() || "",
    smtp_password: document.getElementById("setSmtpPassword")?.value.trim() || "",
    smtp_from: document.getElementById("setSmtpFrom")?.value.trim() || "",
    smtp_use_tls: document.getElementById("setSmtpTls")?.checked ?? true,
    sophos_client_id: document.getElementById("setSophosClientId")?.value.trim() || "",
    sophos_client_secret: document.getElementById("setSophosClientSecret")?.value.trim() || "",
    crowdstrike_client_id: document.getElementById("setCsClientId")?.value.trim() || "",
    crowdstrike_client_secret: document.getElementById("setCsClientSecret")?.value.trim() || "",
    crowdstrike_base_url: document.getElementById("setCsBaseUrl")?.value.trim() || "",
    sentinelone_base_url: document.getElementById("setS1BaseUrl")?.value.trim() || "",
    sentinelone_api_token: document.getElementById("setS1Token")?.value.trim() || "",
    defender_tenant_id: document.getElementById("setDefTenant")?.value.trim() || "",
    defender_client_id: document.getElementById("setDefClient")?.value.trim() || "",
    defender_client_secret: document.getElementById("setDefSecret")?.value.trim() || "",
    defender_hunting_api: document.getElementById("setDefHuntingApi")?.value || "auto",
    prefect_enabled: document.getElementById("setPrefectEnabled")?.checked ?? false,
    prefect_api_url: document.getElementById("setPrefectApiUrl")?.value.trim() || "",
  };
  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(formatApiDetail(err.detail, `HTTP ${res.status}`));
    }
    // Mirror tool toggles into sidebar for this session
    if (localToolsEl) localToolsEl.checked = payload.local_tools_enabled;
    if (netAssessEl) netAssessEl.checked = payload.net_assess_enabled && (netAssessEl.checked || modeEl.value === "assess");
    if (webSearchEl && !payload.web_search_enabled) webSearchEl.checked = false;
    appendMessage("assistant", renderMarkdown("**Settings saved** to `.env` (secrets stay masked)."), true);
    await loadSettingsForm();
    await loadModels();
    await loadToolsStatus();
    await checkHealth();
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**Save failed:** ${err.message}`), true);
  }
}

async function refreshHermesStatus() {
  const hint = document.getElementById("hermesStatusHint");
  if (!hint) return;
  hint.textContent = "Status: checking…";
  try {
    const res = await fetch("/api/hermes/status", { headers: authHeaders() });
    const data = await res.json();
    if (!data.reachable) {
      hint.textContent = `Status: offline — ${data.error || "start hermes gateway"}`;
      return;
    }
    const models = (data.models || []).join(", ") || data.model || "hermes-agent";
    const feats = data.capabilities?.features
      ? Object.entries(data.capabilities.features)
          .filter(([, v]) => v)
          .map(([k]) => k)
          .slice(0, 6)
          .join(", ")
      : "chat_completions";
    hint.textContent = `Status: online · models: ${models} · features: ${feats}`;
  } catch (err) {
    hint.textContent = `Status: error — ${err.message}`;
  }
}

function newHermesSession() {
  hermesSessionId = "";
  localStorage.removeItem("hermesSessionId");
  resetHermesNext = true;
  appendMessage(
    "assistant",
    renderMarkdown("**New Hermes session** — next message starts a fresh Hermes Agent transcript (tools/memory scope uses your session key)."),
    true
  );
}

async function refreshFinetuneHint() {
  try {
    const res = await fetch("/api/finetune", { headers: authHeaders() });
    const job = await res.json();
    if (job.status === "idle") {
      finetuneHint.textContent = "Idle — trains on data/ethical_pentest_dataset.jsonl";
    } else {
      finetuneHint.textContent = `${job.status}: ${job.message || job.engine}`;
    }
    const busy = job.status === "running";
    trainBtn.disabled = busy || streaming;
    settingsTrainBtn.disabled = busy;
  } catch {
    finetuneHint.textContent = "Finetune status unavailable";
  }
}

async function startUnslothTrain() {
  const epochs = Number(document.getElementById("setTrainEpochs")?.value) || 1;
  try {
    const res = await fetch("/api/finetune", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ engine: "unsloth", epochs }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    appendMessage(
      "assistant",
      renderMarkdown(
        `**Unsloth training started** (${data.model} → \`${data.output}\`, ${data.epochs} epoch(s)).\n\nGPU recommended. Watch status via Settings or `/api/finetune`.`
      ),
      true
    );
    refreshFinetuneHint();
    closeSettings();
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**Train failed to start:** ${err.message}`), true);
  }
}

async function switchModel(modelName) {
  if (!modelName) return;
  if (backendEl.value !== "ollama") return;
  await fetch("/api/models/switch", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ model: modelName }),
  });
  checkHealth();
}

async function switchBackend(backend) {
  await fetch("/api/backend", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ backend }),
  });
  await loadModels();
  await checkHealth();
}

async function ingestRag() {
  if (streaming) return;
  ingestBtn.disabled = true;
  try {
    const res = await fetch("/api/ingest", { method: "POST", headers: authHeaders() });
    const data = await res.json();
    appendMessage(
      "assistant",
      renderMarkdown(`**RAG re-indexed:** ${data.documents_ingested} documents.`),
      true
    );
    checkHealth();
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**Re-index failed:** ${err.message}`), true);
  } finally {
    ingestBtn.disabled = false;
  }
}

async function pullModel() {
  const modelName = modelEl.value;
  if (!modelName || streaming) return;

  streaming = true;
  pullBtn.disabled = true;
  sendBtn.disabled = true;

  const body = appendMessage("assistant", "", false);
  body.classList.add("typing");
  let fullText = `Pulling **${modelName}** via Ollama…\n\n`;

  try {
    const res = await fetch("/api/models/pull", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ model: modelName }),
    });
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      fullText += decoder.decode(value, { stream: true });
      body.innerHTML = renderMarkdown(fullText);
      chatEl.scrollTop = chatEl.scrollHeight;
    }
    body.classList.remove("typing");
    body.innerHTML = renderMarkdown(fullText + "\n\n**Done.** Refreshing model list…");
    await loadModels();
    await switchModel(modelName);
  } catch (err) {
    body.classList.remove("typing");
    body.innerHTML = renderMarkdown(`**Pull failed:** ${err.message}`);
  } finally {
    streaming = false;
    pullBtn.disabled = false;
    sendBtn.disabled = false;
  }
}

async function preloadModel() {
  if (streaming) return;
  if (backendEl.value !== "huggingface" && backendEl.value !== "unsloth") return;

  streaming = true;
  preloadBtn.disabled = true;
  sendBtn.disabled = true;

  const body = appendMessage("assistant", "", false);
  body.classList.add("typing");
  let fullText = `Preloading **${modelEl.value}**…\n\n`;

  try {
    const res = await fetch("/api/models/preload", { method: "POST", headers: authHeaders() });
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      fullText += decoder.decode(value, { stream: true });
      body.innerHTML = renderMarkdown(fullText);
      chatEl.scrollTop = chatEl.scrollHeight;
    }
    body.classList.remove("typing");
    body.innerHTML = renderMarkdown(fullText + "\n\n**Model ready.**");
    await checkHealth();
  } catch (err) {
    body.classList.remove("typing");
    body.innerHTML = renderMarkdown(`**Preload failed:** ${err.message}`);
  } finally {
    streaming = false;
    preloadBtn.disabled = false;
    sendBtn.disabled = false;
  }
}

async function ensureWorkingBackend(healthData) {
  if (autoSwitchAttempted) return false;
  if (healthData.backend_ready) return false;
  autoSwitchAttempted = true;
  try {
    const res = await fetch("/api/backends/probe", { headers: authHeaders() });
    const probe = await res.json();
    const next = probe.recommended;
    if (!next || next === healthData.backend) {
      return false;
    }
    await switchBackend(next);
    appendMessage(
      "assistant",
      renderMarkdown(
        `**Auto-switched AI backend** to \`${next}\` because \`${healthData.backend}\` was offline.\n\nYou can change this anytime in the backend dropdown or Settings.`
      ),
      true
    );
    return true;
  } catch {
    return false;
  }
}

let lastHealthData = null;

async function checkHealth() {
  try {
    const res = await fetch("/api/health", { headers: authHeaders() });
    const data = await res.json();
    lastHealthData = data;
    const rag = data.rag_documents != null ? ` · RAG:${data.rag_documents}` : "";
    const backend = data.backend;
    backendEl.value = backend;

    // Prefer ready remote backends; fall back to HuggingFace/Unsloth (loads on chat)
    const canChat =
      Boolean(data.backend_ready) ||
      data.backend_status === "loads_on_chat";
    backendReady = canChat;
    sendBtn.disabled = streaming || !backendReady;
    preloadBtn.classList.add("hidden");
    trainBtn.classList.add("hidden");
    if (hermesNewSessionBtn) hermesNewSessionBtn.classList.add("hidden");

    if (!canChat) {
      const switched = await ensureWorkingBackend(data);
      if (switched) return;
    }

    if (data.finetune) {
      const ft = data.finetune;
      if (ft.status === "running") {
        finetuneHint.textContent = `running: ${ft.message || ft.model}`;
        trainBtn.disabled = true;
      } else if (ft.status === "completed" || ft.status === "failed") {
        finetuneHint.textContent = `${ft.status}: ${ft.message}`;
        trainBtn.disabled = streaming;
      }
    }

    if (backend === "ollama") {
      modelEl.disabled = false;
      pullBtn.disabled = streaming;
      if (!data.ollama_connected) {
        statusEl.textContent = `Ollama offline${rag}`;
        statusEl.className = "status err";
        showSetupPanel(
          "Start Ollama",
          "No Ollama server is running yet. Start Ollama, then pull a model to enable chat.",
          { command: "ollama pull tinyllama", action: "copy", tone: "error" }
        );
      } else if (!data.ollama_has_models) {
        statusEl.textContent = `Ollama ready · pull a model${rag}`;
        statusEl.className = "status err";
        showSetupPanel(
          "Pull a local model",
          "Ollama is reachable, but no local model is installed yet.",
          { command: "ollama pull tinyllama", action: "copy", tone: "warn" }
        );
      } else {
        statusEl.textContent = `${backend} · ${data.model}${rag}`;
        statusEl.className = "status ok";
        hideSetupPanel();
      }
    } else {
      modelEl.disabled = false;
      pullBtn.disabled = true;
      const statusSuffix = data.backend_status === "loads_on_chat" ? " · loads on first chat" : "";

      if (backend === "openai_compat") {
        if (!data.backend_ready) {
          statusEl.textContent = `LM Studio offline${rag}`;
          statusEl.className = "status err";
          showSetupPanel(
            "LM Studio offline",
            "Start LM Studio’s local server (OpenAI-compatible) on http://localhost:1234/v1, or fix the URL/key in Settings.",
            { action: "settings", tone: "error" }
          );
        } else {
          statusEl.textContent = `${backend} · ${data.model}${rag}`;
          statusEl.className = "status ok";
          hideSetupPanel();
        }
      } else if (backend === "hermes") {
        if (hermesNewSessionBtn) hermesNewSessionBtn.classList.remove("hidden");
        if (!data.backend_ready) {
          statusEl.textContent = `Hermes offline${rag}`;
          statusEl.className = "status err";
          showSetupPanel(
            "Hermes Agent offline",
            "Run hermes gateway with API_SERVER_ENABLED=true. Set the API key in Settings to match API_SERVER_KEY.",
            { command: "hermes gateway", action: "copy", tone: "error" }
          );
        } else {
          const sid = hermesSessionId ? ` · sess:${hermesSessionId.slice(0, 8)}…` : "";
          statusEl.textContent = `${backend} · ${data.model}${sid}${rag}`;
          statusEl.className = "status ok";
          hideSetupPanel();
        }
      } else if (backend === "unsloth") {
        trainBtn.classList.remove("hidden");
        preloadBtn.classList.remove("hidden");
        if (data.unsloth_model_loaded) {
          statusEl.textContent = `${backend} · ${data.model}${rag}`;
          statusEl.className = "status ok";
          hideSetupPanel();
        } else {
          statusEl.textContent = `${backend} · ${data.model}${statusSuffix}${rag}`;
          statusEl.className = "status ok";
          // Ready to chat — soft tip only, not an error
          const tip = data.hf_token_set
            ? "Unsloth will load on first chat. You can also Preload now."
            : "Unsloth will load on first chat. Add an HF token in Settings only for gated models.";
          showSetupPanel("Unsloth ready", tip, {
            action: "preload",
            tone: "info",
            key: "unsloth-ready",
          });
        }
      } else if (backend === "huggingface") {
        preloadBtn.classList.remove("hidden");
        const speedTip =
          "For much faster replies: install Ollama, pull a model (e.g. mistral), then set Backend → Ollama in Settings.";
        if (data.hf_model_loaded) {
          statusEl.textContent = `${backend} · ${data.model}${rag}`;
          statusEl.className = "status ok";
          showSetupPanel("Speed tip", speedTip, { action: "settings", tone: "info", key: "hf-speed" });
        } else {
          statusEl.textContent = `${backend} · ${data.model}${statusSuffix}${rag}`;
          statusEl.className = "status ok";
          showSetupPanel(
            "Hugging Face (slower on CPU)",
            `Model loads on first message. ${speedTip}`,
            { action: "preload", tone: "warn", key: "hf-ready" }
          );
        }
      } else {
        statusEl.textContent = `${backend} · ${data.model}${rag}`;
        statusEl.className = data.backend_ready ? "status ok" : "status err";
        if (!data.backend_ready) {
          showSetupPanel(
            "Backend not ready",
            "Check Settings and README for backend setup if chat is not responding.",
            { action: "settings", tone: "error" }
          );
        } else {
          hideSetupPanel();
        }
      }
    }
  } catch {
    backendReady = false;
    sendBtn.disabled = true;
    statusEl.textContent = "Offline";
    statusEl.className = "status err";
    showSetupPanel(
      "Server offline",
      "Start the backend with .\\scripts\\start.ps1 (Windows) or bash scripts/start.sh (Linux/macOS).",
      { command: ".\\scripts\\start.ps1", action: "copy", tone: "error" }
    );
  }
}

async function sendMessage() {
  if (currentView !== "chat") showView("chat", { skipFocus: true });
  let message = inputEl.value.trim();
  const hasFiles = pendingAttachments.length > 0;
  if ((!message && !hasFiles) || streaming) return;
  if (!backendReady) {
    appendMessage(
      "assistant",
      renderMarkdown("**Backend not ready.** Check the status bar and connect a local model backend first."),
      true
    );
    return;
  }

  streaming = true;
  window.__securaiqStreaming = true;
  sendBtn.disabled = true;
  inputEl.value = "";
  resizeInput();

  let attachmentIds = [];
  let attachmentNames = [];
  try {
    if (hasFiles) {
      const up = await uploadPendingAttachments();
      attachmentIds = up.ids;
      attachmentNames = up.names;
      pendingAttachments = [];
      renderAttachChips();
    }
  } catch (err) {
    streaming = false;
    sendBtn.disabled = !backendReady;
    appendMessage("assistant", renderMarkdown(`**Attachment upload failed:** ${err.message}`), true);
    return;
  }

  if (!message && attachmentIds.length) {
    message = "Please review the attached file(s).";
  }

  const userBubble = appendMessage("user", message);
  if (attachmentNames.length) {
    const wrap = document.createElement("div");
    wrap.className = "msg-attachments";
    wrap.innerHTML = attachmentNames
      .map((n) => `<span class="msg-attach-pill">📎 ${n.replace(/</g, "&lt;")}</span>`)
      .join("");
    userBubble.appendChild(wrap);
  }

  const assistantBody = appendMessage("assistant", "", false);
  startThinkingUI(assistantBody);
  let fullText = "";
  let answerStarted = false;
  let pendingCitations = null;

  const captureCitations = (text) =>
    text.replace(/\[\[citations:([^\]]+)\]\]/g, (_, b64) => {
      try {
        pendingCitations = JSON.parse(atob(b64));
      } catch {
        /* malformed marker — ignore, no citations shown for this turn */
      }
      return "";
    });

  const renderCitations = () => {
    if (!pendingCitations || !pendingCitations.length) return;
    const answer = assistantBody.querySelector(".answer-body") || assistantBody;
    const box = document.createElement("div");
    box.className = "citations-box";
    const label = document.createElement("div");
    label.className = "citations-label";
    label.textContent = "Sources (retrieved knowledge, not verified against live web):";
    box.appendChild(label);
    const list = document.createElement("ul");
    list.className = "citations-list";
    pendingCitations.forEach((c) => {
      const li = document.createElement("li");
      const pct = typeof c.relevance === "number" ? `${Math.round(c.relevance * 100)}%` : "n/a";
      const confidenceClass =
        typeof c.relevance === "number"
          ? c.relevance >= 0.7
            ? "conf-high"
            : c.relevance >= 0.4
            ? "conf-med"
            : "conf-low"
          : "conf-unknown";
      li.innerHTML = `<span class="citation-tag">[${c.id || "?"}]</span> ${c.source || "unknown"} <span class="citation-confidence ${confidenceClass}">${pct} relevance</span>`;
      list.appendChild(li);
    });
    box.appendChild(list);
    answer.appendChild(box);
  };

  try {
    const cid = await ensureServerChat().catch(() => null);
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        message,
        history,
        mode: modeEl.value,
        use_rag: ragEl.checked,
        use_web_search: webSearchEl ? webSearchEl.checked : modeEl.value === "research",
        use_net_assess: netAssessEl ? netAssessEl.checked : modeEl.value === "assess",
        use_local_tools:
          selectedTools.length > 0 ? true : localToolsEl ? localToolsEl.checked : true,
        tools: selectedTools.length ? selectedTools.slice() : null,
        target: targetIpEl && targetIpEl.value.trim() ? targetIpEl.value.trim() : null,
        authorized_target: authorizedTargetEl ? authorizedTargetEl.checked : false,
        engagement_id: engagementSelectEl?.value || null,
        chat_id: cid,
        attachment_ids: attachmentIds,
        hermes_session_id: hermesSessionId || null,
        reset_hermes_session: resetHermesNext,
      }),
    });
    resetHermesNext = false;

    if (!res.ok) {
      const errBody = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status}${errBody ? `: ${errBody.slice(0, 120)}` : ""}`);
    }

    const headerSid = res.headers.get("X-Hermes-Session-Id");
    if (headerSid) {
      hermesSessionId = headerSid;
      localStorage.setItem("hermesSessionId", hermesSessionId);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let carry = "";

    const paintAnswer = () => {
      if (!answerStarted && fullText.trim()) {
        answerStarted = true;
        finishThinkingUI(true);
        const thinkSnap = assistantBody.querySelector(".thinking-card");
        assistantBody.classList.remove("thinking", "typing");
        assistantBody.innerHTML = "";
        if (thinkSnap) {
          thinkSnap.classList.add("thinking-collapsed");
          assistantBody.appendChild(thinkSnap);
        }
        const answer = document.createElement("div");
        answer.className = "answer-body";
        assistantBody.appendChild(answer);
      }
      const answer = assistantBody.querySelector(".answer-body");
      if (answer) answer.innerHTML = renderMarkdown(fullText);
      else if (fullText.trim()) assistantBody.innerHTML = renderMarkdown(fullText);
      chatEl.scrollTop = chatEl.scrollHeight;
    };

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      carry += decoder.decode(value, { stream: true });
      carry = carry.replace(/\[\[hermes_session:([^\]]+)\]\]/g, (_, sid) => {
        hermesSessionId = sid;
        localStorage.setItem("hermesSessionId", hermesSessionId);
        return "";
      });
      carry = captureCitations(carry);
      carry = stripLiveMarkers(carry);
      if (
        (carry.includes("[[hermes_session:") ||
          carry.includes("[[live:") ||
          carry.includes("[[citations:")) &&
        !carry.includes("]]")
      ) {
        continue;
      }
      fullText += carry;
      carry = "";
      paintAnswer();
    }
    if (carry) {
      carry = carry.replace(/\[\[hermes_session:([^\]]+)\]\]/g, (_, sid) => {
        hermesSessionId = sid;
        localStorage.setItem("hermesSessionId", hermesSessionId);
        return "";
      });
      carry = captureCitations(carry);
      carry = stripLiveMarkers(carry);
      fullText += carry;
      paintAnswer();
    }

    applyLiveMarker("done");
    assistantBody.classList.remove("typing", "thinking");
    if (!answerStarted) {
      finishThinkingUI(true);
      assistantBody.innerHTML = renderMarkdown(fullText || "_No response_");
    }
    renderCitations();
    const histUser =
      attachmentNames.length > 0
        ? `${message}\n\n[Attached: ${attachmentNames.join(", ")}]`
        : message;
    history.push({ role: "user", content: histUser });
    history.push({ role: "assistant", content: fullText });
    if (history.length > MAX_MESSAGES) history = history.slice(-MAX_MESSAGES);
    if (!getCurrentChat()) createChat(true, { clearUi: false });
    persistCurrentChat();
    checkHealth();
  } catch (err) {
    finishThinkingUI(false);
    assistantBody.classList.remove("typing", "thinking");
    assistantBody.innerHTML = renderMarkdown(`**Error:** ${err.message}`);
  } finally {
    streaming = false;
    window.__securaiqStreaming = false;
    sendBtn.disabled = !backendReady;
    if (composerWrapEl?.classList.contains("is-open")) syncAiAssistThread();
    inputEl.focus();
    refreshModelStatusBar(backendEl?.value, modelEl?.value, backendReady);
  }
}

sendBtn.addEventListener("click", sendMessage);
on(pullBtn, "click", pullModel);
on(preloadBtn, "click", preloadModel);
on(trainBtn, "click", () => openSettings());
on(ingestBtn, "click", ingestRag);
on(settingsBtn, "click", openSettings);
on(topSettingsBtn, "click", openSettings);
on(authBtn, "click", openAuth);
on(gapBtn, "click", () => openGap());
// Module sidebar nav is owned by workspace.js (pages). Keep only gap modal opener here.
on(gapForm, "submit", runGapAnalysis);
on(riskForm, "submit", submitRisk);
on(assetForm, "submit", submitAsset);
on(playbookForm, "submit", submitPlaybook);
on(campaignForm, "submit", submitCampaign);
on(document.getElementById("remRefreshBtn"), "click", loadRemediations);
on(document.getElementById("vulnImportBtn"), "click", () => vulnFileInput?.click());
on(vulnFileInput, "change", importVulns);
on(document.getElementById("vulnExportBtn"), "click", () =>
  downloadMd("/api/vulnerabilities/export", "securaiq-vulns.md").catch((err) =>
    appendMessage("assistant", renderMarkdown(`**Export failed:** ${err.message}`), true)
  )
);
on(document.getElementById("riskExportBtn"), "click", () =>
  downloadMd("/api/risks/export", "securaiq-risks.md").catch((err) =>
    appendMessage("assistant", renderMarkdown(`**Export failed:** ${err.message}`), true)
  )
);
if (gapModal) {
  gapModal.querySelectorAll("[data-close-gap]").forEach((el) => el.addEventListener("click", closeGap));
}
if (dashModal) {
  dashModal.querySelectorAll("[data-close-dash]").forEach((el) => el.addEventListener("click", closeDash));
}
if (riskModal) {
  riskModal.querySelectorAll("[data-close-risk]").forEach((el) => el.addEventListener("click", closeRisk));
}
if (vulnModal) {
  vulnModal.querySelectorAll("[data-close-vuln]").forEach((el) => el.addEventListener("click", closeVuln));
}
if (assetModal) {
  assetModal.querySelectorAll("[data-close-asset]").forEach((el) => el.addEventListener("click", closeAsset));
}
if (remModal) {
  remModal.querySelectorAll("[data-close-rem]").forEach((el) => el.addEventListener("click", closeRem));
}
if (playbookModal) {
  playbookModal.querySelectorAll("[data-close-playbook]").forEach((el) => el.addEventListener("click", closePlaybook));
}
if (campaignModal) {
  campaignModal.querySelectorAll("[data-close-campaign]").forEach((el) => el.addEventListener("click", closeCampaign));
}
on(newEngagementBtn, "click", createEngagement);
on(document.getElementById("renameEngagementBtn"), "click", renameEngagement);
on(document.getElementById("exportEngagementBtn"), "click", exportEngagement);
on(document.getElementById("engagementStatusBtn"), "click", changeEngagementStatus);
on(document.getElementById("aiCanvasSave"), "click", () => {
  const ta = document.getElementById("aiCanvasNotes");
  try {
    localStorage.setItem("securaiq.canvas", ta?.value || "");
    notifyUser("**Canvas saved** locally.");
  } catch (err) {
    notifyUser(`**Save failed:** ${err.message}`);
  }
});
on(uploadBtn, "click", () => fileUploadInput?.click());
on(fileUploadInput, "change", uploadFile);
on(attachBtn, "click", () => chatAttachInput?.click());
on(chatAttachInput, "change", () => {
  if (chatAttachInput?.files?.length) {
    queueChatFiles(chatAttachInput.files);
    chatAttachInput.value = "";
  }
});
if (composerEl) {
  ["dragenter", "dragover"].forEach((ev) => {
    composerEl.addEventListener(ev, (e) => {
      e.preventDefault();
      composerEl.classList.add("drag-over");
    });
  });
  ["dragleave", "drop"].forEach((ev) => {
    composerEl.addEventListener(ev, (e) => {
      e.preventDefault();
      composerEl.classList.remove("drag-over");
    });
  });
  composerEl.addEventListener("drop", (e) => {
    const files = e.dataTransfer?.files;
    if (files?.length) queueChatFiles(files);
  });
}
on(inputEl, "paste", (e) => {
  const items = e.clipboardData?.items;
  if (!items) return;
  const files = [];
  for (const it of items) {
    if (it.kind === "file") {
      const f = it.getAsFile();
      if (f) files.push(f);
    }
  }
  if (files.length) {
    e.preventDefault();
    queueChatFiles(files);
  }
});
on(exportMdBtn, "click", exportCurrentChat);
on(engagementSelectEl, "change", () => {
  serverChatId = null;
  if (currentView === "command") loadCommandCenter();
});
on(authForm, "submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("authUser")?.value?.trim();
  const password = document.getElementById("authPass")?.value || "";
  const totp = document.getElementById("authMfa")?.value?.trim() || "";
  const mfaToken = document.getElementById("authMfaToken")?.value?.trim() || "";
  const mfaWrap = document.getElementById("authMfaWrap");
  try {
    let res;
    if (mfaToken && totp) {
      res = await fetch("/api/auth/mfa/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mfa_token: mfaToken, totp }),
      });
    } else {
      res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, totp: totp || undefined }),
      });
    }
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    if (data.mfa_required) {
      if (mfaWrap) mfaWrap.classList.remove("hidden");
      const tokEl = document.getElementById("authMfaToken");
      if (tokEl) tokEl.value = data.mfa_token || "";
      appendMessage("assistant", renderMarkdown("**MFA required** — enter your authenticator code and submit again."), true);
      return;
    }
    authToken = data.token;
    localStorage.setItem(AUTH_TOKEN_KEY, authToken);
    if (mfaWrap) mfaWrap.classList.add("hidden");
    const tokEl = document.getElementById("authMfaToken");
    if (tokEl) tokEl.value = "";
    await refreshAuthStatus();
    await loadEngagements();
    closeAuth();
    appendMessage("assistant", renderMarkdown(`**Signed in** as ${data.user.username}`), true);
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**Login failed:** ${err.message}`), true);
  }
});
on(document.getElementById("authOidcBtn"), "click", () => {
  window.location.href = "/api/auth/oidc/login";
});
on(document.getElementById("mfaEnrollBtn"), "click", async () => {
  try {
    const res = await fetch("/api/auth/mfa/enroll", { method: "POST", headers: authHeaders() });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    const secretEl = document.getElementById("mfaOtpSecret");
    if (secretEl) {
      secretEl.value = data.secret || "";
      secretEl.type = "password";
    }
    const reveal = document.getElementById("mfaRevealSecret");
    if (reveal) reveal.textContent = "Show secret";
    document.getElementById("mfaEnrollBlock")?.classList.remove("hidden");
    document.getElementById("mfaEnrollBtn")?.classList.add("hidden");
    document.getElementById("mfaAccountHint").textContent =
      "Copy the secret into your authenticator app (hidden by default), then enter a verification code.";
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**MFA enroll failed:** ${err.message}`), true);
  }
});
on(document.getElementById("mfaRevealSecret"), "click", () => {
  const secretEl = document.getElementById("mfaOtpSecret");
  const btn = document.getElementById("mfaRevealSecret");
  if (!secretEl) return;
  const showing = secretEl.type === "text";
  secretEl.type = showing ? "password" : "text";
  if (btn) btn.textContent = showing ? "Show secret" : "Hide secret";
});
on(document.getElementById("mfaConfirmBtn"), "click", async () => {
  const code = document.getElementById("mfaConfirmCode")?.value?.trim() || "";
  if (!code) return;
  try {
    const res = await fetch("/api/auth/mfa/confirm", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ code }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    document.getElementById("mfaConfirmCode").value = "";
    document.getElementById("mfaEnrollBlock")?.classList.add("hidden");
    await refreshAuthStatus();
    appendMessage("assistant", renderMarkdown("**MFA enabled** on your account."), true);
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**MFA confirm failed:** ${err.message}`), true);
  }
});
on(document.getElementById("mfaCancelEnrollBtn"), "click", async () => {
  document.getElementById("mfaEnrollBlock")?.classList.add("hidden");
  document.getElementById("mfaConfirmCode").value = "";
  await refreshAuthStatus();
});
on(document.getElementById("mfaDisableBtn"), "click", async () => {
  const code = window.prompt("Enter your authenticator code to disable MFA:");
  if (!code) return;
  try {
    const res = await fetch("/api/auth/mfa/disable", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ code: code.trim() }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    await refreshAuthStatus();
    appendMessage("assistant", renderMarkdown("**MFA disabled** on your account."), true);
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**MFA disable failed:** ${err.message}`), true);
  }
});
on(document.getElementById("authRegisterBtn"), "click", async () => {
  const username = document.getElementById("authUser")?.value?.trim();
  const password = document.getElementById("authPass")?.value || "";
  const email = document.getElementById("authEmail")?.value?.trim() || null;
  try {
    const res = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, email }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    authToken = data.token;
    localStorage.setItem(AUTH_TOKEN_KEY, authToken);
    await refreshAuthStatus();
    await loadEngagements();
    closeAuth();
    appendMessage("assistant", renderMarkdown(`**Registered** as ${data.user.username}`), true);
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**Register failed:** ${err.message}`), true);
  }
});
on(document.getElementById("authLogoutBtn"), "click", async () => {
  await fetch("/api/auth/logout", { method: "POST", headers: authHeaders() });
  authToken = "";
  localStorage.removeItem(AUTH_TOKEN_KEY);
  await refreshAuthStatus();
  closeAuth();
});
if (authModal) {
  authModal.querySelectorAll("[data-close-auth]").forEach((el) => el.addEventListener("click", closeAuth));
}
on(hermesNewSessionBtn, "click", newHermesSession);
on(hermesRefreshStatusBtn, "click", refreshHermesStatus);
on(menuToggle, "click", toggleMenu);
on(sidebarBackdrop, "click", closeSidebar);
if (window.visualViewport) {
  window.visualViewport.addEventListener("resize", syncFloatingComposerToViewport);
  window.visualViewport.addEventListener("scroll", syncFloatingComposerToViewport);
}
window.addEventListener("resize", () => {
  if (window.matchMedia("(min-width: 901px)").matches) closeSidebar();
  syncFloatingComposerToViewport();
});
on(newChatBtn, "click", () => {
  showView("chat");
  serverChatId = null;
  newChat();
});
on(themeToggleBtn, "click", toggleTheme);
on(themeToggleTopBtn, "click", toggleTheme);
on(settingsForm, "submit", saveSettings);
on(document.getElementById("setWazuhTestBtn"), "click", async () => {
  const hint = document.getElementById("wazuhTestHint");
  const btn = document.getElementById("setWazuhTestBtn");
  if (hint) hint.textContent = "Testing…";
  if (btn) btn.disabled = true;
  try {
    const res = await fetch("/api/siem/status", { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(formatApiDetail(data.detail, `HTTP ${res.status}`));
    const ping = data.ping || {};
    if (!data.configured) {
      if (hint) hint.textContent = "Not configured — save Manager URL, user, and password, then Test again.";
    } else if (ping.ok) {
      if (hint) {
        hint.textContent = `SecuraIQ SIEM connected${data.base_url ? ` · ${data.base_url}` : ""}${
          ping.api_version ? ` · API ${ping.api_version}` : ""
        }${data.indexer_configured ? " · Indexer on" : " · Indexer off"}`;
      }
    } else {
      if (hint) hint.textContent = ping.error || "SecuraIQ SIEM connection failed";
    }
  } catch (err) {
    if (hint) hint.textContent = err.message || String(err);
  } finally {
    if (btn) btn.disabled = false;
  }
});
on(document.getElementById("setOaTestBtn"), "click", async () => {
  const hint = document.getElementById("oaTestHint");
  const btn = document.getElementById("setOaTestBtn");
  if (hint) hint.textContent = "Testing…";
  if (btn) btn.disabled = true;
  try {
    const res = await fetch("/api/openaudit/status", { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(formatApiDetail(data.detail, `HTTP ${res.status}`));
    const ping = data.ping || {};
    if (!data.configured) {
      if (hint) hint.textContent = "Not configured — save URL, user, and password first.";
    } else if (ping.ok) {
      if (hint) {
        hint.textContent = `Connected${ping.host ? ` to ${ping.host}` : ""}${
          ping.devices_hint != null ? ` · ${ping.devices_hint} device(s)` : ""
        }`;
      }
    } else {
      if (hint) hint.textContent = ping.error || "Connection failed";
    }
  } catch (err) {
    if (hint) hint.textContent = err.message || String(err);
  } finally {
    if (btn) btn.disabled = false;
  }
});
on(document.getElementById("setHkTestBtn"), "click", async () => {
  const hint = document.getElementById("hkTestHint");
  const btn = document.getElementById("setHkTestBtn");
  if (hint) hint.textContent = "Detecting…";
  if (btn) btn.disabled = true;
  try {
    const res = await fetch("/api/hardeningkitty/status", { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(formatApiDetail(data.detail, `HTTP ${res.status}`));
    if (data.installed) {
      if (data.module_path) setVal("setHkPath", data.module_path);
      if (hint) {
        hint.textContent = `Found · ${data.finding_lists || 0} lists (${data.cis_lists || 0} CIS) · ${data.module_path || ""}`;
      }
    } else {
      if (hint) {
        hint.textContent =
          "Not found — run .\\scripts\\use_hardeningkitty.cmd or set module path, then Save.";
      }
    }
  } catch (err) {
    if (hint) hint.textContent = err.message || String(err);
  } finally {
    if (btn) btn.disabled = false;
  }
});
on(document.getElementById("setSonarTestBtn"), "click", async () => {
  const hint = document.getElementById("sonarTestHint");
  const btn = document.getElementById("setSonarTestBtn");
  if (hint) hint.textContent = "Testing…";
  if (btn) btn.disabled = true;
  try {
    const res = await fetch("/api/code/test", { method: "POST", headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(formatApiDetail(data.detail, `HTTP ${res.status}`));
    if (data.ok) {
      if (hint) hint.textContent = `Connected · ${data.status || "UP"}${data.version ? ` · v${data.version}` : ""}`;
    } else {
      if (hint) hint.textContent = data.error || "Not configured — save URL + token first";
    }
  } catch (err) {
    if (hint) hint.textContent = err.message || String(err);
  } finally {
    if (btn) btn.disabled = false;
  }
});
on(document.getElementById("setThTestBtn"), "click", async () => {
  const hint = document.getElementById("thTestHint");
  const btn = document.getElementById("setThTestBtn");
  if (hint) hint.textContent = "Testing…";
  if (btn) btn.disabled = true;
  try {
    const res = await fetch("/api/thehive/status", { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(formatApiDetail(data.detail, `HTTP ${res.status}`));
    const ping = data.ping || {};
    if (!data.configured) {
      if (hint) hint.textContent = "Not configured — save URL and API key first.";
    } else if (ping.ok) {
      if (hint) {
        hint.textContent = `Connected${data.base_url ? ` to ${data.base_url}` : ""}${
          data.cases_cached != null ? ` · ${data.cases_cached} case(s) cached` : ""
        }`;
      }
    } else {
      if (hint) hint.textContent = ping.error || "Connection failed";
    }
  } catch (err) {
    if (hint) hint.textContent = err.message || String(err);
  } finally {
    if (btn) btn.disabled = false;
  }
});
on(document.getElementById("setCloudTestBtn"), "click", async () => {
  const hint = document.getElementById("cloudTestHint");
  const btn = document.getElementById("setCloudTestBtn");
  if (hint) hint.textContent = "Testing…";
  if (btn) btn.disabled = true;
  try {
    const res = await fetch("/api/cloud/status", { headers: authHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(formatApiDetail(data.detail, `HTTP ${res.status}`));
    const vendors = data.vendors || {};
    const ping = data.ping || {};
    const labels = { aws_security_hub: "AWS", azure_defender: "Azure", gcp_scc: "GCP" };
    const parts = Object.entries(vendors).map(([id, v]) => {
      if (!v.configured) return `${labels[id] || id}: not set`;
      const p = ping[id] || {};
      return `${labels[id] || id}: ${p.ok ? "ok" : p.error || "error"}`;
    });
    if ((data.configured_count || 0) === 0) {
      if (hint) hint.textContent = "No cloud vendors configured — save AWS, Azure, or GCP credentials first.";
    } else if (hint) {
      hint.textContent = parts.join(" · ");
    }
  } catch (err) {
    if (hint) hint.textContent = err.message || String(err);
  } finally {
    if (btn) btn.disabled = false;
  }
});
on(settingsTrainBtn, "click", startUnslothTrain);
on(document.getElementById("settingsRefreshTools"), "click", () => {
  refreshSettingsToolsHint();
  loadToolsStatus();
});
on(document.getElementById("apiKeyCreateBtn"), "click", async () => {
  const nameEl = document.getElementById("apiKeyName");
  const hint = document.getElementById("apiKeyCreatedHint");
  const name = nameEl?.value?.trim() || "default";
  try {
    const res = await fetch("/api/auth/api-keys", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ name }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    if (hint) {
      hint.classList.remove("hidden");
      hint.innerHTML = `Created — copy now: <code>${escapeHtml(data.api_key || "")}</code>`;
    }
    if (nameEl) nameEl.value = "";
    refreshApiKeysPanel();
  } catch (err) {
    if (hint) {
      hint.classList.remove("hidden");
      hint.textContent = err.message || "Create failed";
    }
  }
});
on(document.getElementById("auditRefreshBtn"), "click", () => refreshAuditPanel());
on(document.getElementById("auditExportBtn"), "click", async () => {
  try {
    const res = await fetch("/api/audit/export", { headers: authHeaders() });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || `HTTP ${res.status}`);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "securaiq-audit.csv";
    a.click();
    URL.revokeObjectURL(url);
    appendMessage("assistant", renderMarkdown("**Audit log exported** as CSV."), true);
  } catch (err) {
    appendMessage("assistant", renderMarkdown(`**Audit export failed:** ${err.message}`), true);
  }
});
on(document.getElementById("setTheme"), "change", applyThemeFromSettings);
if (settingsModal) {
  settingsModal.querySelectorAll("[data-close-settings]").forEach((el) => {
    el.addEventListener("click", closeSettings);
  });
}
on(backendEl, "change", () => {
  switchBackend(backendEl.value);
  closeSidebar();
});
on(modeEl, "change", () => {
  const mode = modeEl.value;
  // Only auto-enable expensive toggles for modes that need them (keeps default chat fast)
  if (webSearchEl) webSearchEl.checked = mode === "research";
  if (netAssessEl) netAssessEl.checked = mode === "assess";
  if (localToolsEl) {
    localToolsEl.checked =
      mode === "assess" || mode === "lab_offensive" || selectedTools.length > 0;
  }
  renderQuickPrompts();
  const chat = getCurrentChat();
  if (chat) {
    chat.mode = mode;
    persistCurrentChat();
  }
  closeSidebar();
});
on(setupPrimaryEl, "click", async () => {
  if (setupAction === "preload") {
    hideSetupPanel();
    await preloadModel();
    return;
  }
  if (setupAction === "settings") {
    openSettings();
    return;
  }
  if (setupAction === "copy" && lastSetupCommand) {
    try {
      await navigator.clipboard.writeText(lastSetupCommand);
      appendMessage("assistant", renderMarkdown(`Copied command: \`${lastSetupCommand}\``), true);
    } catch {
      appendMessage("assistant", renderMarkdown(`Run this command:\n\n\`${lastSetupCommand}\``), true);
    }
    return;
  }
  appendMessage(
    "assistant",
    renderMarkdown("See `README.md` and `docs/cursor-local-models.md` for backend setup steps."),
    true
  );
});
on(setupDismissEl, "click", () => {
  const key = setupPanelEl?.dataset?.key || "";
  if (key) {
    setupDismissedKey = key;
    sessionStorage.setItem("setupDismissed", key);
  }
  hideSetupPanel();
});

on(modelEl, "change", () => {
  if (backendEl.value !== "ollama") return;
  const opt = modelEl.selectedOptions[0];
  if (opt?.dataset.notInstalled) return;
  switchModel(modelEl.value);
});

on(inputEl, "keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});
on(inputEl, "input", resizeInput);

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    if (gapModal && !gapModal.classList.contains("hidden")) closeGap();
    else if (dashModal && !dashModal.classList.contains("hidden")) closeDash();
    else if (riskModal && !riskModal.classList.contains("hidden")) closeRisk();
    else if (vulnModal && !vulnModal.classList.contains("hidden")) closeVuln();
    else if (assetModal && !assetModal.classList.contains("hidden")) closeAsset();
    else if (remModal && !remModal.classList.contains("hidden")) closeRem();
    else if (playbookModal && !playbookModal.classList.contains("hidden")) closePlaybook();
    else if (campaignModal && !campaignModal.classList.contains("hidden")) closeCampaign();
    else if (authModal && !authModal.classList.contains("hidden")) closeAuth();
    else if (settingsModal && !settingsModal.classList.contains("hidden")) closeSettings();
    else if (composerWrapEl?.classList.contains("is-open")) closeAiAssistant();
    else closeSidebar();
  }
});

initTheme();
loadBackend();
loadModes();
loadModels();
loadToolsStatus();
startRealtimeFeed();
ensureActiveChat();
refreshAuthStatus().then(loadEngagements);
checkHealth().then(() => {
  showWelcome();
  loadPlatformTip().then((p) => {
    const lanClient = !!(p && p.lan_mode) && !isLocalHostClient();
    showView(lanClient ? "command" : "chat", { skipFocus: true });
    syncLiveWorkspace();
  });
});
wireCommandCenterUi();
setInterval(checkHealth, 90000);
setInterval(() => {
  if (currentView === "command") loadCommandCenter();
}, 60000);
// Fallback live refresh if SSE stalls — keeps open workspace panels warm
setInterval(() => {
  if (typeof window.__securaiqRefreshActiveView === "function") {
    window.__securaiqRefreshActiveView({}, { heartbeat: true });
  }
}, 15000);
document.addEventListener("visibilitychange", () => {
  if (document.hidden) return;
  syncLiveWorkspace();
  const es = window.__securaiqRealtimeEs;
  if (!es || es.readyState === EventSource.CLOSED) startRealtimeFeed();
});
window.addEventListener("pageshow", () => syncLiveWorkspace());
window.addEventListener("online", () => {
  startRealtimeFeed();
  syncLiveWorkspace();
});
resizeInput();

/* ---- Notifications panel (bell icon) -------------------------------- */
/* Backend: GET/POST /api/notifications — was previously unwired; notifBtn
   just navigated to the SOC view and the badge was a client-side guess from
   dashboard vuln/incident counts. This replaces the badge with the real
   unread_count and gives the bell an actual dropdown list. */

async function fetchNotifications() {
  try {
    const res = await fetch("/api/notifications?limit=30", { headers: authHeaders() });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function setNotifBadge(count) {
  const badge = document.getElementById("notifBadge");
  if (!badge) return;
  const n = Number(count || 0);
  badge.hidden = n <= 0;
  badge.textContent = String(Math.min(99, n));
}

function renderNotifList(data) {
  const list = document.getElementById("notifList");
  if (!list) return;
  const items = data?.notifications || [];
  if (!items.length) {
    list.innerHTML = '<p class="notif-empty">No notifications yet.</p>';
    return;
  }
  list.innerHTML = items
    .map((n) => {
      const time = n.created_at ? new Date(n.created_at * 1000).toLocaleString() : "";
      return `<div class="notif-item ${n.read ? "" : "unread"}" data-id="${n.id}">
        <div class="notif-title">${escapeHtml(n.title || "")}</div>
        ${n.body ? `<div class="notif-body">${escapeHtml(n.body)}</div>` : ""}
        <div class="notif-time">${escapeHtml(time)}</div>
      </div>`;
    })
    .join("");
  list.querySelectorAll(".notif-item").forEach((el) => {
    el.addEventListener("click", async () => {
      const id = el.getAttribute("data-id");
      if (!el.classList.contains("unread")) return;
      el.classList.remove("unread");
      try {
        await fetch(`/api/notifications/${id}/read`, { method: "POST", headers: authHeaders() });
        const fresh = await fetchNotifications();
        if (fresh) setNotifBadge(fresh.unread_count);
      } catch {
        /* badge just stays slightly stale — not worth surfacing an error for */
      }
    });
  });
}

async function refreshNotifBadge() {
  const data = await fetchNotifications();
  if (data) setNotifBadge(data.unread_count);
  return data;
}

async function toggleNotifPanel() {
  const panel = document.getElementById("notifPanel");
  const btn = document.getElementById("notifBtn");
  if (!panel) return;
  if (!panel.classList.contains("hidden")) {
    panel.classList.add("hidden");
    btn?.setAttribute("aria-expanded", "false");
    return;
  }
  panel.classList.remove("hidden");
  btn?.setAttribute("aria-expanded", "true");
  const list = document.getElementById("notifList");
  if (list) list.innerHTML = '<p class="hint">Loading…</p>';
  const data = await fetchNotifications();
  renderNotifList(data);
  if (data) setNotifBadge(data.unread_count);
}

on(document.getElementById("notifBtn"), "click", (e) => {
  e.preventDefault();
  e.stopImmediatePropagation();
  toggleNotifPanel();
});
on(document.getElementById("notifMarkAllRead"), "click", async (e) => {
  e.preventDefault();
  try {
    await fetch("/api/notifications/read-all", { method: "POST", headers: authHeaders() });
    renderNotifList(await fetchNotifications());
    setNotifBadge(0);
  } catch {
    /* ignore — user can retry */
  }
});
document.addEventListener("click", (e) => {
  const panel = document.getElementById("notifPanel");
  const btn = document.getElementById("notifBtn");
  const wrap = e.target.closest?.(".notif-wrap");
  if (panel && !panel.classList.contains("hidden") && !wrap) {
    panel.classList.add("hidden");
    btn?.setAttribute("aria-expanded", "false");
  }
});

refreshNotifBadge();
setInterval(refreshNotifBadge, 45000);

async function loadToolsStatus() {
  if (!toolsStatusEl) return;
  try {
    const res = await fetch("/api/tools", { headers: authHeaders() });
    const data = await res.json();
    const avail = data.available_count ?? 0;
    const total = data.count ?? 0;
    const names = (data.tools || [])
      .filter((t) => t.available)
      .map((t) => t.id)
      .slice(0, 8)
      .join(", ");
    toolsStatusEl.textContent = `Tools ${avail}/${total} ready${names ? `: ${names}` : ""}`;
    const aw = (data.auto_awareness || ["phishing_url", "email_auth"]).join(", ");
    toolsStatusEl.title =
      `Awareness auto: ${aw}\n` +
      (data.tools || [])
        .map((t) => `${t.available ? "✓" : "·"} ${t.id} — ${t.description}`)
        .join("\n");
  } catch {
    toolsStatusEl.textContent = "Tools: unavailable";
  }
}

async function showWelcome() {
  if (emptyLeadEl) {
    emptyLeadEl.textContent =
      "Ask about authorized security work — posture, compliance, findings, or remediations.";
  }
  syncEmptyState();
  renderChatList();
  updateChatTitle();
  syncServerChats();
}

/* ops surfaces: /api/soc /api/reports /api/search /api/intel/watch /api/incidents */

