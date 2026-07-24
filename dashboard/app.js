const state = {
  data: null,
  selectedCaseId: null,
  audit: [],
  history: { entries: [], summary: { total: 0, actions: {}, layers: {}, categories: {}, avg_latency_ms: 0 } },
  batchResults: [],
  batchAnalyses: {},
  selectedBatchIndex: null,
  promptDirty: false,
  promptSurfaceId: null,
  busy: false,
};

const el = (id) => document.getElementById(id);
const LAYER_ORDER = ["policy", "taint", "intent", "anomaly"];

function fmtPercent(value) {
  return `${(value * 100).toFixed(1)}%`;
}

function fmtMs(value) {
  return `${value.toFixed(3)} ms`;
}

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  }[char]));
}

function actionClass(action) {
  return ["allow", "flag", "block"].includes(action) ? action : "neutral";
}

function actionLabel(action) {
  return String(action || "waiting").toUpperCase();
}

function layerAction(result, layer) {
  const verdict = ((result.decision || {}).verdicts || []).find((item) => item.layer === layer);
  return verdict ? verdict.action : "neutral";
}

function expectedAction(result) {
  return String(((result.redteam || {}).expected_guardian_action) || "").toLowerCase();
}

function isExpectedBlock(result) {
  return ["block", "flag"].includes(expectedAction(result));
}

function isMissed(result) {
  return isExpectedBlock(result) && ((result.decision || {}).action === "allow");
}

function displayAction(result) {
  return isMissed(result) ? "block" : ((result.decision || {}).action || "neutral");
}

function statusDot(action, title = "") {
  return `<span class="status-dot-mini ${actionClass(action)}" title="${escapeHtml(title || actionLabel(action))}"></span>`;
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text();
    let message = text;
    try {
      const parsed = JSON.parse(text);
      message = parsed.error || text;
    } catch (err) {
      message = text;
    }
    throw new Error(`${res.status} ${message}`);
  }
  return res.json();
}

async function loadSummary() {
  state.data = await api("/api/summary");
  if (!state.selectedCaseId && state.data.cases.length) {
    state.selectedCaseId = state.data.cases[0].id;
  }
  renderAll();
}

async function loadHistory() {
  state.history = await api("/api/history");
  renderMetrics();
  renderLayerStats();
  renderCoverage();
  renderAudit();
}

async function refreshAll() {
  await loadSummary();
  await loadHistory();
}

function renderMetrics() {
  if (!state.data) {
    return;
  }
  const h = state.history.summary || {};
  if (h.total > 0) {
    el("detectedLabel").textContent = "历史命中";
    el("detectedMetric").textContent = `${(h.actions.block || 0) + (h.actions.flag || 0)}/${h.total}`;
    el("recallMetric").textContent = "persisted audit history";
    el("flagMetric").textContent = h.actions.flag || 0;
    el("blockMetric").textContent = h.actions.block || 0;
    el("latencyMetric").textContent = fmtMs(h.avg_latency_ms || 0);
    el("latencyScope").textContent = "history average";
    return;
  }
  const s = state.data.summary;
  el("detectedLabel").textContent = "攻击检出";
  el("detectedMetric").textContent = `${s.detected}/${s.attacks}`;
  el("recallMetric").textContent = `recall ${fmtPercent(s.recall)}`;
  el("flagMetric").textContent = s.actions.flag;
  el("blockMetric").textContent = s.actions.block;
  el("latencyMetric").textContent = fmtMs(s.avg_latency_ms);
  el("latencyScope").textContent = "baseline evaluation";
}

function renderFilters() {
  const select = el("categoryFilter");
  const current = select.value || "all";
  const categories = [...new Set(state.data.cases.map((item) => item.category))].sort();
  select.innerHTML = `<option value="all">全部类别</option>` + categories.map((cat) => (
    `<option value="${escapeHtml(cat)}">${escapeHtml(cat)}</option>`
  )).join("");
  select.value = categories.includes(current) ? current : "all";
}

function renderCaseList() {
  const filter = el("categoryFilter").value || "all";
  const list = el("caseList");
  const cases = state.data.cases.filter((item) => filter === "all" || item.category === filter);
  list.innerHTML = cases.map((item) => {
    const kind = item.should_block ? "attack" : "benign";
    return `
      <button class="case-item ${item.id === state.selectedCaseId ? "active" : ""}" data-case-id="${escapeHtml(item.id)}">
        <div class="case-line">
          <strong>${escapeHtml(item.id)}</strong>
          <span class="tag ${kind}">${escapeHtml(item.category)}</span>
        </div>
        <p class="case-desc">${escapeHtml(item.description)}</p>
      </button>
    `;
  }).join("");
  list.querySelectorAll("[data-case-id]").forEach((node) => {
    node.addEventListener("click", () => evaluateCase(node.dataset.caseId));
  });
}

function renderLayerStats() {
  if (!state.data) {
    return;
  }
  const historySummary = state.history.summary || {};
  const useHistory = historySummary.total > 0;
  const layers = useHistory ? historySummary.layers : state.data.summary.layers;
  el("layerScope").textContent = useHistory
    ? `历史请求统计：${historySummary.total} 条`
    : "基线样本统计";
  const container = el("layerStats");
  if (!Object.keys(layers || {}).length) {
    container.innerHTML = `<div class="empty-state">暂无历史防御层数据</div>`;
    return;
  }
  container.innerHTML = Object.entries(layers).map(([layer, counts]) => {
    const total = Math.max(1, counts.allow + counts.flag + counts.block);
    const allow = counts.allow / total * 100;
    const flag = counts.flag / total * 100;
    const block = counts.block / total * 100;
    return `
      <div class="layer-row">
        <strong>${escapeHtml(layer)}</strong>
        <div>
          <div class="stack-bar">
            <span class="bar-allow" style="width:${allow}%"></span>
            <span class="bar-flag" style="width:${flag}%"></span>
            <span class="bar-block" style="width:${block}%"></span>
          </div>
          <small>allow ${escapeHtml(counts.allow)} / flag ${escapeHtml(counts.flag)} / block ${escapeHtml(counts.block)}</small>
        </div>
      </div>
    `;
  }).join("");
}

function renderCoverage() {
  if (!state.data) {
    return;
  }
  const historySummary = state.history.summary || {};
  const categories = historySummary.total > 0 ? historySummary.categories : state.data.summary.categories;
  const container = el("coverageGrid");
  container.innerHTML = Object.entries(categories).map(([category, count]) => `
    <div class="coverage-item">
      <strong>${escapeHtml(category)}</strong>
      <span>${escapeHtml(count)} case${count > 1 ? "s" : ""}</span>
    </div>
  `).join("");
}

function renderDeepSeekStatus() {
  const status = state.data.deepseek || {};
  const node = el("deepseekStatus");
  node.className = `tag ${status.env_configured ? "benign" : "attack"}`;
  node.textContent = status.env_configured
    ? `DeepSeek env: ${status.model}`
    : "DeepSeek env: not set";
}

function renderSurfaceLab() {
  const surfaces = state.data.attack_surfaces || [];
  const grid = el("surfaceGrid");
  grid.innerHTML = surfaces.map((surface) => `
    <article class="surface-card">
      <div class="case-line">
        <h4>${escapeHtml(surface.title)}</h4>
        <span class="tag attack">${escapeHtml(surface.category)}</span>
      </div>
      <p>${escapeHtml(surface.description)}</p>
      <div class="surface-focus">
        ${surface.risk_focus.map((item) => `<span class="tag">${escapeHtml(item)}</span>`).join("")}
      </div>
      <div class="surface-actions">
        <button class="ghost-button" data-rerun-surface="${escapeHtml(surface.id)}">离线重跑</button>
        <button class="primary-button" data-deepseek-surface="${escapeHtml(surface.id)}">DeepSeek 红队</button>
      </div>
    </article>
  `).join("");
  grid.querySelectorAll("[data-rerun-surface]").forEach((node) => {
    node.addEventListener("click", () => rerunSurface(node.dataset.rerunSurface));
  });
  grid.querySelectorAll("[data-deepseek-surface]").forEach((node) => {
    node.addEventListener("click", () => runDeepSeekRedTeam(node.dataset.deepseekSurface));
  });

  const select = el("deepseekSurface");
  const current = select.value || (surfaces[0] && surfaces[0].id) || "";
  select.innerHTML = surfaces.map((surface) => (
    `<option value="${escapeHtml(surface.id)}">${escapeHtml(surface.title)}</option>`
  )).join("");
  select.value = surfaces.some((surface) => surface.id === current) ? current : ((surfaces[0] && surfaces[0].id) || "");
  syncPromptText();
}

function currentDeepSeekSurface() {
  const surface = (state.data.attack_surfaces || []).find((item) => item.id === el("deepseekSurface").value);
  return surface || null;
}

function syncPromptText(force = false) {
  const surface = currentDeepSeekSurface();
  const prompt = surface ? surface.prompt : "";
  const textarea = el("deepseekPrompt");
  textarea.placeholder = prompt || "留空则使用默认红队提示词";
  const surfaceChanged = surface && state.promptSurfaceId !== surface.id;
  if (force || !state.promptDirty || surfaceChanged || !textarea.value.trim()) {
    textarea.value = prompt;
    state.promptDirty = false;
    state.promptSurfaceId = surface ? surface.id : null;
  }
}

function shortTool(result) {
  const call = (result.case || {}).tool_call || {};
  const input = call.input || {};
  return `${call.name || "tool"} ${input.url || input.path || input.command || input.cmd || ""}`.trim();
}

function renderBatchMatrix() {
  const matrix = el("batchMatrix");
  if (!state.batchResults.length) {
    matrix.innerHTML = `<div class="empty-state">尚未生成批量攻击条目</div>`;
    return;
  }
  matrix.innerHTML = state.batchResults.map((result, index) => {
    const decision = result.decision || {};
    const redteam = result.redteam || {};
    const active = index === state.selectedBatchIndex ? "active" : "";
    const missed = isMissed(result);
    const canAnalyze = decision.action !== "block";
    const totalAction = displayAction(result);
    const totalTitle = missed
      ? "MISS: DeepSeek expected block/flag, but Guardian allowed"
      : (decision.reason || decision.action || "waiting");
    const subline = missed ? `漏拦截 · ${shortTool(result)}` : shortTool(result);
    return `
      <div class="batch-row ${active} ${missed ? "missed" : ""}" data-batch-index="${index}">
        <div class="batch-title">
          <strong>${escapeHtml(redteam.attack_goal || shortTool(result) || `attack-${index + 1}`)}</strong>
          <small>${escapeHtml(subline)}</small>
        </div>
        <span>${statusDot(totalAction, totalTitle)}</span>
        ${LAYER_ORDER.map((layer) => statusDot(layerAction(result, layer), layer)).join("")}
        <button class="ghost-button mini-action" data-analyze-index="${index}" ${canAnalyze ? "" : "disabled"}>分析漏拦截</button>
      </div>
    `;
  }).join("");
  matrix.querySelectorAll("[data-batch-index]").forEach((node) => {
    node.addEventListener("click", () => selectBatchItem(Number(node.dataset.batchIndex)));
  });
  matrix.querySelectorAll("[data-analyze-index]").forEach((node) => {
    node.addEventListener("click", (event) => {
      event.stopPropagation();
      analyzeMiss(Number(node.dataset.analyzeIndex));
    });
  });
}

function selectBatchItem(index) {
  const result = state.batchResults[index];
  if (!result) {
    return;
  }
  state.selectedBatchIndex = index;
  renderBatchMatrix();
  renderDecision(result);
  const analysis = state.batchAnalyses[index];
  el("deepseekOutput").textContent = prettyJson(result.redteam || {});
  el("deepseekDecision").textContent = prettyJson({
    expected_guardian_action: expectedAction(result) || null,
    missed_detection: isMissed(result),
    displayed_total_action: displayAction(result),
    action: result.decision.action,
    reason: result.decision.reason,
    verdicts: result.decision.verdicts,
    latency_ms: result.latency_ms,
    analysis: analysis || null,
  });
}

function renderDecision(result) {
  const caseData = result.case;
  const decision = result.decision;
  el("selectedTitle").textContent = `${caseData.id} / ${caseData.category}`;
  el("userRequest").textContent = caseData.user_request;
  el("toolCall").textContent = prettyJson(caseData.tool_call);
  const pill = el("decisionPill");
  pill.className = `decision-pill ${actionClass(decision.action)}`;
  pill.textContent = actionLabel(decision.action);
  el("verdictStrip").innerHTML = decision.verdicts.map((verdict) => `
    <div class="verdict-card">
      <div class="case-line">
        <strong>${escapeHtml(verdict.layer)}</strong>
        <span class="decision-pill ${actionClass(verdict.action)}">${actionLabel(verdict.action)}</span>
      </div>
      <p>${escapeHtml(verdict.reason || "all checks passed")}</p>
      <small>confidence ${escapeHtml(Number(verdict.confidence).toFixed(2))}</small>
    </div>
  `).join("");
}

async function evaluateCase(caseId) {
  state.selectedCaseId = caseId;
  renderCaseList();
  const result = await api("/api/evaluate", {
    method: "POST",
    body: JSON.stringify({ case_id: caseId }),
  });
  renderDecision(result);
  await loadHistory();
}

async function runAll() {
  state.data = await api("/api/run-all", { method: "POST", body: "{}" });
  renderAll();
  addAudit("benchmark", "allow", "全量评测完成", `${state.data.summary.detected}/${state.data.summary.attacks} attacks detected`);
}

async function rerunSurface(surfaceId) {
  try {
    const result = await api("/api/rerun-surface", {
      method: "POST",
      body: JSON.stringify({ surface_id: surfaceId }),
    });
    renderDecision(result);
    await loadHistory();
  } catch (err) {
    addAudit("surface-lab", "block", "攻击面重跑失败", err.message);
  }
}

async function runDeepSeekRedTeam(surfaceId) {
  const selectedSurface = surfaceId || el("deepseekSurface").value;
  el("deepseekSurface").value = selectedSurface;
  if (surfaceId) {
    syncPromptText(true);
  }
  el("deepseekOutput").textContent = "DeepSeek 正在批量生成红队样本...";
  el("deepseekDecision").textContent = "等待 Guardian 批量审计...";
  el("deepseekRunBtn").disabled = true;
  try {
    const batch = await api("/api/deepseek-redteam-batch", {
      method: "POST",
      body: JSON.stringify({
        surface_id: selectedSurface,
        api_key: el("deepseekKey").value,
        use_intent_judge: el("deepseekIntent").checked,
        count: Number(el("deepseekCount").value || 1),
        prompt: el("deepseekPrompt").value,
      }),
    });
    state.batchResults = batch.results || [];
    state.batchAnalyses = {};
    state.selectedBatchIndex = state.batchResults.length ? 0 : null;
    renderBatchMatrix();
    if (state.batchResults.length) {
      selectBatchItem(0);
    }
    await loadHistory();
  } catch (err) {
    el("deepseekDecision").textContent = err.message;
    addAudit("deepseek", "block", "DeepSeek 红队调用失败", err.message);
  } finally {
    el("deepseekRunBtn").disabled = false;
  }
}

async function analyzeMiss(index) {
  const result = state.batchResults[index];
  if (!result) {
    return;
  }
  el("deepseekDecision").textContent = "DeepSeek 正在分析漏拦截原因并生成受限防御规则...";
  try {
    const analysis = await api("/api/analyze-miss", {
      method: "POST",
      body: JSON.stringify({
        surface_id: (result.surface || {}).id,
        result,
        api_key: el("deepseekKey").value,
        apply_rules: true,
      }),
    });
    state.batchAnalyses[index] = analysis;
    if (analysis.recheck_result) {
      state.batchResults[index] = analysis.recheck_result;
    }
    renderBatchMatrix();
    selectBatchItem(index);
    addAudit("adaptive-rule", "flag", "DeepSeek 已分析漏拦截并同步自适应规则", `${(analysis.applied_rules || []).length} rules`);
  } catch (err) {
    addAudit("adaptive-rule", "block", "DeepSeek 漏拦截分析失败", err.message);
  }
}

function renderAll() {
  renderMetrics();
  renderFilters();
  renderCaseList();
  renderLayerStats();
  renderCoverage();
  renderDeepSeekStatus();
  renderSurfaceLab();
  renderBatchMatrix();
  const selected = state.data.results.find((item) => item.case.id === state.selectedCaseId);
  if (selected) {
    renderDecision(selected);
  }
}

async function evaluateCustom() {
  let input;
  try {
    input = JSON.parse(el("customInput").value);
  } catch (err) {
    addAudit("custom", "block", "工具参数 JSON 无法解析", err.message);
    return;
  }
  const taint = el("customTaint").value;
  const result = await api("/api/custom", {
    method: "POST",
    body: JSON.stringify({
      user_request: el("customRequest").value,
      tool_name: el("customTool").value,
      input,
      tainted_sources: taint ? [taint] : [],
    }),
  });
  renderDecision(result);
  await loadHistory();
}

function addAudit(title, action, reason, meta) {
  const entry = {
    title,
    action,
    reason,
    meta,
    time: new Date().toLocaleTimeString(),
  };
  state.audit.unshift(entry);
  state.audit = state.audit.slice(0, 18);
  renderAudit();
}

function renderAudit() {
  const historyEntries = (state.history.entries || []).map((entry) => ({
    title: entry.surface_title || entry.case_id || entry.mode,
    action: entry.action,
    reason: entry.reason,
    meta: `${entry.mode} · ${entry.tool_name || "tool"} · ${fmtMs(entry.latency_ms || 0)}`,
    time: new Date(entry.created_at).toLocaleString(),
    request: entry.user_request,
  }));
  const entries = [...state.audit, ...historyEntries].slice(0, 80);
  const total = (state.history.summary || {}).total || 0;
  el("historySummary").textContent = total > 0
    ? `已持久记录 ${total} 条请求`
    : "暂无持久历史，请运行一次攻击或评估";
  if (!entries.length) {
    el("auditLog").innerHTML = `<div class="empty-state">暂无审计记录</div>`;
    return;
  }
  el("auditLog").innerHTML = entries.map((item) => `
    <div class="audit-entry">
      <div class="case-line">
        <strong>${escapeHtml(item.title)}</strong>
        <span class="decision-pill ${actionClass(item.action)}">${actionLabel(item.action)}</span>
      </div>
      <span>${escapeHtml(item.reason)}</span>
      <small>${escapeHtml(item.time)} · ${escapeHtml(item.meta)}</small>
      ${item.request ? `<p>${escapeHtml(item.request)}</p>` : ""}
    </div>
  `).join("");
}

function bindEvents() {
  el("categoryFilter").addEventListener("change", renderCaseList);
  el("refreshBtn").addEventListener("click", refreshAll);
  el("runAllBtn").addEventListener("click", runAll);
  el("customRunBtn").addEventListener("click", evaluateCustom);
  el("deepseekRunBtn").addEventListener("click", () => runDeepSeekRedTeam());
  el("deepseekSurface").addEventListener("change", () => syncPromptText(true));
  el("deepseekPrompt").addEventListener("input", () => {
    state.promptDirty = true;
    state.promptSurfaceId = el("deepseekSurface").value;
  });
  el("clearAuditBtn").addEventListener("click", () => {
    state.audit = [];
    api("/api/history/clear", { method: "POST", body: "{}" })
      .then((history) => {
        state.history = history;
        renderMetrics();
        renderLayerStats();
        renderCoverage();
        renderAudit();
      })
      .catch((err) => addAudit("history", "block", "清空历史失败", err.message));
  });
}

bindEvents();
refreshAll().catch((err) => {
  addAudit("startup", "block", "Dashboard API 初始化失败", err.message);
});
