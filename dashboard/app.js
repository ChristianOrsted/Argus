// Dashboard 前端状态：所有页面渲染都从这里取数据，避免多个区域各自维护副本。
// `data` 是离线基准和攻击面配置；`history` 是 SQLite 历史流；`batchResults`
// 是 DeepSeek 批量红队生成后逐条审计的结果。
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

// 四层 Guardian 的展示顺序，对应页面矩阵中的 1 / 2 / 3 / 4。
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
  // DeepSeek 红队样本自带 expected_guardian_action。若样本期望拦截但 Guardian 放行，
  // 页面把“总”状态标为红色漏拦截，方便继续调用 DeepSeek 分析并同步规则。
  return isExpectedBlock(result) && ((result.decision || {}).action === "allow");
}

function displayAction(result) {
  return isMissed(result) ? "block" : ((result.decision || {}).action || "neutral");
}

function statusDot(action, title = "") {
  return `<span class="status-dot-mini ${actionClass(action)}" title="${escapeHtml(title || actionLabel(action))}"></span>`;
}

async function api(path, options = {}) {
  // 统一 API 调用和错误解包；后端返回 JSON error 时，前端直接显示可读错误。
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
  syncModeOptions();
  syncPromptText();
}

function currentDeepSeekSurface() {
  const surface = (state.data.attack_surfaces || []).find((item) => item.id === el("deepseekSurface").value);
  return surface || null;
}

function currentDeepSeekMode() {
  const surface = currentDeepSeekSurface();
  const modes = (surface && surface.prompt_modes) || [];
  const selected = el("deepseekMode").value;
  return modes.find((mode) => mode.id === selected) || modes[0] || null;
}

function syncModeOptions(force = false) {
  const surface = currentDeepSeekSurface();
  const modes = (surface && surface.prompt_modes) || [];
  const select = el("deepseekMode");
  const current = force ? "" : select.value;
  select.innerHTML = modes.map((mode) => (
    `<option value="${escapeHtml(mode.id)}">${escapeHtml(mode.title)}</option>`
  )).join("");
  select.disabled = modes.length === 0;
  select.value = modes.some((mode) => mode.id === current) ? current : ((modes[0] && modes[0].id) || "");
}

function syncPromptText(force = false) {
  const surface = currentDeepSeekSurface();
  const mode = currentDeepSeekMode();
  const prompt = mode ? mode.prompt : (surface ? surface.prompt : "");
  const textarea = el("deepseekPrompt");
  textarea.placeholder = prompt || "留空则使用默认红队提示词";
  const promptKey = surface ? `${surface.id}:${mode ? mode.id : "default"}` : null;
  const promptTemplateChanged = promptKey && state.promptSurfaceId !== promptKey;
  if (force || !state.promptDirty || promptTemplateChanged || !textarea.value.trim()) {
    textarea.value = prompt;
    state.promptDirty = false;
    state.promptSurfaceId = promptKey;
  }
}

function shortTool(result) {
  const call = (result.case || {}).tool_call || {};
  const input = call.input || {};
  return `${call.name || "tool"} ${input.url || input.path || input.command || input.cmd || ""}`.trim();
}

function tagList(items, fallback = "未提供") {
  const values = Array.isArray(items) ? items.filter((item) => String(item || "").trim()) : [];
  if (!values.length) {
    return `<span class="tag">${escapeHtml(fallback)}</span>`;
  }
  return values.map((item) => `<span class="tag">${escapeHtml(item)}</span>`).join("");
}

function bulletList(items, fallback = "未提供") {
  const values = Array.isArray(items) ? items.filter((item) => String(item || "").trim()) : [];
  if (!values.length) {
    return `<p class="muted-text">${escapeHtml(fallback)}</p>`;
  }
  return `<ul class="detail-list">${values.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function jsonDetails(title, value) {
  return `
    <details class="json-details">
      <summary>${escapeHtml(title)}</summary>
      <pre class="mini-code">${escapeHtml(prettyJson(value || {}))}</pre>
    </details>
  `;
}

function renderToolDetail(toolCall) {
  const call = toolCall || {};
  return `
    <div class="tool-summary">
      <span class="tag attack">${escapeHtml(call.name || "unknown_tool")}</span>
      <pre class="mini-code">${escapeHtml(prettyJson(call.input || {}))}</pre>
    </div>
  `;
}

function redteamDetailHtml(result, { compact = false } = {}) {
  const redteam = result.redteam || {};
  const caseData = result.case || {};
  const toolCall = redteam.tool_call || caseData.tool_call || {};
  const riskPoints = redteam.risk_points || [];
  const head = `
    <div class="detail-block">
      <div class="detail-heading">
        <span class="tag attack">${escapeHtml(redteam.attack_surface || (result.surface || {}).id || caseData.category || "deepseek")}</span>
        <span class="decision-pill ${actionClass(expectedAction(result) || "block")}">${escapeHtml(expectedAction(result) || "expected")}</span>
      </div>
      <h4>${escapeHtml(redteam.attack_goal || caseData.description || "DeepSeek 生成的红队样本")}</h4>
      <p>${escapeHtml(redteam.danger_explanation || "模型未返回 danger_explanation，可查看原始 JSON。")}</p>
      ${compact ? `<button class="ghost-button mini-action summary-open-btn" data-open-selected-detail>查看完整攻击与审计结果</button>` : ""}
    </div>
  `;
  if (compact) {
    return `
      ${head}
      <div class="detail-block">
        <h4>用户请求</h4>
        <p>${escapeHtml(redteam.user_request || caseData.user_request || "未提供")}</p>
      </div>
      <div class="detail-block">
        <h4>关键风险点</h4>
        ${bulletList(riskPoints.slice(0, 4))}
      </div>
    `;
  }
  return `
    ${head}
    <div class="detail-block">
      <h4>用户请求</h4>
      <p>${escapeHtml(redteam.user_request || caseData.user_request || "未提供")}</p>
    </div>
    <div class="detail-block">
      <h4>工具调用</h4>
      ${renderToolDetail(toolCall)}
    </div>
    <div class="detail-two-col">
      <div class="detail-block">
        <h4>污点来源</h4>
        <div class="inline-tags">${tagList(redteam.tainted_sources || caseData.tainted_sources)}</div>
      </div>
      <div class="detail-block">
        <h4>风险点</h4>
        ${bulletList(redteam.risk_points)}
      </div>
    </div>
    ${jsonDetails("查看 DeepSeek 原始 JSON", redteam)}
  `;
}

function renderRedteamDetail(result) {
  const node = el("deepseekOutput");
  node.className = "structured-detail attack-summary";
  node.innerHTML = redteamDetailHtml(result, { compact: true });
  node.querySelectorAll("[data-open-selected-detail]").forEach((button) => {
    button.addEventListener("click", () => openBatchDetail(state.selectedBatchIndex));
  });
}

function guardianDetailHtml(result, analysisPayload, index) {
  const decision = result.decision || {};
  const verdicts = decision.verdicts || [];
  const analysis = (analysisPayload || {}).analysis || null;
  const appliedRules = (analysisPayload || {}).applied_rules || [];
  const recheck = (analysisPayload || {}).recheck_result || null;
  const missed = isMissed(result);
  const canAnalyze = decision.action !== "block";
  return `
    <div class="detail-block ${missed ? "missed" : ""}">
      <div class="detail-heading">
        <span class="decision-pill ${actionClass(displayAction(result))}">总状态 ${actionLabel(displayAction(result))}</span>
        <span class="tag">${escapeHtml(expectedAction(result) ? `期望 ${expectedAction(result).toUpperCase()}` : "无期望动作")}</span>
      </div>
      <h4>${escapeHtml(missed ? "发现漏拦截候选" : (decision.action === "block" ? "Guardian 已阻断" : "Guardian 未阻断"))}</h4>
      <p>${escapeHtml(decision.reason || "all checks passed")}</p>
      <div class="analysis-actions">
        ${canAnalyze ? `<button class="primary-button" data-analyze-selected="${index}">调用 DeepSeek 分析并优化规则</button>` : `<span class="tag benign">当前条目已阻断</span>`}
      </div>
    </div>
    <div class="layer-detail-grid">
      ${LAYER_ORDER.map((layer) => {
        const verdict = verdicts.find((item) => item.layer === layer) || { layer, action: "neutral", reason: "未返回该层判定", confidence: 0 };
        return `
          <div class="detail-block layer-detail">
            <div class="detail-heading">
              <h4>${escapeHtml(layer)}</h4>
              <span class="decision-pill ${actionClass(verdict.action)}">${actionLabel(verdict.action)}</span>
            </div>
            <p>${escapeHtml(verdict.reason || "all checks passed")}</p>
            <small>confidence ${escapeHtml(Number(verdict.confidence || 0).toFixed(2))}</small>
          </div>
        `;
      }).join("")}
    </div>
    ${analysis ? `
      <div class="detail-block analysis-block">
        <h4>DeepSeek 漏拦截分析</h4>
        <p><strong>原因：</strong>${escapeHtml(analysis.missed_reason || "未提供")}</p>
        <p><strong>建议：</strong>${escapeHtml(analysis.recommended_patch || "未提供")}</p>
        <div class="inline-tags">${tagList(appliedRules.map((rule) => rule.description || rule.id || "adaptive_rule"), "未写入规则")}</div>
        ${recheck ? `<p class="muted-text">重评估结果：${escapeHtml((recheck.decision || {}).action || "unknown")}</p>` : ""}
      </div>
      ${jsonDetails("查看自适应规则 JSON", analysis)}
    ` : ""}
    ${jsonDetails("查看 Guardian 原始 JSON", {
      expected_guardian_action: expectedAction(result) || null,
      missed_detection: missed,
      displayed_total_action: displayAction(result),
      action: decision.action,
      reason: decision.reason,
      verdicts,
      latency_ms: result.latency_ms,
    })}
  `;
}

function attachAnalysisButtons(node) {
  node.querySelectorAll("[data-analyze-selected]").forEach((button) => {
    button.addEventListener("click", () => analyzeMiss(Number(button.dataset.analyzeSelected)));
  });
}

function renderGuardianDetail(result, analysisPayload, index, targetId = "modalGuardianDetail") {
  const node = el(targetId);
  if (!node) {
    return;
  }
  node.className = "structured-detail";
  node.innerHTML = guardianDetailHtml(result, analysisPayload, index);
  attachAnalysisButtons(node);
}

function openBatchDetail(index) {
  const result = state.batchResults[index];
  if (!result) {
    return;
  }
  selectBatchItem(index);
  const redteam = result.redteam || {};
  const caseData = result.case || {};
  const analysis = state.batchAnalyses[index];
  el("modalTitle").textContent = redteam.attack_goal || caseData.description || `DeepSeek 条目 ${index + 1}`;
  el("modalStatusRow").innerHTML = `
    <span class="decision-pill ${actionClass(displayAction(result))}">总 ${actionLabel(displayAction(result))}</span>
    ${LAYER_ORDER.map((layer, layerIndex) => `
      <span class="modal-layer-chip">
        ${layerIndex + 1}. ${escapeHtml(layer)}
        ${statusDot(layerAction(result, layer), layer)}
      </span>
    `).join("")}
  `;
  el("modalAttackDetail").innerHTML = redteamDetailHtml(result, { compact: false });
  renderGuardianDetail(result, analysis, index, "modalGuardianDetail");
  el("batchDetailModal").hidden = false;
}

function closeBatchDetail() {
  el("batchDetailModal").hidden = true;
}

function renderBatchMatrix() {
  // 批量矩阵是演示核心：左侧是攻击条目信息，右侧依次是总状态和四层状态。
  // 点击行会把 DeepSeek 攻击说明、Guardian Verdict 和漏拦截闭环展开到结构化详情区。
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
        <button class="ghost-button mini-action" data-open-index="${index}">查看详情</button>
      </div>
    `;
  }).join("");
  matrix.querySelectorAll("[data-batch-index]").forEach((node) => {
    node.addEventListener("click", () => openBatchDetail(Number(node.dataset.batchIndex)));
  });
  matrix.querySelectorAll("[data-open-index]").forEach((node) => {
    node.addEventListener("click", (event) => {
      event.stopPropagation();
      openBatchDetail(Number(node.dataset.openIndex));
    });
  });
}

function selectBatchItem(index) {
  // 选中某个批量攻击条目后，同步刷新右侧详情和下方通用审计面板。
  const result = state.batchResults[index];
  if (!result) {
    return;
  }
  state.selectedBatchIndex = index;
  renderBatchMatrix();
  renderDecision(result);
  renderRedteamDetail(result);
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
  // 网页端在线红队入口：按攻击面和提示词调用后端批量接口。
  // 后端只把生成出的 ToolCall 交给 Guardian 审计，不会真实执行危险工具。
  const selectedSurface = surfaceId || el("deepseekSurface").value;
  el("deepseekSurface").value = selectedSurface;
  if (surfaceId) {
    syncModeOptions(true);
    syncPromptText(true);
  }
  el("deepseekOutput").className = "structured-detail empty-state";
  el("deepseekOutput").textContent = "DeepSeek 正在批量生成红队样本...";
  closeBatchDetail();
  el("deepseekRunBtn").disabled = true;
  try {
    const batch = await api("/api/deepseek-redteam-batch", {
      method: "POST",
      body: JSON.stringify({
        surface_id: selectedSurface,
        attack_mode: el("deepseekMode").value,
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
    el("deepseekOutput").className = "structured-detail";
    el("deepseekOutput").innerHTML = `
      <div class="detail-block missed">
        <h4>DeepSeek 红队调用失败</h4>
        <p>${escapeHtml(err.message)}</p>
      </div>
    `;
    addAudit("deepseek", "block", "DeepSeek 红队调用失败", err.message);
  } finally {
    el("deepseekRunBtn").disabled = false;
  }
}

async function analyzeMiss(index) {
  // 漏拦截闭环：把未被阻断的条目交给 DeepSeek 分析，生成受限自适应规则后重评估。
  const result = state.batchResults[index];
  if (!result) {
    return;
  }
  const modalOpen = !el("batchDetailModal").hidden;
  if (modalOpen) {
    el("modalGuardianDetail").className = "structured-detail empty-state";
    el("modalGuardianDetail").textContent = "DeepSeek 正在分析漏拦截原因并生成受限防御规则...";
  }
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
    if (modalOpen) {
      openBatchDetail(index);
    }
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
  el("deepseekSurface").addEventListener("change", () => {
    syncModeOptions(true);
    syncPromptText(true);
  });
  el("deepseekMode").addEventListener("change", () => syncPromptText(true));
  el("deepseekPrompt").addEventListener("input", () => {
    state.promptDirty = true;
    const surface = el("deepseekSurface").value;
    const mode = el("deepseekMode").value || "default";
    state.promptSurfaceId = `${surface}:${mode}`;
  });
  el("modalCloseBtn").addEventListener("click", closeBatchDetail);
  el("batchDetailModal").addEventListener("click", (event) => {
    if (event.target === el("batchDetailModal")) {
      closeBatchDetail();
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !el("batchDetailModal").hidden) {
      closeBatchDetail();
    }
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
