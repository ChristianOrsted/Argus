const state = {
  data: null,
  selectedCaseId: null,
  audit: [],
  busy: false,
};

const el = (id) => document.getElementById(id);

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

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${text}`);
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

function renderMetrics() {
  const s = state.data.summary;
  el("detectedMetric").textContent = `${s.detected}/${s.attacks}`;
  el("recallMetric").textContent = `recall ${fmtPercent(s.recall)}`;
  el("flagMetric").textContent = s.actions.flag;
  el("blockMetric").textContent = s.actions.block;
  el("latencyMetric").textContent = fmtMs(s.avg_latency_ms);
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
  const layers = state.data.summary.layers;
  const container = el("layerStats");
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
  const categories = state.data.summary.categories;
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
  addAudit(`${caseData.id}`, decision.action, decision.reason, `${fmtMs(result.latency_ms)} latency`);
}

async function evaluateCase(caseId) {
  state.selectedCaseId = caseId;
  renderCaseList();
  const result = await api("/api/evaluate", {
    method: "POST",
    body: JSON.stringify({ case_id: caseId }),
  });
  renderDecision(result);
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
    addAudit(result.surface.title, result.decision.action, "独立攻击面离线重跑完成", result.mode);
  } catch (err) {
    addAudit("surface-lab", "block", "攻击面重跑失败", err.message);
  }
}

async function runDeepSeekRedTeam(surfaceId) {
  const selectedSurface = surfaceId || el("deepseekSurface").value;
  el("deepseekSurface").value = selectedSurface;
  el("deepseekOutput").textContent = "DeepSeek 正在生成红队样本...";
  el("deepseekDecision").textContent = "等待 Guardian 审计...";
  el("deepseekRunBtn").disabled = true;
  try {
    const result = await api("/api/deepseek-redteam", {
      method: "POST",
      body: JSON.stringify({
        surface_id: selectedSurface,
        api_key: el("deepseekKey").value,
        use_intent_judge: el("deepseekIntent").checked,
      }),
    });
    el("deepseekOutput").textContent = prettyJson(result.redteam);
    el("deepseekDecision").textContent = prettyJson({
      action: result.decision.action,
      reason: result.decision.reason,
      verdicts: result.decision.verdicts,
      latency_ms: result.latency_ms,
      intent_judge_enabled: result.intent_judge_enabled,
    });
    renderDecision(result);
    addAudit(result.surface.title, result.decision.action, "DeepSeek 在线红队完成", result.redteam.danger_explanation);
  } catch (err) {
    el("deepseekDecision").textContent = err.message;
    addAudit("deepseek", "block", "DeepSeek 红队调用失败", err.message);
  } finally {
    el("deepseekRunBtn").disabled = false;
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
  el("auditLog").innerHTML = state.audit.map((item) => `
    <div class="audit-entry">
      <div class="case-line">
        <strong>${escapeHtml(item.title)}</strong>
        <span class="decision-pill ${actionClass(item.action)}">${actionLabel(item.action)}</span>
      </div>
      <span>${escapeHtml(item.reason)}</span>
      <small>${escapeHtml(item.time)} · ${escapeHtml(item.meta)}</small>
    </div>
  `).join("");
}

function bindEvents() {
  el("categoryFilter").addEventListener("change", renderCaseList);
  el("refreshBtn").addEventListener("click", loadSummary);
  el("runAllBtn").addEventListener("click", runAll);
  el("customRunBtn").addEventListener("click", evaluateCustom);
  el("deepseekRunBtn").addEventListener("click", () => runDeepSeekRedTeam());
  el("clearAuditBtn").addEventListener("click", () => {
    state.audit = [];
    renderAudit();
  });
}

bindEvents();
loadSummary().catch((err) => {
  addAudit("startup", "block", "Dashboard API 初始化失败", err.message);
});
