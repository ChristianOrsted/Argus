// 独立页面共用的应用外壳：侧边栏不再指向页内锚点，而是实际的静态页面。
const dashboardPages = [
  { id: "overview", href: "/", label: "总览", eyebrow: "LLM Agent Security Prototype", title: "智能体行为监督原型系统" },
  { id: "attack-lab", href: "/attack-lab.html", label: "攻击面实验台", eyebrow: "Attack Surface Lab", title: "攻击面实验与在线红队" },
  { id: "samples", href: "/samples.html", label: "红队样本", eyebrow: "Red Team Corpus", title: "红队样本与决策回放" },
  { id: "defense", href: "/defense.html", label: "防御层", eyebrow: "Defense Analytics", title: "防御层与攻击覆盖" },
  { id: "rules", href: "/rules.html", label: "规则管理", eyebrow: "Adaptive Rules", title: "自适应规则管理" },
  { id: "evaluation", href: "/evaluation.html", label: "演示与评估", eyebrow: "Evaluation Lab", title: "验收演示与自定义评估" },
  { id: "audit", href: "/audit.html", label: "审计流", eyebrow: "Audit Stream", title: "交互审计记录" },
];

const currentPage = document.body.dataset.page || "overview";
const page = dashboardPages.find((item) => item.id === currentPage) || dashboardPages[0];
const escapeShellHtml = (value) => String(value).replace(/[&<>\"']/g, (char) => ({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  "\"": "&quot;",
  "'": "&#39;",
}[char]));

const sidebar = document.querySelector(".sidebar");
const workspace = document.querySelector(".workspace");

if (sidebar && workspace) {
  sidebar.innerHTML = `
    <a class="brand" href="/" aria-label="Argus 总览">
      <div class="brand-mark">A</div>
      <div>
        <h1>Argus</h1>
        <p>Agent Behavior Guardian</p>
      </div>
    </a>
    <nav class="nav-list" aria-label="Dashboard pages">
      ${dashboardPages.map((item) => `
        <a href="${item.href}" class="nav-item ${item.id === page.id ? "active" : ""}" ${item.id === page.id ? "aria-current=\"page\"" : ""}>${escapeShellHtml(item.label)}</a>
      `).join("")}
    </nav>
    <div class="side-note">
      <span class="status-dot"></span>
      <span>本地 Guardian API 已连接</span>
    </div>
  `;
  workspace.insertAdjacentHTML("afterbegin", `
    <header class="topbar">
      <div>
        <p class="eyebrow">${escapeShellHtml(page.eyebrow)}</p>
        <h2>${escapeShellHtml(page.title)}</h2>
      </div>
      <div class="top-actions">
        <button id="refreshBtn" class="icon-button" title="刷新本页数据" aria-label="刷新本页数据"><span class="icon-refresh"></span></button>
        <button id="runAllBtn" class="primary-button">运行全量评测</button>
      </div>
    </header>
  `);
  document.title = `${page.label} · Argus Guardian`;
}
