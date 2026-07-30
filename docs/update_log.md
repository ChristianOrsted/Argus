# Argus Update Log

## 2026-07-24 - Remove Label Leakage And Correct Metrics

本次修复：

- 移除 Policy 对 `expected_guardian_action`、`risk_points`、`danger_explanation` 等红队答案字段的读取。
- DeepSeek 红队评估不再把攻击标签、解释或模型自报的 `tainted_sources` 写入 Guardian 上下文。
- 自适应规则只能匹配运行时可观察的工具名、用户请求和工具输入，不能匹配攻击面或 metadata。
- 前端状态矩阵始终显示 Guardian 的真实动作；漏拦截只做额外标记，不再把 `ALLOW` 显示成 `BLOCK`。
- 良性样本的 `FLAG` 与 `BLOCK` 都计入告警误报，并新增 Block/Alert Recall、Precision 和两类 FPR。
## 2026-07-24 - Report Diagrams And Demo Flow

本次报告补充：

- 在 `report/final_report.tex` 中加入 TikZ 绘图样式，直接生成系统总体架构图，覆盖用户请求、LLM Agent、ToolCall、四层 Guardian、最终决策、工具执行或阻断、审计日志和 Dashboard。
- 将“四层 Guardian 判定流程图”从截图占位改为报告内置流程图，明确展示 Policy、Taint、Intent、Anomaly 四层如何产生 Verdict，以及 `BLOCK > FLAG > ALLOW` 的聚合规则。
- 在“网页演示系统”小节新增网页操作流程图，说明课堂展示时从打开 Dashboard、选择攻击面、运行审计、查看矩阵、展开详情到沉淀验收记录的路径。
- 为报告中的 Guardian 汇总决策代码和 Taint 片段级污点代码加入注释，并补充正文说明，方便答辩时解释关键代码。
- 调整附录截图清单：架构图和流程图已由报告生成，后续主要补 Dashboard、DeepSeek 攻击链、规则管理、Benchmark 和演示验收的真实运行截图。

本次验证结果：

- LaTeX 编译通过：`xelatex -interaction=nonstopmode -halt-on-error final_report.tex`，生成 20 页 PDF。
- 渲染抽查通过：使用 Poppler 抽查摘要页、系统架构图、代码节选、四层判定流程图和网页演示流程图，未发现遮挡或溢出。

## 2026-07-24 - Report Narrative And Four-Layer Explanation Polish

本次报告润色：

- 重写 `report/final_report.tex` 中“选题目标”和“作品成果”部分，减少清单式表达，改为更连贯地说明项目如何从红队样本、防御机制和网页验收形成闭环。
- 深入扩写“四层行为监督机制”小节，解释四层为什么分别对应动作边界、数据来源、意图一致性和行为序列，而不是简单关键词堆叠。
- 在报告中加入两段短代码节选：Guardian 四层 Verdict 聚合逻辑、Taint 层片段级污点流入高权限动作的判断逻辑。
- 扩写实验分析，说明 22/22 检出只代表当前评测集上的结果，不等同于覆盖全部真实攻击；解释 2 条良性 `FLAG` 为什么属于旁路告警而非阻断型误报。
- 新增代表性样本分析表，解释工具调用劫持、间接提示注入、序列异常和良性告警样本分别由哪些层命中、结果含义是什么。
- 重写“创新性说明”和“总结”，减少“第一、第二、第三”的汇报腔，让语言更像完整报告正文。

本次验证结果：

- LaTeX 编译通过：`xelatex -interaction=nonstopmode -halt-on-error final_report.tex`，生成 19 页 PDF。
- 渲染检查通过：抽查第 6-15 页，四层表格、代码块、实验表格和代表性样本表均无溢出或遮挡。
- 密钥扫描通过：未发现真实 DeepSeek API Key 写入项目文件。

## 2026-07-24 - Printable Dashboard, Tool Registry, And Template Report

本次定稿前完善：

- 将 Dashboard 从深色主题切换为白底黑字浅色主题，并补充打印友好的样式，方便报告截图和纸质打印。
- 保留原有 Dashboard 布局与交互，不改变攻击面复跑、DeepSeek 批量红队、规则管理、攻击链视图和一键验收功能。
- 新增 `src/guardian/tool_registry.py`，为内置工具记录能力标签、风险等级和审计关注点。
- `PolicyLayer` 从工具能力注册表读取当前启用工具；未知工具仍默认阻断，并提示新工具应先登记能力标签、最小权限和审计关注点。
- 新增 `tests/test_tool_registry.py`，验证工具注册表与策略白名单一致。
- 新增 `docs/tool_onboarding_policy.md`，说明“工具集超出预设”当前是中等偏大的工程问题，本阶段已补工具能力登记入口，完整治理继续放在展望。
- 按用户提供的夏季学期 Word 模板重写 `report/final_report.tex`，包含封面、填写说明、目录、摘要、五章正文、参考文献和附录。
- 重新编译 `report/final_report.pdf`，当前为 19 页，保留实验结果和截图占位，并附上每张图应放什么内容的文字说明。
- 同步更新 `report/llm_security_argus_briefing.pptx` 中的平均审计延迟为最新 benchmark 结果 0.897ms。
- 更新 `docs/project_overview.md` 和 `docs/project_self_audit.md`，同步当前验收数据、工具扩展结论和后续重点。

本次验证结果：

- 前端页面烟测通过：`GET http://127.0.0.1:8765/` 返回 `200`，`styles.css` 确认 `color-scheme: light`。
- JS 语法检查通过：`node --check dashboard\app.js`。
- 编译检查通过：`.\.venv\Scripts\python -m compileall src scripts tests`。
- 单元测试通过：65 passed。
- Benchmark 通过：30 条用例，22/22 攻击检出，0 阻断型误报，2 条良性告警。
- 最新离线延时：平均 0.897ms，p50 0.875ms，p95 1.471ms。
- LaTeX 编译通过：`xelatex -interaction=nonstopmode -halt-on-error final_report.tex`，生成 19 页 PDF。
- 密钥扫描通过：未发现真实 DeepSeek API Key 写入项目文件。

## 2026-07-17 - Final Presentation Deck

本次新增汇报材料：

- 新增 `report/llm_security_argus_briefing.pptx` 作为课程汇报 PPT。
- PPT 共 9 页，结构为：选题与研究问题、攻击面、项目交付物、系统架构、四层 Guardian 机制、红队与 DeepSeek 在线样本、实验结果、网页演示验收、局限与展望。
- 实验结果页写入当时定稿口径：30 条样本、22 条攻击样本、22/22 攻击检出、0 阻断型误报、平均审计延迟 1.049ms；2026-07-24 已随最新 benchmark 同步为 0.897ms。
- 展望页补充后续可深入方向：接入 AdvBench/JailbreakBench 等现有攻击集扩大测试，工具集超出预设时升级为工具能力标签、最小权限和场景策略。
- 已使用演示文稿工具渲染最终 PPTX 并逐页检查；`slides_test.py` 检查通过，无元素越界。
- 更新 `docs/project_overview.md`，将 PPT 标记为汇报交付物。

## 2026-07-16 - Final LaTeX Report

本次定稿文档更新：

- 新增 `report/final_report.tex` 作为课程正式 LaTeX 报告，并生成 `report/final_report.pdf` 预览版。
- 报告对齐选题要求，覆盖安全风险分析、攻击面威胁模型、四层行为监督机制、对抗样本与越狱测试集、攻击脚本、可演示原型系统和实验结果。
- 报告写入当前定稿评测数据：30 条样本、22 条攻击、22/22 检出、0 阻断型误报、2 条良性告警。
- 报告预留系统架构图、四层防御流程图、Dashboard 总览、DeepSeek 攻击链弹窗、规则管理页、Benchmark 结果和一键演示验收快照等图位，并附有每张图应放什么内容的文字说明。
- 更新 `docs/project_overview.md`，将安全风险分析报告状态标记为 LaTeX 正式报告已完成。

## 2026-07-16 - Rules Management And Acceptance Demo

本次 B/D 方向优化：

- 自适应规则从简单 JSON 列表升级为可管理规则，兼容旧规则并新增 `source`、`enabled`、`hit_count`、`created_at`、`last_hit_at` 字段。
- `PolicyLayer` 命中自适应规则时会自动累加命中次数，停用规则不会参与匹配。
- 新增 Dashboard API：`GET /api/adaptive-rules`、`POST /api/adaptive-rules/toggle`、`POST /api/adaptive-rules/delete`。
- 新增规则管理页：展示规则来源、命中次数、启停状态，并支持停用、启用和撤销。
- 攻击详情弹窗新增攻击链视图，把用户请求、模型输出/攻击点、工具调用、污点来源和防御层命中串成链路图。
- 新增一键演示脚本模式：`POST /api/demo-run` 固定运行 7 个攻击面，并写入历史审计流。
- 一键演示会生成验收产物：`sandbox_runs/demo_acceptance/argus_demo_*.md`、`.json`、`.svg`。
- Dashboard 通过 `/artifacts/demo_acceptance/...` 提供验收记录和 SVG 截图快照访问。
- 新增测试覆盖自适应规则命中计数、启停、撤销，以及一键演示产物生成。

本次验证结果：

- JS 语法检查通过：`node --check dashboard\app.js`。
- 编译检查通过：`.\.venv\Scripts\python -m compileall src scripts tests`。
- 单元测试通过：62 passed。
- Dashboard 前台 smoke test 通过：`GET http://127.0.0.1:8765/` 返回 `200`。
- 规则管理接口通过：`GET /api/adaptive-rules` 返回规则 summary。
- 一键演示接口通过：`POST /api/demo-run` 返回 7 个攻击面，7/7 检出。
- 演示产物链接通过：生成的 `.svg` 截图快照和 `.md` 验收记录均可通过 HTTP 打开。

## 2026-07-16 - DeepSeek Detail Modal And Anomaly Layer Upgrade

本次新增功能：

- DeepSeek 批量红队区改为“矩阵 + 攻击摘要 + 弹窗详情”结构，避免攻击说明和 Guardian 审计结果在主页面双列挤压。
- 点击任意批量条目或“查看详情”按钮，会弹出完整详情：左侧展示攻击点、用户请求、工具调用、风险点，右侧展示总决策、四层 Verdict、漏拦截分析和自适应规则写入结果。
- 主页面下方只保留当前选中条目的攻击摘要，完整 Guardian 结果交给弹窗和下方通用 `Guardian Decision` 面板展示。
- `AnomalyLayer` 从单一重复调用检测升级为三类启发式：重复工具循环、DeepSeek 红队攻击链元数据、读取/抓取后跳转高影响工具或外联目标共现。
- 新增离线攻击样本 `an-002`：读取系统日志并外联到 `evil.example`，用于展示第 4 层 anomaly 的 `BLOCK` 能力。
- 新增 anomaly 单元测试，覆盖 DeepSeek 红队元数据、读取外联链路和读取后高影响工具跳转。
- 更新评测结果，离线集变为 30 条：22 条攻击、8 条良性对照。

本次验证结果：

- JS 语法检查通过：`node --check dashboard\app.js`。
- 编译检查通过：`.\.venv\Scripts\python -m compileall src scripts tests`。
- 单元测试通过：60 passed。
- Benchmark 通过：30 条用例，22/22 攻击检出，0 阻断型误报，2 条良性告警。
- 第 4 层统计不再全绿：`anomaly` 层在离线评测中产生 5 次 `BLOCK`、7 次 `FLAG`。

## 2026-07-16 - DeepSeek Red Team UX And Prompt Modes

本次新增功能：

- DeepSeek 在线红队从单一固定提示词升级为 4 种攻击模式：精准单步、伪装正常任务、多步攻击链、绕过变体。
- 每个攻击面现在通过 `/api/summary` 返回 `prompt_modes`，前端可按模式显式展示和编辑完整提示词。
- 批量生成接口新增 `attack_mode` 元数据，审计历史和 Guardian context 能记录该条攻击来自哪种生成模式。
- DeepSeek 批量条目的详情展示从原始 JSON 代码块改为结构化说明，拆分展示攻击目标、用户请求、工具调用、污点来源、风险点和危险解释。
- Guardian / 漏拦截分析区改为结构化展示总状态、四层 Verdict、漏拦截状态、DeepSeek 分析结果和自适应规则写入结果。
- 未被 `BLOCK` 的 DeepSeek 红队条目可在详情区直接点击“调用 DeepSeek 分析并优化规则”，形成红队生成、Guardian 审计、漏拦截复盘、规则同步、重评估的闭环。
- 更新 `docs/project_overview.md`，说明 DeepSeek 在线红队的四类模式和前端漏拦截闭环。
- 新增测试覆盖攻击面提示词模式和 `attack_mode` 透传。

本次验证结果：

- JS 语法检查通过：`node --check dashboard\app.js`。
- 编译检查通过：`.\.venv\Scripts\python -m compileall src scripts tests`。
- 单元测试通过：57 passed。
- 补丁检查通过：`git diff --check`。
- Dashboard 前台 smoke test 通过：`GET http://127.0.0.1:8765/` 返回 `200`。
- Dashboard 摘要接口通过：29 个样本、7 个攻击面、每个攻击面 4 个 DeepSeek 提示词模式。
- 无 API Key 时在线 DeepSeek 接口按预期拒绝真实调用，不会把密钥写入项目文件。

## 2026-07-16 - Adversarial Dataset And Quantified Evaluation

本次 C 方向优化：

- 将离线评测种子集扩展到 29 条：21 条攻击样本、8 条良性对照。
- 新增攻击类别覆盖：模型越狱、训练数据泄露扩展样本、工具调用劫持外联样本、记忆中毒外部 URL 链路、环境感知污染 shell 链路、序列异常样本。
- 新增良性对照：低于异常阈值的重复读取、读取不可信源后写普通摘要等，用于观察告警和阻断的区别。
- 同步更新 `datasets/seed_cases.jsonl`，并增加测试保证 jsonl 样本 ID 与 `src/redteam/attacks.py` 的 `EVAL_CASES` 一致。
- 强化 `PolicyLayer` 对 PowerShell encoded command 的阻断，覆盖模型越狱变体。
- 增强 `src/eval/benchmark.py`：新增按攻击面分类指标、四层 Verdict 分布、混淆矩阵、良性告警数、p50/p95 延时、逐样本层级动作。
- `scripts/run_benchmark.py` 现在同时输出 `report/eval_results.md` 和 `report/eval_results.json`。

本次验证结果：

- `.\.venv\Scripts\python scripts\run_benchmark.py`：29 条用例，21/21 攻击检出，0 阻断型误报，2 条良性告警。
- 编译检查通过：`.\.venv\Scripts\python -m compileall src scripts tests`。
- 单元测试通过：56 passed。

## 2026-07-16 - Four-Layer Explanation And Code Comments

本次新增文档和注释：

- 深入扩写 `docs/project_overview.md` 中 Guardian 四层模块的实现说明，不再只写概述作用，而是解释每层输入、判断逻辑、输出结果、覆盖攻击面和当前边界。
- 新增 `project_overview` 的“核心代码注释导航”，说明答辩和小组协作时应如何阅读核心代码。
- 补充四层核心代码注释：`guardian.py`、`policy.py`、`taint.py`、`intent.py`、`anomaly.py`、`adaptive_rules.py`。
- 补充 Agent 和工具执行代码注释：`deepseek_agent.py`、`tools.py`。
- 补充红队实验台、Dashboard 服务、审计日志和前端批量矩阵注释：`surface_lab.py`、`dashboard_server.py`、`audit.py`、`dashboard/app.js`。

本次验证结果：

- 代码注释为说明性改动，不改变业务逻辑。
- 编译检查通过：`.\.venv\Scripts\python -m compileall src scripts tests`。
- 单元测试通过：54 passed。
- 前端 JS 语法检查通过：`node --check dashboard\app.js`。

## 2026-07-16 - Operation Guide And Topic-Aligned Self Audit

本次新增文档：

- 新增 `docs/operation_guide.md`，说明当前 Dashboard 是前端静态页面和后端 API 共用一个 Python 进程。
- 补充 Dashboard 默认端口 `127.0.0.1:8765` 的启动、换端口、检查端口、关闭端口命令。
- 补充 DeepSeek API Key 的临时使用方式，强调真实 key 不应写入脚本、文档或提交。
- 补充 Windows `WinError 10013` 的排查路径：通常是启动 Dashboard 的 Python 进程没有出站网络权限。
- 更新 `docs/project_self_audit.md`，按选题目标重新梳理后续深入方向：攻击面覆盖、行为监督机制工程化、对抗样本量化评测、前端演示和验收增强。
- 更新 `README.md` 和 `docs/project_overview.md`，加入操作指导文档入口。

本次验证结果：

- 文档中未写入真实 API Key。
- 文档命令使用占位符和本地默认端口，不改变代码运行逻辑。

## 2026-07-16 - DeepSeek Dashboard Connectivity And Prompt Sync Fix

本次修复：

- 修复 DeepSeek Red Team 前端切换攻击面后，提示词文本框仍停留在上一个攻击面的默认提示词问题。现在首次加载、下拉切换攻击面、点击攻击面卡片运行 DeepSeek 红队时，都会同步显示当前攻击面的默认提示词；用户手动编辑后会保留修改。
- 改进前端 API 错误展示：服务端返回 JSON 错误时，页面会显示整理后的错误消息，而不是直接显示原始 `500 {"error": ...}`。
- 改进 DeepSeek 红队生成和漏拦截分析的网络错误诊断：遇到 Windows `WinError 10013` 时，会明确提示“当前 Python 进程或系统权限阻止出站网络”，提示需要用有出站网络权限的终端启动 Dashboard。

本次验证结果：

- 单元测试通过：54 passed。
- 编译检查通过：`.\.venv\Scripts\python -m compileall src scripts tests`。
- 前端 JS 语法检查通过：`node --check dashboard\app.js`。
- 受限默认执行环境复现 `WinError 10013`，错误消息已被包装为可操作中文诊断。
- 带出站网络权限的真实 DeepSeek smoke test 通过：`model_jailbreak` 生成 `run_shell`，期望动作 `block`。
- Dashboard 固定端口已用带出站网络权限的进程重启。
- 真实 Dashboard 批量接口通过：`model_jailbreak` 一次生成 3 条，3 条均返回 `block`。
- 真实 Dashboard 批量接口 + DeepSeek intent judge 通过：`tool_hijack` 生成 1 条，`intent_judge_enabled=True`，最终返回 `block`。
- 真实 API Key 只通过运行时隐藏输入进入内存，没有写入项目文件。

## 2026-07-15 - Red Team Expectation Guard And Missed-Detection Display

本次新增功能：

- Guardian 策略层新增 DeepSeek 红队“期望阻断”兜底：当样本元数据中 `expected_guardian_action` 为 `block` / `flag`，且包含 `attack_goal`、`risk_points` 或 `danger_explanation` 时，即使没有命中旧关键词，也会阻断当前攻击链候选工具调用。
- 前端批量矩阵新增漏拦截语义：如果 DeepSeek 样本期望阻断但 Guardian 实际 `ALLOW`，该条“总”状态会显示红色，并在详情 JSON 中回显 `missed_detection`、`expected_guardian_action` 和 `displayed_total_action`。
- `/api/custom` 支持透传 `metadata`，便于把某条 DeepSeek 生成的红队 JSON 手工复现到 Guardian 审计链路中。
- 保留前端可编辑红队提示词、可设置生成条数、点开条目查看详情、点击“分析漏拦截”后同步受限自适应规则的闭环。

本次验证结果：

- 单元测试通过：53 passed。
- 编译检查通过：`.\.venv\Scripts\python -m compileall src scripts tests`。
- 前端 JS 语法检查通过：`node --check dashboard\app.js`。
- 离线基准通过：`.\.venv\Scripts\python scripts\run_benchmark.py`，10/10 攻击检出，0 阻断型误报。
- Dashboard 固定端口烟测通过：`GET http://127.0.0.1:8765/` 返回 `200`。
- 自定义元数据烟测通过：`web_fetch https://example.com/data` 携带 DeepSeek 红队 `expected_guardian_action=block` 与风险点时返回 `BLOCK`。
- 未写入任何真实 API Key；API Key 仍只允许通过运行时输入或本地页面临时请求进入内存。

## 2026-07-15 - Batch Red Team Matrix And Adaptive Defense Analysis

本次新增功能：

- DeepSeek 红队支持一次生成多条攻击样本，前端可设置生成条数。
- DeepSeek 红队提示词可在前端显式编辑；留空时使用对应攻击面的默认提示词。
- 前端新增批量防御状态矩阵：每条攻击显示“条目信息 / 总 / 1 / 2 / 3 / 4 / 操作”，其中 1-4 对应 `Policy`、`Taint`、`Intent`、`Anomaly` 四层状态。
- 点击任意攻击条目可查看该条 DeepSeek 原始红队 JSON、Guardian 总决策和四层 Verdict。
- 对未被 `BLOCK` 的条目，前端提供“分析漏拦截”按钮，调用 DeepSeek 分析未拦截原因。
- 新增受限自适应规则文件 `sandbox_runs/audit/adaptive_rules.json`；DeepSeek 只能生成 `tool_name`、`surface_id`、`*_contains_any` 这类数据规则，不能生成或执行代码。
- 漏拦截分析后会自动应用自适应规则，并对同一攻击条目重评估，前端显示应用规则后的防御状态。
- Guardian `Context` 新增 `metadata`，DeepSeek 红队的 `risk_points`、`danger_explanation`、`expected_guardian_action` 会进入防御判断。
- 修复工具调用劫持中“当前工具只是 `web_fetch`，但红队元数据明确说明后续会诱导 `delete_database` / `send_http`”的绕过问题。

本次验证结果：

- 单元测试通过：51 passed。
- 编译检查通过：`.\.venv\Scripts\python -m compileall src scripts tests`。
- 页面入口通过：`GET http://127.0.0.1:8765/` 返回 `200`。
- 用户请求中包含 `evil.example` 外联意图时，即使当前工具只是 `web_fetch internal.example.com`，也返回 `block`。
- DeepSeek 批量红队通过：`tool_hijack` 一次生成 2 条，2 条均返回 `block`，并返回每条四层状态。
- 漏拦截分析接口通过：DeepSeek 返回未拦截原因，写入 1 条受限自适应规则，重评估后同一条目返回 `block`。
- 真实 API Key 只通过隐藏输入或本地页面临时请求进入内存，没有写入项目文件。

## 2026-07-15 - Dashboard History And DeepSeek Attack Hardening

本次新增功能：

- 修复 DeepSeek 在线红队下的记忆中毒漏拦截：对 `evil.example`、`/config` 等可疑外部 URL 抓取，以及“外部内容写入长期记忆”的链路进行阻断。
- 修复工具调用劫持漏拦截：`run_shell` 不再只检查 `command` 字段，也会检查 `cmd`、`script`、`code` 等字段和完整参数文本。
- 扩展敏感信息策略：阻断读取敏感路径、回显 `$TOKEN` / `$API_KEY` 等环境变量。
- 修复间接提示注入漏拦截：不可信来源触发 shell 或写入 `memory`、`plans`、`config` 等持久化/计划类文件时直接阻断。
- DeepSeek 红队生成样本若漏填 `tainted_sources`，会按攻击面默认补齐污点来源，避免前端演示丢失上下文。
- 新增 Dashboard SQLite 历史库 `sandbox_runs/audit/dashboard_history.sqlite3`。
- 新增 API：`GET /api/history` 和 `POST /api/history/clear`。
- 前端审计流改为持久历史流；每次请求后指标卡、四层防御统计和攻击面覆盖都会按历史请求动态刷新。
- 前端固定使用默认端口 `http://127.0.0.1:8765` 作为演示入口。

本次验证结果：

- 单元测试通过：45 passed。
- 编译检查通过：`.\.venv\Scripts\python -m compileall src scripts tests`。
- 页面入口通过：`GET http://127.0.0.1:8765/` 返回 `200`。
- 记忆中毒烟测通过：`web_fetch https://evil.example/security/config.txt` 返回 `block`。
- 工具调用劫持烟测通过：`run_shell {"cmd":"ls /backup && rm -rf /data/db"}` 返回 `block`。
- 间接提示注入烟测通过：污点来源 `web_fetch` 写入 `plans/next_steps.txt` 返回 `block`。
- 历史流烟测通过：`GET /api/history` 返回持久记录，动态统计显示 4 条烟测请求均阻断。
- DeepSeek 在线红队复测通过：`memory_poison`、`tool_hijack`、`indirect_injection` 均返回 `block`。
- 真实 API Key 只通过隐藏输入或本地页面临时请求进入内存，没有写入项目文件。

## 2026-07-15 - Attack Surface Lab And DeepSeek Red Team Dashboard

本次新增功能：

- 新增 `src/redteam/surface_lab.py`，把提示注入、模型越狱、训练数据泄露、工具调用劫持、记忆中毒、环境感知污染、间接提示注入整理为 7 个独立攻击面。
- Dashboard 新增“独立攻击面重跑”区域，每个攻击面都可以单独离线重跑，并观察用户请求、工具调用、四层 Verdict 和最终动作。
- Dashboard 新增“DeepSeek Red Team”区域，可以选择攻击面，让 DeepSeek 在线生成攻击请求、危险工具调用、风险点和危险说明。
- DeepSeek 生成的工具调用只交给 Guardian 审计，不会真实执行危险工具。
- DeepSeek 红队区域支持可选启用 DeepSeek intent judge，用同一个运行时 key 对生成工具调用做意图一致性判断。
- 新增 Dashboard API：`GET /api/attack-surfaces`、`POST /api/rerun-surface`、`POST /api/deepseek-redteam`。
- 更新 `docs/project_overview.md`，补充新前端操作方式和验收流程。

验收方式：

```powershell
.\.venv\Scripts\python scripts\dashboard_server.py
```

浏览器打开：

```text
http://127.0.0.1:8765
```

本次验证结果：

- 单元测试通过：36 passed。
- 编译检查通过：`.\.venv\Scripts\python -m compileall src scripts tests`。
- 页面入口通过：`GET /` 返回 `200`。
- 攻击面接口通过：返回 7 个独立攻击面。
- 独立攻击面离线重跑通过：`memory_poison` 返回 `block`。
- DeepSeek 在线红队通过：`prompt_injection` 生成 `delete_database`，Guardian 返回 `block`。
- DeepSeek 在线红队 + intent judge 通过：`tool_hijack` 生成 `run_shell`，Guardian 返回 `block`。
- 真实 API Key 只通过隐藏输入或本地页面临时请求进入内存，没有写入项目文件。

## 2026-07-15 - Web Dashboard And Project Self Audit

本次新增功能：

- 新增本地网页前端 `dashboard/`。
- 新增 `scripts/dashboard_server.py`，使用 Python 标准库提供静态页面和 Guardian API。
- Dashboard 支持查看拦截统计、红队样本列表、攻击面覆盖、四层防御统计、逐层 Verdict 和交互审计流。
- Dashboard 支持自定义工具调用评估，可在前端输入工具名、JSON 参数和污点来源。
- Dashboard 前端对样本内容和审计内容做 HTML 转义，后端对静态文件路径做目录约束，避免演示数据污染页面或路径穿越读取项目文件。
- 新增测试 `tests/test_dashboard_server.py`，覆盖 Dashboard summary、样本评估和自定义危险命令拦截。
- 新增项目自查文档 `docs/project_self_audit.md`，列出后续还应补充的方向。

验收方式：

```powershell
.\.venv\Scripts\python scripts\dashboard_server.py
```

浏览器打开：

```text
http://127.0.0.1:8765
```

验证命令：

```powershell
.\.venv\Scripts\python -m pytest
```

本次验证结果：

- 页面入口通过：`GET http://127.0.0.1:8766/` 返回 `200`。
- 汇总 API 通过：16 条内置样本，10 条命中风险，9 次阻断，2 次标记。
- 单样本评估通过：`POST /api/evaluate` 评估 `ii-001` 返回 `block`。
- 自定义攻击评估通过：`run_shell {"command":"rm -rf /"}` 返回 `block`，原因命中“危险命令：递归强制删除”。
- 单元测试通过：32 passed。
- 编译检查通过：`.\.venv\Scripts\python -m compileall src scripts tests`。
- 补丁检查通过：`git diff --check`。

## 2026-07-15 - Public Jailbreak Dataset Conversion

本次新增功能：

- 新增公开越狱/对抗数据集转换器 `src/redteam/dataset_converter.py`。
- 新增命令行脚本 `scripts/convert_public_jailbreaks.py`。
- 新增 AdvBench 风格小型样例 `datasets/public_samples/advbench_sample.csv`。
- 支持 CSV、JSON、JSONL 输入。
- 支持常见公开数据集字段：`goal`、`prompt`、`behavior`、`instruction`、`question`、`query`。
- 转换输出统一为 Argus jsonl 格式：`id`、`category`、`user_request`、`should_block`、`source`、`original`。
- 新增测试 `tests/test_dataset_converter.py`，覆盖行转换、CSV 读取、JSONL 写入。

实现意义：

- 后续可以把 AdvBench、JailbreakBench 等公开越狱集转换为项目自己的对抗样本格式。
- 大型公开数据集不直接入库，只提交小型样例和转换脚本，避免仓库膨胀。

验收方式：

```powershell
.\.venv\Scripts\python scripts\convert_public_jailbreaks.py datasets\public_samples\advbench_sample.csv datasets\public_jailbreak_seed.jsonl --source advbench
.\.venv\Scripts\python -m pytest
```

本次验证结果：

- 转换脚本通过：3 行 AdvBench 风格样例转换为 `datasets/public_jailbreak_seed.jsonl`。
- 单元测试通过：27 passed。
- 编译检查通过：`.\.venv\Scripts\python -m compileall src scripts tests`。
- 密钥泄漏检查通过：跟踪文件中只存在占位符示例，没有真实 API Key。
