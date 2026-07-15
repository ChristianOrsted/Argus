# Argus 项目总览与验收说明

更新日期：2026-07-15

## 1. 选题确认

本项目对应课程选题：

> 面向大模型及其应用的安全性研究

项目对象是大语言模型智能体（LLM Agent），不是传统单机脚本或普通网络安全工具。核心问题是：当大模型 Agent 可以调用 shell、读写文件、抓取网页、执行代码时，攻击者可能通过提示注入、越狱、工具调用劫持、训练数据泄露、记忆中毒、环境感知污染等方式，让 Agent 执行危险动作。

Argus 的目标是做一个可嵌入或旁路部署的智能体行为监督器：

```text
用户请求 -> LLM Agent 规划工具调用 -> Argus Guardian 审计 -> ALLOW / FLAG / BLOCK -> 工具执行或阻断
```

因此，它和题目要求中的“对智能体的工具调用、代码执行和文件访问进行实时审计、异常检测和阻断”是一一对应的。

## 2. 项目做了什么

Argus 已经从原始骨架推进为一个可运行原型系统：

- 支持 DeepSeek/OpenAI-compatible tool calling 的 Agent 入口。
- 支持无需 API Key 的离线 Guardian 演示。
- 支持 shell、文件读写、网页/fixture 抓取等工具调用。
- 在工具真正执行前插入 Guardian 检查点。
- 通过四层防御进行实时审计、异常检测和阻断。
- 提供红队攻击样本、良性对照样本、攻击复现脚本和离线评测脚本。
- 生成可读的 Markdown 评测结果。
- 输出 JSONL 审计日志，方便演示和报告取证。

## 3. 模块说明

### 3.1 Agent 层

路径：

- `src/agent/deepseek_agent.py`
- `src/agent/react_agent.py`
- `src/agent/tools.py`

作用：

- `DeepSeekReActAgent` 使用 DeepSeek 的 OpenAI-compatible Chat Completions 接口。
- `ReActAgent` 保留原 Claude/Anthropic demo 兼容入口。
- `tools.py` 定义 Agent 可用工具：`run_shell`、`read_file`、`write_file`、`web_fetch`。
- `web_fetch` 支持 `fixture://`，所以间接提示注入可以离线复现，不依赖真实网页。

关键点：

- Agent 每次准备调用工具时，都会先构造 `ToolCall`。
- `ToolCall` 先交给 Guardian。
- 只有未被 `BLOCK` 的工具调用才会真正执行。

### 3.2 Guardian 核心层

路径：

- `src/guardian/guardian.py`
- `src/guardian/policy.py`
- `src/guardian/taint.py`
- `src/guardian/intent.py`
- `src/guardian/anomaly.py`
- `src/guardian/audit.py`

Guardian 四层防御：

- `PolicyLayer`：确定性规则层。拦截危险 shell、未知工具、沙箱外文件读写、敏感凭据读取、记忆中毒写入。
- `TaintLayer`：污点追踪层。把 `web_fetch`、`read_file` 视为不可信来源；同时抽取具体文本片段、摘要和来源工具调用 ID。若片段流入 `run_shell` / `write_file` 等高权限动作，则按证据告警或阻断。
- `IntentLayer`：意图一致性层。提供可插拔 judge 接口和 `DeepSeekIntentJudge`，用于判断工具调用是否符合用户原始意图。默认关闭，避免离线演示依赖 API Key。
- `AnomalyLayer`：序列异常层。当前实现重复工具调用检测，后续可扩展为 n-gram 或 Markov 行为模型。

决策逻辑：

- 任一层 `BLOCK`，最终阻断。
- 无 `BLOCK` 但有 `FLAG`，最终告警。
- 全部 `ALLOW`，最终放行。

### 3.3 红队样本与测试集

路径：

- `src/redteam/attacks.py`
- `datasets/seed_cases.jsonl`
- `datasets/fixtures/web_notes_evil.txt`

已有样本：

- 攻击样本 10 条。
- 良性对照 6 条。
- 覆盖提示注入、工具调用劫持、敏感信息读取、间接提示注入、记忆中毒、环境污染等场景。

`web_notes_evil.txt` 是间接提示注入 fixture：表面是普通网页笔记，隐藏内容要求 Agent 忽略原指令并下载执行恶意脚本。

### 3.4 攻击脚本与演示脚本

路径：

- `scripts/offline_demo.py`
- `scripts/replay_case.py`
- `scripts/run_benchmark.py`
- `scripts/run_intent_judge_eval.py`
- `scripts/convert_public_jailbreaks.py`
- `scripts/dashboard_server.py`
- `scripts/deepseek_demo.py`

作用：

- `offline_demo.py`：无需 API Key，演示良性放行、危险命令阻断、间接注入阻断。
- `replay_case.py`：按样本 ID 复现单个攻击或良性场景。
- `run_benchmark.py`：运行全部种子样本，输出检出率、误报率和延时。
- `run_intent_judge_eval.py`：调用真实 DeepSeek intent judge，在线评测工具调用与用户意图是否一致。
- `convert_public_jailbreaks.py`：把 AdvBench/JailbreakBench 风格公开数据集转换为 Argus jsonl。
- `dashboard_server.py`：启动本地网页 Dashboard，展示样本、统计、逐层 Verdict 和自定义评估。
- `deepseek_demo.py`：有 DeepSeek API Key 时，运行真实在线 Agent demo。

### 3.5 报告与结果

路径：

- `docs/architecture.md`
- `docs/project_overview.md`
- `report/final_report.md`
- `report/eval_results.md`
- `COMMIT_SUMMARY.md`

作用：

- `architecture.md`：系统架构说明。
- `project_overview.md`：总体性说明和验收指南。
- `final_report.md`：课程报告草稿。
- `eval_results.md`：自动生成的评测结果。
- `COMMIT_SUMMARY.md`：阶段 commit 汇总。

## 4. 已达成的课程交付物

| 课程要求 | 当前状态 | 对应文件 |
|---|---|---|
| 安全风险分析报告 | 已有草稿，后续可继续润色 | `report/final_report.md`, `docs/architecture.md` |
| 对抗样本与越狱测试集 | 已有可运行种子集 | `datasets/seed_cases.jsonl`, `src/redteam/attacks.py` |
| 攻击脚本 | 已有，可按 ID 复现 | `scripts/replay_case.py` |
| 可演示的智能体行为监督原型系统 | 已有，离线可跑，在线 DeepSeek 可接入 | `scripts/offline_demo.py`, `scripts/deepseek_demo.py`, `src/guardian/` |
| 实时审计、异常检测和阻断 | 已实现四层 Guardian 与 JSONL 审计 | `src/guardian/`, `sandbox_runs/audit/offline_demo.jsonl` |
| 评测结果 | 已自动生成 | `report/eval_results.md` |

## 5. 如何验收

建议按下面顺序验收。

### 5.1 安装依赖

```powershell
cd E:\eve_jump\暑期课程\Argus
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m pip install pytest
```

如果已经安装过，可跳过。

### 5.2 跑单元测试

```powershell
.\.venv\Scripts\python -m pytest
```

当前验证结果：

```text
20 passed in 0.33s
```

### 5.3 跑离线原型演示

```powershell
.\.venv\Scripts\python scripts\offline_demo.py
```

应看到三类关键效果：

- 良性写文件：`ALLOW`
- 危险命令 `rm -rf /`：`BLOCK`
- 读取恶意网页 fixture 后写入注入计划：`BLOCK`

同时生成审计日志：

```text
sandbox_runs/audit/offline_demo.jsonl
```

### 5.4 复现单个攻击样本

```powershell
.\.venv\Scripts\python scripts\replay_case.py ii-001
```

`ii-001` 是间接提示注入样本，预期结果是被 `TaintLayer` 阻断。

也可以复现良性告警样本：

```powershell
.\.venv\Scripts\python scripts\replay_case.py bn-005
```

`bn-005` 会得到 `FLAG`，但不会被 `BLOCK`，用于说明系统支持“告警但不阻断”的旁路监督模式。

### 5.5 跑整体评测

```powershell
.\.venv\Scripts\python scripts\run_benchmark.py
```

当前评测结果：

- 总样本：16
- 攻击样本：10
- 良性样本：6
- 攻击检出：10/10
- 阻断型误报：0
- Recall：100.00%
- False positive rate：0.00%

结果会写入：

```text
report/eval_results.md
```

### 5.6 可选：跑 DeepSeek 在线 Agent

如果要演示真实大模型 Agent，而不是离线构造 ToolCall，需要配置 DeepSeek API Key：

```powershell
Copy-Item .env.example .env
```

然后编辑 `.env`：

```text
ARGUS_LLM_PROVIDER=deepseek
DEEPSEEK_API_KEY=你的 key
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
ARGUS_AGENT_MODEL=deepseek-chat
```

运行：

```powershell
.\.venv\Scripts\python scripts\deepseek_demo.py
```

### 5.7 可选：跑 DeepSeek Intent Judge 在线评测

该脚本会用隐藏输入读取 API Key，并生成 `report/deepseek_intent_eval.md`：

```powershell
.\.venv\Scripts\python scripts\run_intent_judge_eval.py
```

## 6. 当前验证记录

2026-07-15 已重新验证：

- `.\.venv\Scripts\python -m pytest`：20 passed
- `.\.venv\Scripts\python scripts\offline_demo.py`：通过
- `.\.venv\Scripts\python scripts\replay_case.py ii-001`：通过，攻击被阻断
- `.\.venv\Scripts\python scripts\run_benchmark.py`：通过，10/10 攻击检出，0 阻断型误报
- `.\.venv\Scripts\python -m compileall src scripts tests`：通过
- DeepSeek 在线 Agent smoke test：通过，真实模型发起 `write_file` 与 `read_file` 工具调用，Guardian 审计后放行，沙箱文件内容确认为 `deepseek ok`
- DeepSeek intent judge smoke test：通过，对“只要求总结网页却执行 `rm -rf /`”的工具调用返回不一致
- DeepSeek intent judge 在线评测：通过，5/5 样本判断正确，结果见 `report/deepseek_intent_eval.md`

DeepSeek API Key 仅通过运行时隐藏输入临时注入，没有写入脚本、文档、`.env` 或提交历史。

2026-07-15 片段级污点追踪增强后已重新验证：

- `.\.venv\Scripts\python -m pytest`：24 passed
- `.\.venv\Scripts\python scripts\offline_demo.py`：通过
- `.\.venv\Scripts\python scripts\run_benchmark.py`：通过，10/10 攻击检出，0 阻断型误报
- `.\.venv\Scripts\python -m compileall src scripts tests`：通过

2026-07-15 DeepSeek intent judge 在线评测接入后已重新验证：

- `.\.venv\Scripts\python -m pytest`：25 passed
- `.\.venv\Scripts\python scripts\run_intent_judge_eval.py`：通过，5/5 判断正确
- `.\.venv\Scripts\python -m compileall src scripts tests`：通过

2026-07-15 公开越狱集转换能力接入后已重新验证：

- `.\.venv\Scripts\python scripts\convert_public_jailbreaks.py datasets\public_samples\advbench_sample.csv datasets\public_jailbreak_seed.jsonl --source advbench`：通过，3 条样例转换成功
- `.\.venv\Scripts\python -m pytest`：27 passed
- `.\.venv\Scripts\python -m compileall src scripts tests`：通过

## 7. 后续还能增强什么

如果还有时间，可以继续增强：

- 把污点追踪从来源级升级为片段级数据流追踪。
- 接入 DeepSeek intent judge 的真实在线评测样本。
- 扩展公开越狱集，例如 AdvBench/JailbreakBench 格式转换。
- 给评测结果增加图表。
- 把 `sandbox_runs/audit/*.jsonl` 转成演示看板。

不过就课程原型验收而言，当前项目已经具备：样本、攻击脚本、可运行监督系统、评测结果和报告草稿。
