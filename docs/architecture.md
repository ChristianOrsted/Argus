# Argus 架构说明

## 1. 项目目标

Argus 是一个面向 LLM Agent 的旁路行为监督器。它不试图替代模型本身的安全对齐，
而是插入在 Agent 和工具之间，对工具调用、代码执行、文件访问和外部内容读取进行实时审计。

核心链路：

```text
用户请求 -> Agent 规划 -> ToolCall -> Guardian 多层检查 -> ALLOW / FLAG / BLOCK -> 工具执行或阻断
```

课程交付对应关系：

- 风险分析报告：威胁模型、攻击面和防御边界。
- 对抗样本与越狱测试集：`datasets/` 与 `src/redteam/`。
- 攻击脚本：可复现直接攻击、工具劫持、间接提示注入等场景。
- 原型系统：Agent + Guardian + 审计日志 + 离线/在线演示。

## 2. 威胁模型

本项目重点覆盖六类风险：

- 提示注入：用户直接诱导模型忽略规则或执行危险动作。
- 模型越狱：通过角色扮演、编码、分步诱导绕过安全边界。
- 训练数据泄露：诱导输出隐私、密钥、训练样本或内部提示词。
- 工具调用劫持：诱导 Agent 调用非预期工具、越权访问文件或外联泄露数据。
- 记忆中毒：将恶意偏好、虚假事实或后门写入长期记忆。
- 环境感知污染：在网页、文件、日志等外部上下文中埋入恶意指令。

阶段 1 的工程重点是工具调用劫持与环境感知污染，因为它们最容易通过工具审计和污点追踪形成可演示闭环。

## 3. Guardian 四层防御

### 3.1 PolicyLayer

确定性策略层，负责最低成本、最高确定性的阻断：

- 工具白名单。
- 危险 shell 模式，例如 `rm -rf`、fork bomb、`curl | sh`、反弹 shell。
- 文件路径沙箱限制。

该层适合直接 `BLOCK`。

### 3.2 TaintLayer

污点追踪层，负责防御间接提示注入：

- `web_fetch` 和 `read_file` 的返回视为不可信来源。
- Agent 登记来源级污点，同时抽取片段级污点：`source`、`text`、`digest`、`origin_tool_use_id`。
- 读取不可信来源后，如果马上执行 `run_shell` 或 `write_file`，至少 `FLAG`。
- 如果具体污点片段流入高权限动作参数，并命中忽略指令、下载执行、删除、凭据等危险模式，则 `BLOCK`。

当前阶段已经把 `ctx.tainted_sources` 扩展为 `ctx.tainted_fragments`，可在审计日志中追踪片段摘要和来源工具调用。

### 3.3 IntentLayer

意图一致性层，计划使用独立 judge 模型判断工具调用是否符合用户原始意图。

阶段 1 保留接口；阶段 2 可接入 DeepSeek 或其他 OpenAI-compatible 模型，且只对高风险工具触发，以控制延时和成本。

阶段 3 已提供 `DeepSeekIntentJudge` 与 `IntentLayer` 的可插拔 judge 协议。默认不启用，
传入 judge client 后才会对 `run_shell`、`read_file`、`write_file` 进行一致性判断。

### 3.4 AnomalyLayer

序列异常层，检测异常工具调用链：

- 连续重复同一工具超过阈值即 `FLAG`，用于发现异常循环。
- DeepSeek 红队元数据中出现外联、非白名单、删除数据库、`evil.example` 等攻击链关键词时 `BLOCK`。
- 读取/抓取动作与外联目标共现时 `BLOCK`，用于识别数据外泄攻击链前序步骤。
- 读取/抓取后跳转到 `run_shell` / `write_file` 等高影响工具时 `FLAG` 或 `BLOCK`。
- 后续仍可基于良性序列建立 n-gram/Markov 基线，替换或补充当前启发式分数。

## 4. DeepSeek 接入方向

阶段 1 新增 `DeepSeekReActAgent`，通过 DeepSeek OpenAI-compatible `chat/completions` 接口调用工具。
工具 schema 从 Anthropic 格式转换为 OpenAI tool calling 格式，每次 tool call 执行前仍经过 Guardian。

DeepSeek 相关环境变量：

- `ARGUS_LLM_PROVIDER=deepseek`
- `DEEPSEEK_API_KEY=...`
- `DEEPSEEK_BASE_URL=https://api.deepseek.com/v1`
- `ARGUS_AGENT_MODEL=deepseek-chat`
- `ARGUS_JUDGE_MODEL=deepseek-chat`

## 5. 审计事件

建议所有演示和评测都记录：

- 用户原始请求。
- 工具名和参数。
- 每层 Verdict。
- 最终 Decision。
- 是否执行工具。
- 工具输出摘要。
- 污点来源和触发原因。

这些字段既服务 demo，也服务报告中的风险复现、消融实验和结果表。

阶段 3 新增 `JsonlAuditLogger`，可把每次 `ToolCall`、上下文摘要、逐层 Verdict 和最终 Decision 写入 JSONL。
