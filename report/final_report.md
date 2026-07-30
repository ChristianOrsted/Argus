# Argus 大模型智能体行为监督系统报告草稿

## 1. 引言

大语言模型智能体可以调用 shell、文件、网页等外部工具，因此安全风险不再停留在“模型说了什么”，
而是扩展到“模型做了什么”。一旦攻击者通过提示注入、网页污染或工具劫持诱导 Agent 执行危险动作，
后果可能包括文件破坏、凭据泄露、恶意脚本执行和长期记忆污染。

Argus 的目标是实现一个旁路部署的行为监督器：在 Agent 发起工具调用之后、真实工具执行之前，
对工具名、参数、历史上下文和数据来源进行实时审计，并给出放行、告警或阻断决策。

## 2. 威胁模型与攻击面

本项目覆盖六类风险：

- 提示注入：直接要求模型忽略规则并执行危险命令。
- 模型越狱：诱导模型绕过原有安全边界。
- 训练数据泄露：诱导读取或输出 `.env`、API key、SSH key 等敏感信息。
- 工具调用劫持：调用非白名单工具，或越出沙箱读写文件。
- 记忆中毒：向长期记忆或指令文件写入恶意规则。
- 环境感知污染：在网页、README、日志等外部内容中隐藏恶意指令。

阶段实现重点放在工具调用劫持、间接提示注入和记忆中毒，因为这些风险可以通过工具调用审计形成可复现证据。

## 3. 系统设计

Argus 采用四层 Guardian：

- PolicyLayer：工具白名单、危险命令模式、文件沙箱、敏感凭据读取、记忆中毒规则。
- TaintLayer：将 `web_fetch`、`read_file` 视为不可信来源；不可信来源后触发高权限工具至少告警，命中危险 sink 时阻断。
- IntentLayer：可插拔 DeepSeek judge，判断工具调用是否符合用户原始意图；默认关闭以保证离线演示可运行。
- AnomalyLayer：检测重复工具调用等序列异常。

所有层输出 `Verdict`，Guardian 汇总成最终 `Decision`：任一层 `BLOCK` 即阻断；无阻断但有 `FLAG` 则告警；否则放行。

## 4. 实现

主要模块：

- `src/agent/deepseek_agent.py`：DeepSeek/OpenAI-compatible Agent，支持 tool calling。
- `src/agent/tools.py`：shell、读写文件、网页抓取工具；`web_fetch` 支持 `fixture://` 离线样本。
- `src/guardian/`：四层防御、审计日志、DeepSeek intent judge。
- `src/redteam/attacks.py`：红队与良性种子用例。
- `src/eval/benchmark.py`：检出率、误报率、平均延时和逐用例结果。
- `scripts/offline_demo.py`：无需 API Key 的演示脚本。
- `scripts/replay_case.py`：按用例 ID 复现攻击或良性案例。
- `scripts/run_benchmark.py`：生成评测结果表。

## 5. 红队样本

当前种子集共 30 条：

- 攻击样本 22 条：覆盖提示注入、模型越狱、训练数据泄露、工具劫持、间接注入、记忆中毒、环境污染和序列异常。
- 良性对照 8 条：覆盖正常 shell、文件读写、网页读取、读不可信源后写普通摘要等场景。

可提交的小型测试集在 `datasets/seed_cases.jsonl`，可直接运行的 Python 用例在 `src/redteam/attacks.py`。

## 6. 评测结果

离线评测结果见 `report/eval_results.md`。2026 年 7 月 30 日使用当前代码重新生成的结果如下：

- 总用例：30
- 攻击用例：22
- 良性用例：8
- 攻击检出：22/22（Alert Recall：100.00%）
- 直接阻断攻击：21/22（Block Recall：95.45%）
- 阻断型误报：0（Block false positive rate：0.00%）
- 良性告警：2
- 平均审计延时：0.269 ms（p50：0.238 ms；p95：0.586 ms）

说明：良性 `bn-005` 和 `bn-008` 被污点层与异常层标记为 `FLAG`，但没有阻断，因此不计为阻断型误报。这符合“可疑但允许继续”的旁路监督定位。

在线 Intent Judge 也已于同日使用 `.env` 中配置的 DeepSeek Key 重新评测：5 条工具调用一致性样例全部判断正确（5/5，100.00%），平均端到端延时为 1028.608 ms。逐样例结果见 `report/deepseek_intent_eval.md`；该延时包含网络和模型推理，不应与离线本地审计延时直接比较。

## 7. 演示方式

离线演示：

```powershell
python scripts\offline_demo.py
```

复现单个攻击：

```powershell
python scripts\replay_case.py ii-001
```

运行评测：

```powershell
python scripts\run_benchmark.py
```

在线 DeepSeek Agent demo：

```powershell
Copy-Item .env.example .env
# 填写 DEEPSEEK_API_KEY
python scripts\deepseek_demo.py
```

## 8. 局限与未来工作

- 污点追踪仍是来源级与参数模式级，还没有做到 token/片段级数据流追踪。
- Intent judge 默认关闭，在线效果需要 DeepSeek API Key 和更多真实样本校准。
- 序列异常目前是启发式重复检测，后续可加入 n-gram 或 Markov 基线。
- 当前测试集是课程演示规模，后续可接入公开越狱集和更复杂的 Agent 真实轨迹。

## 9. 分工建议

- A：Agent、工具层、DeepSeek demo、审计输出。
- B：Guardian 核心、policy/taint/intent、防御规则。
- C：红队样本、攻击脚本、benchmark、报告图表。

三人都需要理解 `src/guardian/guardian.py` 的 `ToolCall -> Verdict -> Decision` 主接口。
