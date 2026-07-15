# Project Self Audit

更新日期：2026-07-15

## 当前完成度

项目已经具备课程题目要求的核心交付物：

- 红队攻击面：提示注入、训练数据泄露、工具调用劫持、记忆中毒、环境感知污染、间接提示注入。
- 行为监督机制：Policy、Taint、Intent、Anomaly 四层 Guardian。
- 实时审计：JSONL 审计日志与网页 Dashboard 审计流。
- 异常检测和阻断：可对危险 shell、越界文件访问、敏感凭据读取、污点数据流入高权限动作进行阻断或告警。
- 对抗样本与越狱测试集：本地种子集与公开数据集转换器。
- 攻击脚本：单样本复现、全量 benchmark、DeepSeek intent judge 在线评测。
- 可演示原型：离线 CLI demo、DeepSeek 在线 demo、本地网页 dashboard。

## 仍建议补充的方向

### 1. 扩展真实 Agent 轨迹

当前 benchmark 主要是把关键 `ToolCall` 直接交给 Guardian，稳定、便宜、适合验收。后续可以收集 DeepSeek 真实运行时产生的多步工具调用轨迹，形成更接近真实 Agent 的评测集。

### 2. 增强片段级污点追踪

当前片段级污点按行抽取并做规范化包含匹配。后续可增强为：

- token/ngram 级相似匹配；
- 对 paraphrase 注入做语义相似检测；
- 对跨多轮合成的污点进行链式追踪；
- 在审计日志中记录片段流动路径图。

### 3. 扩大公开越狱集覆盖

当前提供转换器和小样例。后续应下载更大规模 AdvBench/JailbreakBench 数据集，转换到 `datasets/raw/` 或外部存储，再抽样形成课程报告中的扩展实验。

### 4. 完善 Intent Judge 消融实验

当前 DeepSeek intent judge 有 5 条在线样本。后续可以：

- 扩展到 30-50 条；
- 统计 judge 准确率、延时、误判类型；
- 比较“无 IntentLayer / 有 IntentLayer”的检出差异；
- 对高风险工具才触发 judge，统计成本。

### 5. 增加前端演示数据持久化

Dashboard 当前实时调用本地 API 并在页面内维护审计流。后续可把前端操作写入 `sandbox_runs/audit/dashboard.jsonl`，便于演示后复盘。

### 6. 报告继续润色

报告草稿已经可用，但最终提交前建议补：

- 系统架构图；
- 攻击链路图；
- Dashboard 截图；
- 评测表格和分析；
- 分工说明；
- 参考文献。

## 下一步优先级建议

1. 用 Dashboard 做一次完整演示录屏或截图。
2. 增加 10-20 条公开越狱样本的转换结果。
3. 追加一组 DeepSeek 真实 Agent 轨迹。
4. 把 Dashboard 截图和 benchmark 表格写入最终报告。
