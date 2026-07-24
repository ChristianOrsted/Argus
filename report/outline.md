# 实训报告大纲 —— Argus 大模型智能体行为监督系统

## 进度表（4 周）

| 周次 | 目标 | 主要负责人 | 验收（周五进度汇报） |
|---|---|---|---|
| 第 1 周 | 攻击面调研；最小 Agent 跑通；攻击集种子 | 全体 / A | demo 能在 Guardian 下执行良性任务 |
| 第 2 周 | Guardian 核心：策略+沙箱+污点；基线检测 | B | 能拦 rm -rf / 越界读写 / 简单间接注入 |
| 第 3 周 | 意图一致性(LLM-judge) + 序列异常；评测基准 | B / C | 跑出检出率/误报率/延时初版数据 |
| 第 4 周 | 加固、看板 demo、写报告 | 全体 | 完整演示 + 报告定稿 |

---

## 报告正文结构（建议）

1. **引言**：背景（智能体安全为何重要）、问题定义、本文贡献。
2. **威胁模型与攻击面**：六类攻击的分类学（见 docs/architecture.md）。
3. **系统设计**：四层防御架构，重点讲第 2 层污点追踪的原创性。
4. **实现**：Agent 手动循环 + Guardian 检查点；关键代码与工程取舍。
5. **红队**：攻击集构造方法与代表性样本；越狱/注入复现。
6. **评测**：检出率 / 误报率 / 延时开销；逐层消融实验；结果分析。
7. **讨论与不足**：绕过手法、误报来源、未来工作。
8. **结论**。
9. **分工说明 + 参考文献**。

---

## 交付物清单（对应选题要求）

- [x] 风险分析报告（= report/final_report.md + docs/architecture.md）
- [x] 越狱 / 对抗测试集（datasets/seed_cases.jsonl + src/redteam/attacks.py）
- [x] 攻击脚本（scripts/replay_case.py + scripts/run_benchmark.py）
- [x] 可演示的智能体行为监督原型系统（src/ + scripts/offline_demo.py + scripts/deepseek_demo.py）
- [x] 评测结果（report/eval_results.md）

阶段 2 已补充：

- `src/redteam/attacks.py`：红队与良性种子用例，覆盖提示注入、工具劫持、敏感信息读取、间接注入、记忆中毒、环境污染。
- `datasets/seed_cases.jsonl`：可提交的小型 jsonl 测试集。
- `scripts/run_benchmark.py`：离线评测脚本，输出 `report/eval_results.md`。
