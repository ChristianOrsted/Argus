# Argus — 大模型智能体行为监督系统

> An Agent Behavior Guardian for LLM Agents
>
> 阿耳戈斯（Argus Panoptes），希腊神话中拥有一百只眼睛、永不全闭的百眼巨人。本项目做的就是"洞察智能体的每一次动作"。

2023 级网络空间安全专业·网络空间安全应用联合大作业（选题一：面向大模型及其应用的安全性研究）。

---

## 项目总览

面向验收的总体说明见 [docs/project_overview.md](docs/project_overview.md)：包含项目目标、模块设计、交付物对应关系和验收命令。启动、关闭端口和 DeepSeek 在线演示排障见 [docs/operation_guide.md](docs/operation_guide.md)。

## 一句话定位

一个**旁路部署的智能体行为监督器（Guardian）**：夹在 LLM Agent 与它的工具（shell / 文件读写 / 联网）之间，对每一次**工具调用、代码执行、文件访问**做实时审计 → 异常检测 → 拦截 / 告警。红队造攻击，蓝队做防御，形成闭环。

## 系统架构

```
用户指令 → [ Agent (LLM + ReAct 循环) ] → 工具调用请求
                                            │
                                  ┌─────────▼──────────┐
                                  │   Argus Guardian   │  ← 项目核心
                                  │ 1 策略 / 沙箱层     │
                                  │ 2 数据来源污点层    │  ← 防"间接提示注入"的关键
                                  │ 3 意图一致性层(LLM) │
                                  │ 4 序列异常层        │
                                  └─────────┬──────────┘
                                     放行 / 拦截 / 告警
                                            │
                                       [ 真实工具执行 ]
```

四层防御的设计细节见 [docs/architecture.md](docs/architecture.md)。

## 目录结构

| 路径 | 内容 | 负责人 |
|---|---|---|
| [src/agent/](src/agent/) | 被监督的智能体：ReAct 循环 + shell/file/web 工具 | A |
| [src/guardian/](src/guardian/) | 监督器核心（四层防御） | B |
| [src/redteam/](src/redteam/) | 红队攻击集与攻击脚本 | C |
| [src/eval/](src/eval/) | 评测：检出率 / 误报率 / 延时开销 | C |
| [datasets/](datasets/) | 越狱 / 对抗测试集（jsonl） | C |
| [report/](report/) | 实训报告 | 全体 |

> 分工是初步建议，三个人可按兴趣调整。建议每人主攻一块，但都要看懂 `guardian/guardian.py` 的接口。

## 快速开始

```powershell
# 1. 建虚拟环境
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. 装依赖
pip install -r requirements.txt

# 3. 先跑离线 demo（不需要 API Key）
python scripts\offline_demo.py

# 4. 配置 DeepSeek API Key（复制模板后填入自己的 key）
Copy-Item .env.example .env
#   然后编辑 .env，填 DEEPSEEK_API_KEY=sk-...

# 5. 跑 DeepSeek 在线 demo（让 Agent 在 Guardian 监督下执行一个任务）
python scripts\deepseek_demo.py

# 6. 复现单个红队用例 / 跑离线评测
python scripts\replay_case.py ii-001
python scripts\run_benchmark.py

# 7. 转换公开越狱集样例
python scripts\convert_public_jailbreaks.py datasets\public_samples\advbench_sample.csv datasets\public_jailbreak_seed.jsonl --source advbench

# 8. 启动网页 Dashboard：攻击面实验台 + DeepSeek 在线红队
python scripts\dashboard_server.py

# 9. 跑测试
pytest
```

## 技术栈

- Python 3.10+
- DeepSeek OpenAI-compatible API（默认模型 `deepseek-chat`，可在 `.env` 里改）
- [Anthropic SDK](https://pypi.org/project/anthropic/)（保留旧版 Claude demo 兼容入口）
- `rich`（终端审计看板）、`pytest`

Dashboard 固定端口为 `http://127.0.0.1:8765`。页面支持 7 个独立攻击面离线重跑、DeepSeek 批量红队生成、可编辑红队提示词、总/四层状态矩阵、DeepSeek 期望阻断兜底、漏拦截红色标记、漏拦截分析与自适应规则同步、持久历史审计流和动态四层防御统计；Key 只用于本地请求，不会写入项目文件。

如果网页端 DeepSeek 调用出现 Windows `WinError 10013`，说明启动 `dashboard_server.py` 的 Python 进程没有出站网络权限；请从有网络权限的终端重新启动 Dashboard，或在防火墙/安全软件中允许 Python 访问 `https://api.deepseek.com`。

完整端口操作命令见 [docs/operation_guide.md](docs/operation_guide.md)。

## 路线图（4 周）

- **第 1 周**：攻击面调研 + 最小 Agent 跑通 + 收集/构造攻击集
- **第 2 周**：Guardian 核心（策略 + 沙箱 + 污点），基线检测
- **第 3 周**：意图一致性（LLM-judge）+ 序列异常；搭"良性+攻击"基准并评测
- **第 4 周**：加固、看板 demo、写报告

详细任务拆分见 [report/outline.md](report/outline.md) 顶部的进度表。
