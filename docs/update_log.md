# Argus Update Log

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
