# Argus Update Log

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
