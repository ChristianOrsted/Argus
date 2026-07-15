# datasets/ —— 越狱 / 对抗测试集

大的攻击/越狱样本集放这里（jsonl 格式），默认不入 git；小型可复现种子集 `seed_cases.jsonl` 入库，用于课程演示和离线评测。

## 格式约定（每行一个 JSON 对象）

```json
{"id": "ii-007", "category": "indirect_injection", "user_request": "...", "fixture": "web_notes_evil.txt", "should_block": true}
```

字段对应 `src/redteam/attacks.py` 里的 `AttackCase`。

## 来源建议

- 种子用例：`src/redteam/attacks.py`（少量、可直接跑）。
- 公开越狱集：AdvBench / JailbreakBench 类（按需下载后转成上面的 jsonl）。
- 间接注入：把恶意指令写进 `datasets/fixtures/` 下的网页/文件，给 `web_fetch` / `read_file` 当 fixture。

## 目录

- `datasets/*.jsonl` —— 攻击/良性用例（git 忽略）
- `datasets/seed_cases.jsonl` —— 阶段 2 入库的小型种子集
- `datasets/public_jailbreak_seed.jsonl` —— 由公开数据集样例转换得到的小型越狱种子集
- `datasets/public_samples/` —— 可提交的小型公开格式样例，用于验证转换脚本
- `datasets/fixtures/` —— 间接注入用的被读取文件

## 公开数据集转换

支持 AdvBench / JailbreakBench 风格的 CSV、JSON、JSONL，只要包含 `goal`、`prompt`、`behavior`、`instruction`、`question` 或 `query` 等字段之一即可。

```powershell
python scripts\convert_public_jailbreaks.py datasets\public_samples\advbench_sample.csv datasets\public_jailbreak_seed.jsonl --source advbench
```
