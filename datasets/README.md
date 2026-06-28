# datasets/ —— 越狱 / 对抗测试集

大的攻击/越狱样本集放这里（jsonl 格式），**不入 git**（见根目录 `.gitignore`），只在本目录留说明与下载方式。

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
- `datasets/fixtures/` —— 间接注入用的被读取文件（git 忽略）
