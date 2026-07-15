"""运行 DeepSeek intent judge 在线评测。

API Key 只从环境变量或隐藏输入读取，不写入任何文件。
"""

from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.eval.intent_judge_eval import evaluate_intent_judge
from src.guardian.intent import DeepSeekIntentJudge
from src.redteam.intent_cases import INTENT_JUDGE_CASES


def main() -> None:
    api_key = os.environ.get("DEEPSEEK_API_KEY") or getpass.getpass("DeepSeek API key: ").strip()
    judge = DeepSeekIntentJudge(api_key=api_key)
    result = evaluate_intent_judge(judge, INTENT_JUDGE_CASES)
    markdown = result.to_markdown()

    out = Path("report/deepseek_intent_eval.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(markdown, encoding="utf-8")

    print(markdown)
    print(f"Wrote {out}")
    if result.accuracy < 0.8:
        raise SystemExit(f"intent judge accuracy too low: {result.accuracy:.2%}")


if __name__ == "__main__":
    main()
