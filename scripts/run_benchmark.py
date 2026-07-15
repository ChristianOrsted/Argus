"""运行 Guardian 离线评测并输出 Markdown 结果。"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.eval.benchmark import evaluate_guardian
from src.guardian import build_default_guardian
from src.redteam.attacks import EVAL_CASES


def main() -> None:
    result = evaluate_guardian(build_default_guardian(), EVAL_CASES)
    markdown = result.to_markdown()

    out = Path("report/eval_results.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(markdown, encoding="utf-8")

    print(markdown)
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
