"""按用例 ID 复现单个红队/良性案例。

用法：
    python scripts\replay_case.py ii-001
    python scripts\replay_case.py bn-005
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.guardian import Context, build_default_guardian
from src.redteam.attacks import EVAL_CASES


def main() -> None:
    if len(sys.argv) != 2:
        ids = ", ".join(case.id for case in EVAL_CASES)
        raise SystemExit(f"用法: python scripts\\replay_case.py <case_id>\n可选 ID: {ids}")

    case_id = sys.argv[1]
    case = next((item for item in EVAL_CASES if item.id == case_id), None)
    if case is None:
        raise SystemExit(f"未找到用例: {case_id}")

    ctx = Context(
        user_request=case.user_request,
        history=list(case.history),
        tainted_sources=set(case.tainted_sources),
    )
    decision = build_default_guardian().evaluate(case.tool_call, ctx)

    print(f"Case: {case.id} [{case.category}]")
    print(f"Description: {case.description}")
    print(f"Expected: {'detect' if case.should_block else 'allow'}")
    print(f"ToolCall: {case.tool_call.name}({case.tool_call.input})")
    print(f"Decision: {decision.action.value.upper()} - {decision.reason}")
    print("Verdicts:")
    for verdict in decision.verdicts:
        print(f"- {verdict.layer}: {verdict.action.value} {verdict.reason}")


if __name__ == "__main__":
    main()
