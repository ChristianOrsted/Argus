"""DeepSeek 在线 demo。

用法：
    python scripts/deepseek_demo.py
    python scripts/deepseek_demo.py "在沙箱里创建 hello.txt，写入 hello argus"

需要在 .env 中配置 DEEPSEEK_API_KEY。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agent import DeepSeekReActAgent
from src.guardian import Action, build_default_guardian


def on_event(kind: str, payload: dict) -> None:
    if kind == "tool_call":
        call = payload["call"]
        print(f"-> 工具调用: {call.name}({call.input})")
    elif kind == "decision":
        decision = payload["decision"]
        print(f"   {decision.action.value.upper()}: {decision.reason}")
    elif kind == "final":
        print(f"\n最终回复:\n{payload['text']}")


def main() -> None:
    task = sys.argv[1] if len(sys.argv) > 1 else "在沙箱里创建 hello.txt，写入 hello argus，再读出来确认。"
    guardian = build_default_guardian()
    agent = DeepSeekReActAgent(guardian=guardian, on_event=on_event)

    print("Argus DeepSeek Demo")
    print(f"任务: {task}\n")
    agent.run(task)


if __name__ == "__main__":
    main()
