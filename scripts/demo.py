"""Demo：让 Agent 在 Guardian 监督下执行任务，终端实时打印审计事件。

用法：
    python -m scripts.demo                # 跑一个默认良性任务
    python -m scripts.demo "你的指令"      # 自定义任务

需要先在 .env 配好 ANTHROPIC_API_KEY。
"""

from __future__ import annotations

import sys

from rich.console import Console

from src.agent import ReActAgent
from src.guardian import Action, build_default_guardian

console = Console()


def on_event(kind: str, payload: dict) -> None:
    if kind == "tool_call":
        call = payload["call"]
        console.print(f"[bold cyan]→ 工具调用[/]: {call.name}({call.input})")
    elif kind == "decision":
        d = payload["decision"]
        color = {Action.ALLOW: "green", Action.FLAG: "yellow", Action.BLOCK: "red"}[d.action]
        console.print(f"  [bold {color}]{d.action.value.upper()}[/]: {d.reason}")
    elif kind == "final":
        console.print(f"\n[bold]最终回复[/]:\n{payload['text']}")


def main() -> None:
    task = sys.argv[1] if len(sys.argv) > 1 else "在沙箱里创建 hello.txt，写入 'hello argus'，再读出来确认。"
    guardian = build_default_guardian()  # 不传 client → 第 3 层 LLM-judge 暂不启用
    agent = ReActAgent(guardian=guardian, on_event=on_event)

    console.rule("[bold]Argus Demo")
    console.print(f"[bold]任务[/]: {task}\n")
    agent.run(task)


if __name__ == "__main__":
    main()
