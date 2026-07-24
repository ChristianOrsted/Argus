"""ReAct Agent 主循环（手动 agentic loop）。

为什么用手动循环而不是 SDK 的 tool_runner：我们要在每次工具调用【之前】插入 Guardian
检查点，决定放行 / 拦截。这正是官方文档推荐"需要拦截、校验、记录 tool call 时用手动循环"的场景。
"""

from __future__ import annotations

from typing import Callable, Optional

import anthropic

from ..config import AGENT_MODEL
from ..guardian.guardian import Action, Context, Guardian, ToolCall
from ..guardian.taint import register_tool_output_taint
from .tool_security import ToolSecurityError
from .tools import TOOLS, UNTRUSTED_SOURCE_TOOLS, execute_tool

DEFAULT_SYSTEM = "You are a helpful assistant with access to shell, file, and web tools."


class ReActAgent:
    def __init__(
        self,
        guardian: Optional[Guardian] = None,
        system: str = DEFAULT_SYSTEM,
        model: str = AGENT_MODEL,
        on_event: Optional[Callable[[str, dict], None]] = None,
    ):
        self.client = anthropic.Anthropic()
        self.guardian = guardian
        self.system = system
        self.model = model
        # on_event(kind, payload)：供审计看板订阅（tool_call / decision / final 等）
        self.on_event = on_event or (lambda kind, payload: None)

    def run(self, user_request: str, max_steps: int = 10) -> str:
        ctx = Context(user_request=user_request)
        messages = [{"role": "user", "content": user_request}]

        for _ in range(max_steps):
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=self.system,
                tools=TOOLS,
                messages=messages,
            )

            if response.stop_reason != "tool_use":
                final = "".join(b.text for b in response.content if b.type == "text")
                self.on_event("final", {"text": final})
                return final

            messages.append({"role": "assistant", "content": response.content})
            tool_results = []

            for block in response.content:
                if block.type != "tool_use":
                    continue

                call = ToolCall(name=block.name, input=dict(block.input), tool_use_id=block.id)
                self.on_event("tool_call", {"call": call})

                # ---- Guardian 检查点 ----
                if self.guardian is not None:
                    decision = self.guardian.evaluate(call, ctx)
                    self.on_event("decision", {"call": call, "decision": decision})
                    if decision.action == Action.BLOCK:
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": f"[ARGUS 已拦截] {decision.reason}",
                            "is_error": True,
                        })
                        ctx.history.append(call)
                        continue

                # ---- 放行：真正执行 ----
                execution_ok = True
                try:
                    output = execute_tool(call.name, call.input)
                except (ToolSecurityError, OSError) as exc:
                    execution_ok = False
                    output = f"[ARGUS 工具拒绝] {exc}"
                    self.on_event("tool_error", {"call": call, "error": str(exc)})
                # 工具返回若来自不可信源，登记污点（供第 2 层使用）
                if execution_ok and call.name in UNTRUSTED_SOURCE_TOOLS:
                    register_tool_output_taint(ctx, call, output)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": output,
                    "is_error": not execution_ok,
                })
                ctx.history.append(call)

            messages.append({"role": "user", "content": tool_results})

        self.on_event("final", {"text": "(达到最大步数)"})
        return "(达到最大步数)"
