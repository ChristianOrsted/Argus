"""DeepSeek/OpenAI-compatible ReAct Agent。

DeepSeek 的 chat/completions 接口兼容 OpenAI tool calling。这个 Agent 保持与
`ReActAgent` 相同的 Guardian 检查点：每次工具调用执行前都先生成 `ToolCall`，
交给 Guardian 决策，再决定是否执行真实工具。
"""

from __future__ import annotations

import json
from typing import Callable, Optional
from urllib.request import Request, urlopen

from ..config import AGENT_MODEL, DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL
from ..guardian.guardian import Action, Context, Guardian, ToolCall
from .tools import OPENAI_TOOLS, UNTRUSTED_SOURCE_TOOLS, execute_tool

DEFAULT_SYSTEM = "You are a helpful assistant with access to shell, file, and web tools."


class DeepSeekReActAgent:
    def __init__(
        self,
        guardian: Optional[Guardian] = None,
        system: str = DEFAULT_SYSTEM,
        model: str = AGENT_MODEL,
        base_url: str = DEEPSEEK_BASE_URL,
        api_key: str = DEEPSEEK_API_KEY,
        on_event: Optional[Callable[[str, dict], None]] = None,
    ):
        self.guardian = guardian
        self.system = system
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.on_event = on_event or (lambda kind, payload: None)

    def _chat(self, messages: list[dict]) -> dict:
        if not self.api_key:
            raise RuntimeError("缺少 DEEPSEEK_API_KEY，无法调用 DeepSeek API")

        payload = {
            "model": self.model,
            "messages": messages,
            "tools": OPENAI_TOOLS,
            "tool_choice": "auto",
            "max_tokens": 4096,
        }
        req = Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def run(self, user_request: str, max_steps: int = 10) -> str:
        ctx = Context(user_request=user_request)
        messages = [
            {"role": "system", "content": self.system},
            {"role": "user", "content": user_request},
        ]

        for _ in range(max_steps):
            response = self._chat(messages)
            message = response["choices"][0]["message"]
            tool_calls = message.get("tool_calls") or []

            if not tool_calls:
                final = message.get("content") or ""
                self.on_event("final", {"text": final})
                return final

            messages.append(message)

            for tool_call in tool_calls:
                function = tool_call["function"]
                try:
                    tool_input = json.loads(function.get("arguments") or "{}")
                except json.JSONDecodeError:
                    tool_input = {"_raw_arguments": function.get("arguments", "")}

                call = ToolCall(
                    name=function["name"],
                    input=tool_input,
                    tool_use_id=tool_call["id"],
                )
                self.on_event("tool_call", {"call": call})

                if self.guardian is not None:
                    decision = self.guardian.evaluate(call, ctx)
                    self.on_event("decision", {"call": call, "decision": decision})
                    if decision.action == Action.BLOCK:
                        output = f"[ARGUS 已拦截] {decision.reason}"
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call["id"],
                            "content": output,
                        })
                        ctx.history.append(call)
                        continue

                output = execute_tool(call.name, call.input)
                if call.name in UNTRUSTED_SOURCE_TOOLS:
                    ctx.tainted_sources.add(call.name)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call["id"],
                    "content": output,
                })
                ctx.history.append(call)

        self.on_event("final", {"text": "(达到最大步数)"})
        return "(达到最大步数)"
