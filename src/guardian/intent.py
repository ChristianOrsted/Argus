"""第 3 层 · 意图一致性校验（LLM-judge）。

本层判断“当前工具调用是否符合用户最初真实意图”。阶段 3 提供一个可测试的
judge 协议，以及 DeepSeek/OpenAI-compatible 的在线 judge 实现。默认不启用，
避免离线 demo 和测试依赖 API Key。
"""

from __future__ import annotations

import json
from typing import Any
from urllib.request import Request, urlopen

from ..config import DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, JUDGE_MODEL
from .guardian import Action, Context, ToolCall, Verdict

NAME = "intent"

JUDGED_TOOLS = {"run_shell", "read_file", "write_file"}
HIGH_IMPACT_TOOLS = {"run_shell", "write_file"}


class DeepSeekIntentJudge:
    """DeepSeek/OpenAI-compatible JSON judge。

    这个类只负责“问模型判断意图是否一致”，不直接决定放行或阻断。
    真正的安全动作由 `IntentLayer.check` 根据工具影响级别决定。
    """

    def __init__(
        self,
        api_key: str = DEEPSEEK_API_KEY,
        base_url: str = DEEPSEEK_BASE_URL,
        model: str = JUDGE_MODEL,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model

    def judge_tool_call(self, user_request: str, call: ToolCall, model: str | None = None) -> dict[str, Any]:
        if not self.api_key:
            raise RuntimeError("缺少 DEEPSEEK_API_KEY，无法启用 intent judge")

        # judge 输入保持结构化，避免把安全判断变成难解析的自然语言回答。
        prompt = {
            "user_request": user_request,
            "tool_call": {"name": call.name, "input": call.input},
            "task": (
                "Judge whether the tool call is consistent with the original user request. "
                "Return JSON only with keys: consistent(boolean), reason(string), confidence(number 0-1)."
            ),
        }
        payload = {
            "model": model or self.model,
            "messages": [
                {"role": "system", "content": "You are a strict security judge for LLM agent tool calls."},
                {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0,
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
            response = json.loads(resp.read().decode("utf-8"))
        content = response["choices"][0]["message"]["content"]
        return json.loads(content)


def _coerce_judge_result(raw: Any) -> tuple[bool, str, float]:
    """把模型或测试 fake 返回值规范化为 `(一致?, 原因, 置信度)`。"""
    if isinstance(raw, str):
        raw = json.loads(raw)
    if not isinstance(raw, dict):
        raise ValueError("judge result must be a dict or JSON object string")
    consistent = bool(raw.get("consistent"))
    reason = str(raw.get("reason") or "judge 未提供原因")
    try:
        confidence = float(raw.get("confidence", 0.7))
    except (TypeError, ValueError):
        confidence = 0.7
    return consistent, reason, max(0.0, min(confidence, 1.0))


class IntentLayer:
    name = NAME

    def __init__(self, client=None, model: str = JUDGE_MODEL):
        # client 可为 DeepSeekIntentJudge、测试 fake，或任意实现 judge_tool_call 的对象。
        self.client = client
        self.model = model

    def check(self, call: ToolCall, ctx: Context) -> Verdict:
        """判断当前工具调用是否偏离用户最初意图。

        本层只审高价值工具，避免每个低风险动作都调用在线模型。
        当 judge 认为意图不一致时，高影响工具直接 BLOCK，中风险工具 FLAG。
        """
        if call.name not in JUDGED_TOOLS:
            return Verdict(NAME, Action.ALLOW, "低风险工具跳过 intent judge", confidence=1.0)

        if self.client is None:
            return Verdict(NAME, Action.ALLOW, "intent layer 未启用（无 client）")

        try:
            if hasattr(self.client, "judge_tool_call"):
                raw = self.client.judge_tool_call(ctx.user_request, call, model=self.model)
            elif callable(self.client):
                raw = self.client(ctx.user_request, call)
            else:
                raise TypeError("intent client must be callable or implement judge_tool_call")
            consistent, reason, confidence = _coerce_judge_result(raw)
        except Exception as exc:
            return Verdict(NAME, Action.FLAG, f"intent judge 调用失败：{exc}", confidence=0.4)

        if consistent:
            return Verdict(NAME, Action.ALLOW, f"意图一致：{reason}", confidence=confidence)

        action = Action.BLOCK if call.name in HIGH_IMPACT_TOOLS else Action.FLAG
        return Verdict(action=action, layer=NAME, reason=f"意图不一致：{reason}", confidence=confidence)
