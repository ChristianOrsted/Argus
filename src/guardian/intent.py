"""第 3 层 · 意图一致性校验（LLM-judge）。

用一次独立的 Claude 调用判断："这次工具调用是否符合用户最初的真实意图？"
抓【工具调用劫持 / 意图漂移】。

实现要点（待 B 同学填充）：
  - 把 ctx.user_request + 当前 call 拼成 prompt，让 judge 输出 {consistent: bool, reason}；
  - 用 structured outputs（output_config.format）拿到稳定 JSON；
  - 复杂判断可开 thinking={"type": "adaptive"}；
  - 为省钱可缓存/批量，或仅对高权限工具触发本层。
"""

from __future__ import annotations

from ..config import JUDGE_MODEL
from .guardian import Action, Context, ToolCall, Verdict

NAME = "intent"


class IntentLayer:
    name = NAME

    def __init__(self, client=None, model: str = JUDGE_MODEL):
        # client 注入便于测试时 mock；正式运行传入 anthropic.Anthropic()
        self.client = client
        self.model = model

    def check(self, call: ToolCall, ctx: Context) -> Verdict:
        if self.client is None:
            # 未接入模型时不阻断流程，便于先跑通其它层
            return Verdict(NAME, Action.ALLOW, "intent layer 未启用（无 client）")

        # TODO(B): 调用 self.client.messages.create(...) 让 judge 评估一致性。
        # 参考 docs/architecture.md 第 5 节与 README 的快速开始。
        return Verdict(NAME, Action.ALLOW, "TODO: 接入 LLM-judge")
