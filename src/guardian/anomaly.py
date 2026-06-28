"""第 4 层 · 序列异常。

对工具调用序列建模，抓突然提权、异常循环、罕见调用链。

实现要点（待 C 同学填充）：
  - v1：简单启发式——同一工具短时间高频重复、调用链长度异常 → FLAG。
  - v2：在良性调用序列上训练 n-gram / Markov，算当前调用的"惊讶度"。
"""

from __future__ import annotations

from .guardian import Action, Context, ToolCall, Verdict

NAME = "anomaly"

# v1 简单阈值：同一工具连续重复超过这么多次就告警（疑似死循环）
REPEAT_THRESHOLD = 5


class AnomalyLayer:
    name = NAME

    def check(self, call: ToolCall, ctx: Context) -> Verdict:
        # TODO(C): 替换为序列模型。下面是占位的简单循环检测。
        recent = [c.name for c in ctx.history[-REPEAT_THRESHOLD:]]
        if len(recent) == REPEAT_THRESHOLD and all(n == call.name for n in recent):
            return Verdict(
                NAME, Action.FLAG,
                f"工具 {call.name!r} 连续重复调用，疑似异常循环",
                confidence=0.6,
            )
        return Verdict(NAME, Action.ALLOW)
