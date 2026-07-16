"""第 4 层 · 序列异常。

对工具调用序列建模，抓突然提权、异常循环、罕见调用链。

实现要点：
  - v1：简单启发式——同一工具短时间高频重复 → FLAG；
  - v2：可替换为 n-gram / Markov / 轨迹模型，计算当前调用的“惊讶度”。

本层的价值不是替代前三层，而是覆盖“单次调用看似正常，但调用序列异常”的行为。
"""

from __future__ import annotations

from .guardian import Action, Context, ToolCall, Verdict

NAME = "anomaly"

# v1 简单阈值：同一工具连续重复超过这么多次就告警（疑似死循环）
REPEAT_THRESHOLD = 5


class AnomalyLayer:
    name = NAME

    def check(self, call: ToolCall, ctx: Context) -> Verdict:
        """用历史工具序列判断当前调用是否异常。

        当前版本先保留可解释的重复调用检测，确保接口、前端展示和测试链路稳定；
        后续 C/D 优化时可以在这里替换为基于真实 Agent 轨迹的序列模型。
        """
        recent = [c.name for c in ctx.history[-REPEAT_THRESHOLD:]]
        if len(recent) == REPEAT_THRESHOLD and all(n == call.name for n in recent):
            return Verdict(
                NAME, Action.FLAG,
                f"工具 {call.name!r} 连续重复调用，疑似异常循环",
                confidence=0.6,
            )
        return Verdict(NAME, Action.ALLOW)
