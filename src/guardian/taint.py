"""第 2 层 · 数据来源污点追踪（项目原创核心）。

思路：给来自不可信源（web_fetch 返回、read_file 内容、工具返回）的文本打污点标记；
当某次高权限动作（写文件、跑 shell、外联）是"被污点数据触发"时，拦截或要求二次确认。
这是防御【间接提示注入】的关键机制。

实现要点（待 B 同学填充）：
  - 在 agent 侧，工具返回内容入模型前先登记到 ctx.tainted_sources；
  - 这里判断当前 call 是否在"读取污点内容之后"发起的高权限动作，并结合参数内容做关联。
  - 进阶：做真正的数据流跟踪（污点是否流入了 call.input），而非仅时序启发式。
"""

from __future__ import annotations

from .guardian import Action, Context, ToolCall, Verdict

NAME = "taint"

# 视为"高权限"的工具：被污点数据触发时需要拦截/确认
HIGH_PRIVILEGE_TOOLS = {"run_shell", "write_file"}


class TaintLayer:
    name = NAME

    def check(self, call: ToolCall, ctx: Context) -> Verdict:
        # TODO(B): 实现污点传播判定。
        #   v1（时序启发式）：若 ctx 中存在污点来源，且本次是高权限工具 → FLAG。
        #   v2（数据流）：检查污点文本是否实际出现在 call.input 中 → BLOCK。
        if ctx.tainted_sources and call.name in HIGH_PRIVILEGE_TOOLS:
            return Verdict(
                NAME, Action.FLAG,
                f"高权限动作发生在读取不可信内容之后（来源：{', '.join(ctx.tainted_sources)}）",
                confidence=0.5,
            )
        return Verdict(NAME, Action.ALLOW)
