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

import re

from .guardian import Action, Context, ToolCall, Verdict

NAME = "taint"

# 视为"高权限"的工具：被污点数据触发时需要拦截/确认
HIGH_PRIVILEGE_TOOLS = {"run_shell", "write_file"}

TAINTED_SINK_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I), "注入文本要求忽略原指令"),
    (re.compile(r"\b(curl|wget)\b.*\|\s*(ba)?sh\b", re.I), "污点内容诱导下载并执行"),
    (re.compile(r"\brm\s+-rf\b", re.I), "污点内容诱导破坏性删除"),
    (re.compile(r"\b(id_rsa|api[_-]?key|token|secret)\b", re.I), "污点内容诱导处理敏感凭据"),
    (re.compile(r"\b(powershell|pwsh)\b.*(-enc|-encodedcommand)\b", re.I), "污点内容诱导编码命令执行"),
]


def _flatten_input(value) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten_input(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_input(v) for v in value)
    return str(value)


class TaintLayer:
    name = NAME

    def check(self, call: ToolCall, ctx: Context) -> Verdict:
        if ctx.tainted_sources and call.name in HIGH_PRIVILEGE_TOOLS:
            payload = _flatten_input(call.input)
            for pattern, desc in TAINTED_SINK_PATTERNS:
                if pattern.search(payload):
                    return Verdict(
                        NAME, Action.BLOCK,
                        f"疑似污点数据流入高权限动作：{desc}（来源：{', '.join(sorted(ctx.tainted_sources))}）",
                        confidence=0.8,
                    )
            return Verdict(
                NAME, Action.FLAG,
                f"高权限动作发生在读取不可信内容之后（来源：{', '.join(sorted(ctx.tainted_sources))}）",
                confidence=0.5,
            )
        return Verdict(NAME, Action.ALLOW)
