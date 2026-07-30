"""第 4 层 · 序列异常。

对工具调用序列建模，抓突然提权、异常循环、罕见调用链。

实现要点：
  - v1：简单启发式——同一工具短时间高频重复 → FLAG；
  - v2：可替换为 n-gram / Markov / 轨迹模型，计算当前调用的“惊讶度”。

本层的价值不是替代前三层，而是覆盖“单次调用看似正常，但调用序列异常”的行为。
"""

from __future__ import annotations

import re

from .guardian import Action, Context, ToolCall, Verdict

NAME = "anomaly"

# 同一工具连续重复超过这么多次就告警（疑似死循环）。
REPEAT_THRESHOLD = 5

# 第 4 层关注“当前调用放在运行时请求、污点和历史序列里是否异常”。这些关键词不直接替代
# PolicyLayer 的硬规则，而是用于识别可观察的攻击链线索和异常跳转。
ATTACK_CHAIN_PATTERNS = [
    re.compile(r"(delete_database|send_http|evil\.example|exfil|外联|外泄|上传|发送到)", re.I),
    re.compile(r"(非白名单|删除数据库|生产数据库|敏感数据|敏感日志)", re.I),
    re.compile(r"(ignore\s+previous|system\s+override|高优先级指令|忽略.*指令)", re.I),
    re.compile(r"(rm\s+-rf|curl\s+.*\|\s*(ba)?sh|powershell\s+.*-enc)", re.I),
]

READ_TOOLS = {"read_file", "web_fetch"}
HIGH_IMPACT_TOOLS = {"run_shell", "write_file"}
EXFIL_CHAIN_HINTS = re.compile(r"(evil\.example|exfil|外联|外泄|上传|发送到|send_http)", re.I)
SENSITIVE_READ_HINTS = re.compile(r"(/var/log|syslog|\.env|id_rsa|secret|token|api[_-]?key|private|training)", re.I)


def _flatten(value) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten(v) for v in value)
    return str(value)


def _context_text(ctx: Context) -> str:
    fragments = " ".join(fragment.text for fragment in ctx.tainted_fragments)
    return " ".join([
        ctx.user_request,
        " ".join(sorted(ctx.tainted_sources)),
        fragments,
    ])


def _matches_attack_chain(text: str) -> bool:
    return any(pattern.search(text) for pattern in ATTACK_CHAIN_PATTERNS)


def _recent_read_or_fetch_count(ctx: Context, window: int = 4) -> int:
    return sum(1 for item in ctx.history[-window:] if item.name in READ_TOOLS)


class AnomalyLayer:
    name = NAME

    def check(self, call: ToolCall, ctx: Context) -> Verdict:
        """用历史工具序列判断当前调用是否异常。

        本层现在包含三类可解释启发式：
        - 同一工具连续重复，说明 Agent 可能进入异常循环；
        - 读取或抓取动作和运行时请求中的外联线索组合成数据外泄攻击链；
        - 读取或网页抓取后突然跳到高影响工具，属于序列提权/意图漂移。
        """
        context_text = _context_text(ctx)
        call_text = _flatten(call.input)

        if call.name in READ_TOOLS and EXFIL_CHAIN_HINTS.search(context_text):
            confidence = 0.82 if SENSITIVE_READ_HINTS.search(f"{context_text} {call_text}") else 0.72
            return Verdict(
                NAME,
                Action.BLOCK,
                "读取/抓取动作与外联目标同时出现，疑似数据外泄攻击链前序步骤",
                confidence=confidence,
            )

        if call.name in HIGH_IMPACT_TOOLS and (_recent_read_or_fetch_count(ctx) >= 2 or ctx.tainted_sources):
            action = Action.BLOCK if _matches_attack_chain(f"{context_text} {call_text}") else Action.FLAG
            return Verdict(
                NAME,
                action,
                "读取/抓取之后跳转到高影响工具，疑似序列提权或间接提示注入",
                confidence=0.74 if action == Action.BLOCK else 0.62,
            )

        recent = [c.name for c in ctx.history[-REPEAT_THRESHOLD:]]
        if len(recent) == REPEAT_THRESHOLD and all(n == call.name for n in recent):
            return Verdict(
                NAME, Action.FLAG,
                f"工具 {call.name!r} 连续重复调用，疑似异常循环",
                confidence=0.6,
            )
        return Verdict(NAME, Action.ALLOW)
