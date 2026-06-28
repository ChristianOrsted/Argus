"""Guardian 核心：共享数据类型 + 四层编排器。

设计见 docs/architecture.md 第 3 节。每一层实现 `Layer.check(call, ctx) -> Verdict`，
Guardian 汇总所有层的 Verdict 得到最终 Decision。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol


class Action(str, Enum):
    ALLOW = "allow"   # 放行
    BLOCK = "block"   # 拦截（高危）
    FLAG = "flag"     # 可疑，告警但不一定拦截


@dataclass
class ToolCall:
    """Agent 发起的一次工具调用。"""

    name: str                       # 工具名，如 run_shell / read_file / web_fetch
    input: dict[str, Any]           # 工具参数
    tool_use_id: str = ""           # 对应 Claude 响应里的 tool_use block id


@dataclass
class Context:
    """本轮会话上下文，供各层判断使用。"""

    user_request: str                         # 用户最初的真实指令
    history: list[ToolCall] = field(default_factory=list)   # 已发生的工具调用序列
    tainted_sources: set[str] = field(default_factory=set)  # 已知的污点来源标记（见 taint 层）


@dataclass
class Verdict:
    """单层结论。"""

    layer: str
    action: Action
    reason: str = ""
    confidence: float = 1.0


@dataclass
class Decision:
    """Guardian 汇总后的最终决定。"""

    action: Action
    reason: str
    verdicts: list[Verdict] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action == Action.BLOCK


class Layer(Protocol):
    """所有防御层的统一接口。"""

    name: str

    def check(self, call: ToolCall, ctx: Context) -> Verdict:
        ...


class Guardian:
    """编排四层防御，汇总成最终 Decision。"""

    def __init__(self, layers: list[Layer]):
        self.layers = layers

    def evaluate(self, call: ToolCall, ctx: Context) -> Decision:
        verdicts = [layer.check(call, ctx) for layer in self.layers]

        # 汇总策略：任一层 BLOCK 即 BLOCK；否则有 FLAG 则 FLAG；全 ALLOW 才 ALLOW。
        blocking = [v for v in verdicts if v.action == Action.BLOCK]
        if blocking:
            reason = "; ".join(f"[{v.layer}] {v.reason}" for v in blocking)
            return Decision(Action.BLOCK, reason, verdicts)

        flags = [v for v in verdicts if v.action == Action.FLAG]
        if flags:
            reason = "; ".join(f"[{v.layer}] {v.reason}" for v in flags)
            return Decision(Action.FLAG, reason, verdicts)

        return Decision(Action.ALLOW, "all layers passed", verdicts)
