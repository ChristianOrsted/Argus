"""Guardian 核心：共享数据类型 + 四层编排器。

本文件是四层防御的公共接口层，不直接写具体安全规则，而是定义整个项目中
“一次工具调用如何被审计”的数据结构：

1. Agent 产生 `ToolCall`；
2. 调用前上下文被整理为 `Context`；
3. Policy/Taint/Intent/Anomaly 四层分别返回 `Verdict`；
4. `Guardian.evaluate` 汇总为最终 `Decision`。

这样做的好处是各层可以独立演进，但前端、测试、日志和 Agent 接入点都只依赖
这一套稳定协议。设计见 docs/architecture.md 和 docs/project_overview.md。
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
class TaintedFragment:
    """来自不可信工具输出的文本片段。"""

    source: str                     # 来源工具，如 web_fetch / read_file
    text: str                       # 被标记的具体片段
    digest: str = ""                # 片段摘要，便于审计时引用
    origin_tool_use_id: str = ""    # 产生该片段的工具调用 id


@dataclass
class Context:
    """本轮会话上下文，供各层判断使用。

    `Context` 是四层共享的信息总线：
    - PolicyLayer 读取 user_request / metadata 判断确定性风险；
    - TaintLayer 读取 tainted_sources / tainted_fragments 做数据流判断；
    - IntentLayer 使用 user_request 和当前 ToolCall 做语义一致性判断；
    - AnomalyLayer 使用 history 判断序列是否异常。
    """

    user_request: str                         # 用户最初的真实指令
    history: list[ToolCall] = field(default_factory=list)   # 已发生的工具调用序列
    tainted_sources: set[str] = field(default_factory=set)  # 已知的污点来源标记（见 taint 层）
    tainted_fragments: list[TaintedFragment] = field(default_factory=list)  # 片段级污点
    metadata: dict[str, Any] = field(default_factory=dict)  # 红队/前端传入的结构化上下文


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
    """编排四层防御，汇总成最终 Decision。

    Guardian 本身不关心某条规则如何写，只负责保证所有层都被调用，并把
    BLOCK / FLAG / ALLOW 的优先级统一起来。这也是 Dashboard 可以展示
    “总 / 1 / 2 / 3 / 4”的原因。
    """

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
