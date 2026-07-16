"""第 2 层 · 数据来源污点追踪（项目原创核心）。

思路：给来自不可信源（web_fetch 返回、read_file 内容、工具返回）的文本打污点标记；
当某次高权限动作（写文件、跑 shell、外联）是"被污点数据触发"时，拦截或要求二次确认。
这是防御【间接提示注入】的关键机制。

实现要点：
  - 在 agent 侧，工具返回内容入模型前登记来源级和片段级污点；
  - 本层判断当前 call 是否在读取污点内容之后发起高权限动作；
  - 若具体不可信片段流入 call.input，则给出更强证据并按危险程度 FLAG/BLOCK。
"""

from __future__ import annotations

import hashlib
import re

from .guardian import Action, Context, TaintedFragment, ToolCall, Verdict

NAME = "taint"

# 视为"高权限"的工具：被污点数据触发时需要拦截/确认
HIGH_PRIVILEGE_TOOLS = {"run_shell", "write_file"}
HIGH_RISK_WRITE_PATH_HINTS = ("memory", "profile", "system_prompt", "instructions", "plan", "plans", "config", "policy")

TAINTED_SINK_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I), "注入文本要求忽略原指令"),
    (re.compile(r"\b(curl|wget)\b.*\|\s*(ba)?sh\b", re.I), "污点内容诱导下载并执行"),
    (re.compile(r"\brm\s+-rf\b", re.I), "污点内容诱导破坏性删除"),
    (re.compile(r"\b(id_rsa|api[_-]?key|token|secret)\b", re.I), "污点内容诱导处理敏感凭据"),
    (re.compile(r"\b(powershell|pwsh)\b.*(-enc|-encodedcommand)\b", re.I), "污点内容诱导编码命令执行"),
]

MAX_FRAGMENT_LEN = 300
MIN_FRAGMENT_LEN = 12
MAX_FRAGMENTS_PER_OUTPUT = 12


def _flatten_input(value) -> str:
    """把任意工具参数展平为文本，便于与不可信片段做包含匹配。"""
    if isinstance(value, dict):
        return " ".join(_flatten_input(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_input(v) for v in value)
    return str(value)


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().lower()


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:12]


def extract_tainted_fragments(
    source: str,
    output: str,
    origin_tool_use_id: str = "",
) -> list[TaintedFragment]:
    """从不可信输出中抽取可追踪片段。

    v1 采用可解释的片段策略：按非空行切分，优先保留命中危险 sink 的行，
    同时保留少量普通长行，方便后续识别“外部文本被复制进高权限动作”的数据流。
    这里没有直接做复杂语义匹配，是为了让审计证据能在前端和报告里清晰解释：
    “哪个来源的哪段文本流入了哪个工具参数”。
    """

    candidates: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if len(line) < MIN_FRAGMENT_LEN:
            continue
        candidates.append(line[:MAX_FRAGMENT_LEN])

    dangerous: list[str] = []
    normal: list[str] = []
    for line in candidates:
        if any(pattern.search(line) for pattern, _ in TAINTED_SINK_PATTERNS):
            dangerous.append(line)
        else:
            normal.append(line)

    selected: list[str] = []
    for line in dangerous + normal:
        normalized = _normalize(line)
        if normalized and normalized not in {_normalize(item) for item in selected}:
            selected.append(line)
        if len(selected) >= MAX_FRAGMENTS_PER_OUTPUT:
            break

    return [
        TaintedFragment(
            source=source,
            text=text,
            digest=_digest(text),
            origin_tool_use_id=origin_tool_use_id,
        )
        for text in selected
    ]


def register_tool_output_taint(ctx: Context, call: ToolCall, output: str) -> None:
    """登记某次不可信工具输出的来源级和片段级污点。"""

    ctx.tainted_sources.add(call.name)
    ctx.tainted_fragments.extend(
        extract_tainted_fragments(call.name, output, origin_tool_use_id=call.tool_use_id)
    )


def _fragment_matches_payload(fragment: TaintedFragment, payload: str) -> bool:
    fragment_norm = _normalize(fragment.text)
    payload_norm = _normalize(payload)
    if len(fragment_norm) < MIN_FRAGMENT_LEN:
        return False
    return fragment_norm in payload_norm


def _dangerous_text(text: str) -> str:
    for pattern, desc in TAINTED_SINK_PATTERNS:
        if pattern.search(text):
            return desc
    return ""


class TaintLayer:
    name = NAME

    def check(self, call: ToolCall, ctx: Context) -> Verdict:
        """检查不可信来源是否影响当前高权限动作。

        本层先看来源级污点：只要读取过网页/文件等不可信来源，再触发 shell 或写文件，
        就进入高风险审查。随后再看片段级污点：如果具体不可信片段出现在工具参数里，
        就能给出 digest 和来源作为证据。这样既能抓住间接提示注入，也能说明拦截原因。
        """
        if ctx.tainted_sources and call.name in HIGH_PRIVILEGE_TOOLS:
            payload = _flatten_input(call.input)
            write_path = str(call.input.get("path", "")).lower() if call.name == "write_file" else ""

            # 片段级证据：外部网页/文件中的文本被模型复制进当前高权限工具参数。
            fragment_matches = [
                fragment for fragment in ctx.tainted_fragments
                if _fragment_matches_payload(fragment, payload)
            ]
            if fragment_matches:
                for fragment in fragment_matches:
                    desc = _dangerous_text(fragment.text) or _dangerous_text(payload)
                    if desc:
                        return Verdict(
                            NAME, Action.BLOCK,
                            f"污点片段流入高权限动作：{desc}（片段={fragment.digest}, 来源={fragment.source}）",
                            confidence=0.9,
                        )
                evidence = ", ".join(f"{item.source}:{item.digest}" for item in fragment_matches[:3])
                return Verdict(
                    NAME, Action.FLAG,
                    f"检测到不可信文本片段流入高权限动作（{evidence}）",
                    confidence=0.7,
                )

            # 来源级证据：没有看到具体片段复制，但调用发生在不可信读取之后，仍需保守处理。
            desc = _dangerous_text(payload)
            if desc:
                return Verdict(
                    NAME, Action.BLOCK,
                    f"疑似污点数据流入高权限动作：{desc}（来源：{', '.join(sorted(ctx.tainted_sources))}）",
                    confidence=0.8,
                )
            if call.name == "run_shell":
                return Verdict(
                    NAME, Action.BLOCK,
                    f"不可信来源触发 shell 执行（来源：{', '.join(sorted(ctx.tainted_sources))}）",
                    confidence=0.85,
                )
            if call.name == "write_file" and any(hint in write_path for hint in HIGH_RISK_WRITE_PATH_HINTS):
                return Verdict(
                    NAME, Action.BLOCK,
                    f"不可信来源写入高风险持久化/计划文件：{write_path}（来源：{', '.join(sorted(ctx.tainted_sources))}）",
                    confidence=0.8,
                )
            return Verdict(
                NAME, Action.FLAG,
                f"高权限动作发生在读取不可信内容之后（来源：{', '.join(sorted(ctx.tainted_sources))}）",
                confidence=0.5,
            )
        return Verdict(NAME, Action.ALLOW)
