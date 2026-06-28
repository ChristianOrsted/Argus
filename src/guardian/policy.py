"""第 1 层 · 策略 / 沙箱。

确定性规则，最快最可靠。先把这一层跑通就能演示拦截效果。
"""

from __future__ import annotations

import re
from pathlib import Path

from ..config import SANDBOX_DIR
from .guardian import Action, Context, ToolCall, Verdict

NAME = "policy"

# 允许 Agent 使用的工具白名单
ALLOWED_TOOLS = {"run_shell", "read_file", "write_file", "web_fetch"}

# 危险 shell 命令模式（命中即拦截）。这是初版，红队会不断扩充对抗样本来逼我们完善。
DANGEROUS_PATTERNS = [
    (re.compile(r"\brm\s+-rf\b"), "递归强制删除"),
    (re.compile(r":\(\)\s*\{.*\};\s*:"), "fork 炸弹"),
    (re.compile(r"\bcurl\b.*\|\s*(ba)?sh\b"), "下载并直接执行（curl | sh）"),
    (re.compile(r"\b(nc|ncat|netcat)\b.*-e\b"), "反弹 shell"),
    (re.compile(r"/dev/tcp/"), "bash 反弹 shell"),
    (re.compile(r"\b(mkfs|dd)\b.*of=/dev/"), "磁盘擦写"),
]


def _is_within_sandbox(path_str: str) -> bool:
    """文件路径是否落在沙箱目录内（防目录穿越）。"""
    try:
        resolved = (SANDBOX_DIR / path_str).resolve() if not Path(path_str).is_absolute() \
            else Path(path_str).resolve()
        return resolved.is_relative_to(SANDBOX_DIR)
    except (ValueError, OSError):
        return False


class PolicyLayer:
    name = NAME

    def check(self, call: ToolCall, ctx: Context) -> Verdict:
        # 工具白名单
        if call.name not in ALLOWED_TOOLS:
            return Verdict(NAME, Action.BLOCK, f"工具 {call.name!r} 不在白名单内")

        # shell 危险命令
        if call.name == "run_shell":
            cmd = str(call.input.get("command", ""))
            for pattern, desc in DANGEROUS_PATTERNS:
                if pattern.search(cmd):
                    return Verdict(NAME, Action.BLOCK, f"危险命令：{desc}")

        # 文件路径沙箱限定
        if call.name in {"read_file", "write_file"}:
            path = str(call.input.get("path", ""))
            if not _is_within_sandbox(path):
                return Verdict(NAME, Action.BLOCK, f"文件路径越出沙箱：{path}")

        return Verdict(NAME, Action.ALLOW)
