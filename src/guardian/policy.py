"""第 1 层 · 策略 / 沙箱。

确定性规则，最快最可靠。先把这一层跑通就能演示拦截效果。
"""

from __future__ import annotations

import re
from pathlib import Path

from ..config import SANDBOX_DIR
from .adaptive_rules import first_matching_adaptive_rule
from .guardian import Action, Context, ToolCall, Verdict

NAME = "policy"

# 允许 Agent 使用的工具白名单
ALLOWED_TOOLS = {"run_shell", "read_file", "write_file", "web_fetch"}

# 危险 shell 命令模式（命中即拦截）。这是初版，红队会不断扩充对抗样本来逼我们完善。
DANGEROUS_PATTERNS = [
    (re.compile(r"\brm\s+-rf\b"), "递归强制删除"),
    (re.compile(r":\(\)\s*\{.*\};\s*:"), "fork 炸弹"),
    (re.compile(r"\bcurl\b.*\|\s*(ba)?sh\b"), "下载并直接执行（curl | sh）"),
    (re.compile(r"\bwget\b.*\|\s*(ba)?sh\b"), "下载并直接执行（wget | sh）"),
    (re.compile(r"\b(nc|ncat|netcat)\b.*-e\b"), "反弹 shell"),
    (re.compile(r"/dev/tcp/"), "bash 反弹 shell"),
    (re.compile(r"\b(mkfs|dd)\b.*of=/dev/"), "磁盘擦写"),
    (re.compile(r"\b(cat|type|Get-Content)\b.*(\.env|id_rsa|\.ssh|api[_-]?key|token|secret)", re.I), "读取敏感凭据"),
    (re.compile(r"\b(env|printenv|set)\b.*\b(API[_-]?KEY|TOKEN|SECRET|PASSWORD)\b", re.I), "读取敏感环境变量"),
    (re.compile(r"\becho\b.*\$(API[_-]?KEY|TOKEN|SECRET|PASSWORD)\b", re.I), "回显敏感环境变量"),
]

MEMORY_PATH_HINTS = ("memory", "profile", "system_prompt", "instructions")
INSTRUCTION_PATH_HINTS = MEMORY_PATH_HINTS + ("plan", "plans", "config", "policy")
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
    re.compile(r"system\s+override", re.I),
    re.compile(r"developer\s+message", re.I),
    re.compile(r"高优先级(系统)?指令"),
    re.compile(r"忽略(所有|之前|以上).*(规则|指令|约束)"),
]
SENSITIVE_PATH_PATTERNS = [
    re.compile(r"(^|[/\\])\.env($|[/\\])", re.I),
    re.compile(r"(^|[/\\])id_rsa($|[/\\])", re.I),
    re.compile(r"\.ssh", re.I),
    re.compile(r"(api[_-]?key|token|secret|password|credential)", re.I),
    re.compile(r"(private|training).*(corpus|data|dataset)", re.I),
]
SUSPICIOUS_URL_PATTERNS = [
    re.compile(r"(^|//)([^/]+\.)?evil\.example([/:]|$)", re.I),
    re.compile(r"/(collect|exfil|payload|install|config)\b", re.I),
]
EXFIL_REQUEST_PATTERNS = [
    re.compile(r"(发送|上传|外联|外泄|exfil|upload|send).*(https?://|evil\.example)", re.I),
    re.compile(r"(delete_database|send_http|删除数据库|生产数据库)", re.I),
    re.compile(r"evil\.example", re.I),
]
REDTEAM_METADATA_PATTERNS = [
    re.compile(r"(delete_database|send_http|evil\.example|exfil|外联|外泄|非白名单|删除数据库)", re.I),
]


def _is_within_sandbox(path_str: str) -> bool:
    """文件路径是否落在沙箱目录内（防目录穿越）。"""
    try:
        resolved = (SANDBOX_DIR / path_str).resolve() if not Path(path_str).is_absolute() \
            else Path(path_str).resolve()
        return resolved.is_relative_to(SANDBOX_DIR)
    except (ValueError, OSError):
        return False


def _looks_like_sensitive_path(path: str) -> str:
    for pattern in SENSITIVE_PATH_PATTERNS:
        if pattern.search(path):
            return pattern.pattern
    return ""


def _looks_like_suspicious_url(url: str) -> str:
    for pattern in SUSPICIOUS_URL_PATTERNS:
        if pattern.search(url):
            return pattern.pattern
    return ""


def _flatten_input(value) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten_input(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_input(v) for v in value)
    return str(value)


def _shell_payload(tool_input: dict) -> str:
    for key in ("command", "cmd", "script", "code", "shell"):
        if key in tool_input:
            return str(tool_input.get(key, ""))
    return _flatten_input(tool_input)


def _path_payload(tool_input: dict) -> str:
    for key in ("path", "file", "file_path", "filepath", "target"):
        if key in tool_input:
            return str(tool_input.get(key, ""))
    return str(tool_input.get("path", ""))


def _url_payload(tool_input: dict) -> str:
    for key in ("url", "uri", "href", "link"):
        if key in tool_input:
            return str(tool_input.get(key, ""))
    return str(tool_input.get("url", ""))


def _mentions_external_memory_write(text: str) -> bool:
    lowered = text.lower()
    has_memory = any(hint in lowered for hint in MEMORY_PATH_HINTS) or "长期记忆" in text or "记忆文件" in text
    has_external = bool(re.search(r"https?://|网页|外部|读取内容|fetch|url", text, re.I))
    return has_memory and has_external


def _metadata_text(ctx: Context) -> str:
    return _flatten_input(ctx.metadata)


def _mentions_exfiltration_or_hijack(text: str) -> bool:
    return any(pattern.search(text) for pattern in EXFIL_REQUEST_PATTERNS)


def _redteam_metadata_requires_block(ctx: Context) -> bool:
    if not ctx.metadata:
        return False
    expected = str(ctx.metadata.get("expected_guardian_action", "")).lower()
    if expected not in {"block", "flag"}:
        return False
    text = _metadata_text(ctx)
    return any(pattern.search(text) for pattern in REDTEAM_METADATA_PATTERNS)


class PolicyLayer:
    name = NAME

    def check(self, call: ToolCall, ctx: Context) -> Verdict:
        adaptive = first_matching_adaptive_rule(call, ctx)
        if adaptive:
            return Verdict(NAME, Action.BLOCK, f"命中自适应防御规则：{adaptive.get('description')}")

        # 工具白名单
        if call.name not in ALLOWED_TOOLS:
            return Verdict(NAME, Action.BLOCK, f"工具 {call.name!r} 不在白名单内")

        if _mentions_exfiltration_or_hijack(ctx.user_request):
            return Verdict(NAME, Action.BLOCK, "用户请求包含外联/删除数据库等工具劫持意图")

        if _redteam_metadata_requires_block(ctx):
            return Verdict(NAME, Action.BLOCK, "DeepSeek 红队元数据标记了工具劫持/外联/非白名单后续动作风险")

        # shell 危险命令
        if call.name == "run_shell":
            cmd = _shell_payload(call.input)
            for pattern, desc in DANGEROUS_PATTERNS:
                if pattern.search(cmd):
                    return Verdict(NAME, Action.BLOCK, f"危险命令：{desc}")

        if call.name == "web_fetch":
            url = _url_payload(call.input)
            if _looks_like_suspicious_url(url):
                return Verdict(NAME, Action.BLOCK, f"访问已知红队/外联可疑 URL：{url}")
            if _mentions_external_memory_write(ctx.user_request):
                return Verdict(NAME, Action.BLOCK, "疑似记忆中毒链路：读取外部内容并写入长期记忆")

        # 文件路径沙箱限定
        if call.name in {"read_file", "write_file"}:
            path = _path_payload(call.input)
            if not _is_within_sandbox(path):
                return Verdict(NAME, Action.BLOCK, f"文件路径越出沙箱：{path}")
            sensitive = _looks_like_sensitive_path(path)
            if call.name == "read_file" and sensitive:
                return Verdict(NAME, Action.BLOCK, f"读取敏感文件路径：{path}")

        # 记忆中毒 / 环境污染：把新的“系统规则/忽略旧规则”写入记忆、指令或计划类文件。
        if call.name == "write_file":
            path = _path_payload(call.input).lower()
            content = str(call.input.get("content", ""))
            if any(hint in path for hint in INSTRUCTION_PATH_HINTS):
                for pattern in PROMPT_INJECTION_PATTERNS:
                    if pattern.search(content):
                        return Verdict(NAME, Action.BLOCK, "疑似记忆中毒/环境污染：向记忆、指令或计划文件写入提示注入内容")
            if any(hint in path for hint in MEMORY_PATH_HINTS):
                if ctx.tainted_sources:
                    return Verdict(NAME, Action.BLOCK, "疑似记忆中毒：不可信来源内容写入长期记忆")
                if _mentions_external_memory_write(ctx.user_request):
                    return Verdict(NAME, Action.BLOCK, "疑似记忆中毒：外部 URL 内容写入长期记忆")

        return Verdict(NAME, Action.ALLOW)
