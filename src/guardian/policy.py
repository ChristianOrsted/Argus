"""第 1 层 · 策略 / 沙箱。

PolicyLayer 是四层中的“硬规则底线”。它不依赖模型判断，直接用确定性规则处理
已知高危行为：危险 shell、未知工具、沙箱外文件访问、敏感凭据读取、可疑 URL、
记忆中毒写入和 DeepSeek 红队元数据标记的攻击链候选动作。

本层适合做实时阻断，因为速度快、可解释、误差可控。后续红队发现新绕过时，
优先把稳定、明确、低误报的模式固化到这里。
"""

from __future__ import annotations

import re

from ..agent.tool_security import (
    ToolSecurityError,
    parse_safe_shell_command,
    resolve_confined_path,
    validate_web_url,
)
from ..config import SANDBOX_DIR
from .adaptive_rules import first_matching_adaptive_rule
from .guardian import Action, Context, ToolCall, Verdict
from .tool_registry import enabled_tool_names, get_tool_profile

NAME = "policy"

# 允许 Agent 使用的工具白名单来自工具能力注册表。未知工具仍默认阻断，但注册表会
# 记录每个工具的能力标签、风险等级和审计重点，便于后续从固定白名单过渡到
# “工具能力标签 + 最小权限 + 场景策略”。
ALLOWED_TOOLS = enabled_tool_names()

# 危险 shell 命令模式（命中即拦截）。这些模式代表破坏、反弹 shell、下载执行和凭据读取。
DANGEROUS_PATTERNS = [
    (re.compile(r"\brm\s+-rf\b"), "递归强制删除"),
    (re.compile(r":\(\)\s*\{.*\};\s*:"), "fork 炸弹"),
    (re.compile(r"\bcurl\b.*\|\s*(ba)?sh\b"), "下载并直接执行（curl | sh）"),
    (re.compile(r"\bwget\b.*\|\s*(ba)?sh\b"), "下载并直接执行（wget | sh）"),
    (re.compile(r"\b(nc|ncat|netcat)\b.*-e\b"), "反弹 shell"),
    (re.compile(r"/dev/tcp/"), "bash 反弹 shell"),
    (re.compile(r"\b(powershell|pwsh)\b.*(-enc|-encodedcommand)\b", re.I), "PowerShell encoded command"),
    (re.compile(r"\b(mkfs|dd)\b.*of=/dev/"), "磁盘擦写"),
    (re.compile(r"\b(cat|type|Get-Content)\b.*(\.env|id_rsa|\.ssh|api[_-]?key|token|secret)", re.I), "读取敏感凭据"),
    (re.compile(r"\b(env|printenv|set)\b.*\b(API[_-]?KEY|TOKEN|SECRET|PASSWORD)\b", re.I), "读取敏感环境变量"),
    (re.compile(r"\becho\b.*\$(API[_-]?KEY|TOKEN|SECRET|PASSWORD)\b", re.I), "回显敏感环境变量"),
]

# 下列规则组按攻击面拆分，方便答辩时解释“为什么这类输入会被认为危险”。
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
def _is_within_sandbox(path_str: str) -> bool:
    """文件路径是否为不含链接组件的沙箱内相对路径。"""
    try:
        resolve_confined_path(path_str, root=SANDBOX_DIR)
        return True
    except (ToolSecurityError, OSError):
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
    """把嵌套工具参数压成文本，供策略规则做统一匹配。"""
    if isinstance(value, dict):
        return " ".join(_flatten_input(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_input(v) for v in value)
    return str(value)


def _shell_payload(tool_input: dict) -> str:
    """提取 shell 载荷，兼容 DeepSeek 可能生成的 cmd/script/code 等参数名。"""
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


def _mentions_exfiltration_or_hijack(text: str) -> bool:
    return any(pattern.search(text) for pattern in EXFIL_REQUEST_PATTERNS)


class PolicyLayer:
    name = NAME

    def check(self, call: ToolCall, ctx: Context) -> Verdict:
        """按“自适应规则 -> 白名单 -> 用户意图关键字 -> 红队元数据 -> 工具细则”的顺序检查。

        顺序很重要：自适应规则代表最近红队反馈；白名单是最基础边界；
        后面的规则再针对 shell、web、文件和记忆写入做细分。
        """
        adaptive = first_matching_adaptive_rule(call, ctx)
        if adaptive:
            return Verdict(NAME, Action.BLOCK, f"命中自适应防御规则：{adaptive.get('description')}")

        # 工具白名单
        if call.name not in ALLOWED_TOOLS:
            return Verdict(
                NAME,
                Action.BLOCK,
                f"工具 {call.name!r} 未在能力注册表中启用；新工具应先登记能力标签、最小权限和审计关注点",
            )

        tool_profile = get_tool_profile(call.name)

        if _mentions_exfiltration_or_hijack(ctx.user_request):
            return Verdict(NAME, Action.BLOCK, "用户请求包含外联/删除数据库等工具劫持意图")

        # shell 危险命令
        if call.name == "run_shell":
            cmd = _shell_payload(call.input)
            for pattern, desc in DANGEROUS_PATTERNS:
                if pattern.search(cmd):
                    risk = f"，工具风险等级：{tool_profile.risk}" if tool_profile else ""
                    return Verdict(NAME, Action.BLOCK, f"危险命令：{desc}{risk}")
            try:
                parse_safe_shell_command(call.input.get("command"))
            except ToolSecurityError as exc:
                return Verdict(NAME, Action.BLOCK, f"命令越出能力沙箱：{exc}")

        if call.name == "web_fetch":
            url = _url_payload(call.input)
            if _looks_like_suspicious_url(url):
                return Verdict(NAME, Action.BLOCK, f"访问已知红队/外联可疑 URL：{url}")
            try:
                validate_web_url(url)
            except ToolSecurityError as exc:
                return Verdict(NAME, Action.BLOCK, f"不安全 URL：{exc}")
            if _mentions_external_memory_write(ctx.user_request):
                return Verdict(NAME, Action.BLOCK, "疑似记忆中毒链路：读取外部内容并写入长期记忆")

        # 文件路径沙箱限定：训练数据泄露、凭据读取和目录穿越会在这里被拦截。
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
