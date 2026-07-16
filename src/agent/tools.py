"""Agent 可用的工具：Claude tool 定义 + 本地执行实现。

这些工具会真实执行（沙箱内），所以才需要 Guardian 监督。执行实现要尽量贴近真实，
但默认限定在 SANDBOX_DIR 内，避免误伤开发机。
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from urllib.request import Request, urlopen

from ..config import FIXTURE_DIR, SANDBOX_DIR

# ---- 给 Claude 的工具 schema（messages.create 的 tools 参数）----
# 这些 schema 描述 Agent 能“提出”的工具调用；是否真正执行由 Guardian 决定。
TOOLS = [
    {
        "name": "run_shell",
        "description": "在沙箱中执行一条 shell 命令并返回输出。",
        "input_schema": {
            "type": "object",
            "properties": {"command": {"type": "string", "description": "要执行的命令"}},
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": "读取沙箱内一个文件的文本内容。",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "相对沙箱目录的路径"}},
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "向沙箱内一个文件写入文本内容。",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "web_fetch",
        "description": "抓取一个 URL 的文本内容。注意：返回内容来自外部，是不可信源。",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
]

# DeepSeek 使用 OpenAI-compatible tool calling 格式。
OPENAI_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": tool["name"],
            "description": tool["description"],
            "parameters": tool["input_schema"],
        },
    }
    for tool in TOOLS
]

# 经过 Guardian 后才会被工具返回标记为"不可信源"的工具（供污点层登记）
UNTRUSTED_SOURCE_TOOLS = {"web_fetch", "read_file"}


def execute_tool(name: str, tool_input: dict) -> str:
    """真正执行工具。注意：调用方应在 Guardian 放行后才调用本函数。

    工具执行层尽量保持简单真实：shell 会在沙箱目录运行，文件读写限制在沙箱路径，
    `fixture://` 用于离线复现间接提示注入，真实 http(s) 抓取用于在线演示。
    """
    if name == "run_shell":
        # 高危工具：命令执行能力最强，所以 Policy/Taint/Intent 都会重点审计它。
        proc = subprocess.run(
            tool_input["command"], shell=True, capture_output=True, text=True,
            cwd=SANDBOX_DIR, timeout=30,
        )
        return (proc.stdout + proc.stderr).strip() or "(无输出)"

    if name == "read_file":
        p = (SANDBOX_DIR / tool_input["path"]).resolve()
        return p.read_text(encoding="utf-8", errors="replace")

    if name == "write_file":
        p = (SANDBOX_DIR / tool_input["path"]).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(tool_input["content"], encoding="utf-8")
        return f"已写入 {p}"

    if name == "web_fetch":
        url = str(tool_input["url"])
        if url.startswith("fixture://"):
            # 离线 fixture 让课程演示不依赖真实恶意网页，也便于稳定测试。
            fixture_name = url.removeprefix("fixture://").lstrip("/\\")
            p = (FIXTURE_DIR / fixture_name).resolve()
            if not p.is_relative_to(FIXTURE_DIR.resolve()):
                return f"fixture 路径越界：{fixture_name}"
            return p.read_text(encoding="utf-8", errors="replace")

        if url.startswith(("http://", "https://")):
            req = Request(url, headers={"User-Agent": "ArgusGuardian/0.1"})
            with urlopen(req, timeout=10) as resp:
                body = resp.read(20000)
                charset = resp.headers.get_content_charset() or "utf-8"
            return body.decode(charset, errors="replace")

        return f"不支持的 URL 协议：{url}"

    return f"未知工具：{name}"
