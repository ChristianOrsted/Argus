"""Agent 可用的工具：Claude tool 定义 + 本地执行实现。

这些工具会真实执行（沙箱内），所以才需要 Guardian 监督。执行实现要尽量贴近真实，
但默认限定在 SANDBOX_DIR 内，避免误伤开发机。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from ..config import SANDBOX_DIR

# ---- 给 Claude 的工具 schema（messages.create 的 tools 参数）----
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

# 经过 Guardian 后才会被工具返回标记为"不可信源"的工具（供污点层登记）
UNTRUSTED_SOURCE_TOOLS = {"web_fetch", "read_file"}


def execute_tool(name: str, tool_input: dict) -> str:
    """真正执行工具。注意：调用方应在 Guardian 放行后才调用本函数。"""
    if name == "run_shell":
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
        # TODO(A): 用 requests/httpx 真正抓取；demo 阶段可返回固定内容或本地 fixture。
        return f"(TODO: 抓取 {tool_input['url']} 的内容)"

    return f"未知工具：{name}"
