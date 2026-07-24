"""Agent 可用的工具：工具定义 + 默认拒绝的能力型执行沙箱。"""

from __future__ import annotations

from pathlib import Path

from ..config import FIXTURE_DIR, SANDBOX_DIR
from .safe_http import fetch_public_text
from .tool_security import (
    SandboxViolation,
    ToolSecurityError,
    parse_safe_shell_command,
    resolve_confined_path,
    validate_web_url,
)

MAX_FILE_BYTES = 64 * 1024
MAX_LIST_ENTRIES = 500

# ---- 给 Claude 的工具 schema（messages.create 的 tools 参数）----
TOOLS = [
    {
        "name": "run_shell",
        "description": "在能力沙箱中执行受限命令。仅支持 echo、pwd、ls/dir、cat/type，不会调用宿主 Shell。",
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


def _read_confined_text(path_value: object, root: Path = SANDBOX_DIR) -> str:
    path = resolve_confined_path(path_value, root=root)
    if not path.is_file():
        raise SandboxViolation(f"文件不存在或不是普通文件：{path_value}")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise SandboxViolation(f"文件超过 {MAX_FILE_BYTES} 字节上限：{path_value}")
    return path.read_text(encoding="utf-8", errors="replace")


def _write_confined_text(path_value: object, content_value: object) -> str:
    if not isinstance(content_value, str):
        raise SandboxViolation("content 必须是字符串")
    if len(content_value.encode("utf-8")) > MAX_FILE_BYTES:
        raise SandboxViolation(f"写入内容超过 {MAX_FILE_BYTES} 字节上限")

    path = resolve_confined_path(path_value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path = resolve_confined_path(path_value)
    path.write_text(content_value, encoding="utf-8")
    return f"已写入 {path}"


def _execute_capability_command(command_value: object) -> str:
    parsed = parse_safe_shell_command(command_value)
    if parsed.name == "echo":
        return " ".join(parsed.args)
    if parsed.name == "pwd":
        return str(SANDBOX_DIR)
    if parsed.name in {"ls", "dir"}:
        path = resolve_confined_path(parsed.args[0] if parsed.args else ".")
        if not path.is_dir():
            raise SandboxViolation(f"目录不存在：{parsed.args[0] if parsed.args else '.'}")
        entries = sorted(
            item.name + ("/" if item.is_dir() and not item.is_symlink() else "")
            for item in path.iterdir()
        )
        if len(entries) > MAX_LIST_ENTRIES:
            entries = entries[:MAX_LIST_ENTRIES] + [f"...（其余 {len(entries) - MAX_LIST_ENTRIES} 项已省略）"]
        return "\n".join(entries) or "(空目录)"
    if parsed.name in {"cat", "type"}:
        return _read_confined_text(parsed.args[0])
    raise SandboxViolation(f"未实现的能力命令：{parsed.name}")


def execute_tool(name: str, tool_input: dict) -> str:
    """执行工具；即使调用方绕过 Guardian，也不能越出执行器安全边界。"""

    if not isinstance(tool_input, dict):
        raise ToolSecurityError("工具参数必须是对象")

    if name == "run_shell":
        return _execute_capability_command(tool_input.get("command"))

    if name == "read_file":
        return _read_confined_text(tool_input.get("path"))

    if name == "write_file":
        return _write_confined_text(tool_input.get("path"), tool_input.get("content"))

    if name == "web_fetch":
        url_value = tool_input.get("url")
        endpoint = validate_web_url(url_value)
        url = endpoint.url
        if url.startswith("fixture://"):
            fixture_name = url.removeprefix("fixture://").lstrip("/\\")
            return _read_confined_text(fixture_name, root=FIXTURE_DIR)
        return fetch_public_text(url)

    raise ToolSecurityError(f"未知工具：{name}")
