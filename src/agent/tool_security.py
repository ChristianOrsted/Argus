"""工具执行边界：路径沙箱、受限命令和公网 URL 校验。"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from ..config import SANDBOX_DIR

MAX_COMMAND_LEN = 4096
MAX_URL_LEN = 2048
ALLOWED_SHELL_COMMANDS = {"echo", "pwd", "ls", "dir", "cat", "type"}
SHELL_META_PATTERN = re.compile(r"[;&|<>`\r\n]")
LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
ALLOWED_WEB_PORTS = {80, 443}


class ToolSecurityError(ValueError):
    """工具输入违反执行边界。"""


class SandboxViolation(ToolSecurityError):
    """文件或命令试图越出能力沙箱。"""


class UnsafeURL(ToolSecurityError):
    """URL 可能访问本机、内网或其他受限目标。"""


@dataclass(frozen=True)
class ParsedShellCommand:
    name: str
    args: tuple[str, ...]


@dataclass(frozen=True)
class ValidatedURL:
    url: str
    scheme: str
    hostname: str
    port: int
    addresses: tuple[str, ...] = ()


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if is_junction and is_junction():
        return True
    if path.is_file() and path.stat().st_nlink > 1:
        return True
    return False


def resolve_confined_path(path_value: object, root: Path = SANDBOX_DIR) -> Path:
    """解析相对路径，并拒绝绝对路径、穿越和已有链接组件。"""

    text = str(path_value or "")
    if not text or "\x00" in text:
        raise SandboxViolation("文件路径为空或包含非法字符")

    relative = Path(text)
    if relative.is_absolute():
        raise SandboxViolation(f"不允许绝对路径：{text}")

    root = root.resolve()
    candidate = (root / relative).resolve(strict=False)
    try:
        relative_candidate = candidate.relative_to(root)
    except ValueError as exc:
        raise SandboxViolation(f"文件路径越出沙箱：{text}") from exc

    current = root
    for part in relative_candidate.parts:
        current /= part
        if current.exists():
            if _is_link_or_junction(current):
                raise SandboxViolation(f"路径包含链接、联接点或硬链接：{text}")
            if current != root and current.is_mount():
                raise SandboxViolation(f"路径包含额外挂载点：{text}")

    return candidate


def _split_shell(command: str) -> list[str]:
    tokens = shlex.split(command, posix=os.name != "nt")
    if os.name == "nt":
        tokens = [
            token[1:-1] if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"} else token
            for token in tokens
        ]
    return tokens


def parse_safe_shell_command(command_value: object) -> ParsedShellCommand:
    """把 shell 工具限制为几个内建能力，永不调用宿主 Shell。"""

    if not isinstance(command_value, str):
        raise SandboxViolation("command 必须是字符串")
    command = command_value.strip()
    if not command:
        raise SandboxViolation("command 不能为空")
    if len(command) > MAX_COMMAND_LEN:
        raise SandboxViolation("command 过长")
    if SHELL_META_PATTERN.search(command):
        raise SandboxViolation("禁止管道、重定向、命令连接符或命令替换")

    try:
        tokens = _split_shell(command)
    except ValueError as exc:
        raise SandboxViolation(f"命令引号无法解析：{exc}") from exc
    if not tokens:
        raise SandboxViolation("command 不能为空")

    name = tokens[0].lower()
    args = tuple(tokens[1:])
    if name not in ALLOWED_SHELL_COMMANDS:
        allowed = ", ".join(sorted(ALLOWED_SHELL_COMMANDS))
        raise SandboxViolation(f"命令 {name!r} 不在能力白名单内（允许：{allowed}）")

    if name == "pwd" and args:
        raise SandboxViolation("pwd 不接受参数")
    if name in {"ls", "dir"}:
        if len(args) > 1 or (args and args[0].startswith("-")):
            raise SandboxViolation(f"{name} 只接受一个沙箱内相对路径")
        if args:
            resolve_confined_path(args[0])
    if name in {"cat", "type"}:
        if len(args) != 1:
            raise SandboxViolation(f"{name} 必须且只能读取一个沙箱内文件")
        resolve_confined_path(args[0])

    return ParsedShellCommand(name=name, args=args)


def _require_global_address(address_text: str) -> str:
    try:
        address = ipaddress.ip_address(address_text)
    except ValueError as exc:
        raise UnsafeURL(f"无法解析目标 IP：{address_text}") from exc
    if not address.is_global:
        raise UnsafeURL(f"禁止访问非公网地址：{address.compressed}")
    return address.compressed


def _resolve_public_addresses(hostname: str, port: int) -> tuple[str, ...]:
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeURL(f"无法解析目标主机：{hostname}") from exc

    addresses: list[str] = []
    for record in records:
        address = _require_global_address(record[4][0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise UnsafeURL(f"目标主机没有可用公网地址：{hostname}")
    return tuple(addresses)


def validate_web_url(
    url_value: object,
    *,
    resolve_dns: bool = False,
    allow_fixture: bool = True,
) -> ValidatedURL:
    """校验 URL；联网前解析全部地址并拒绝任何非公网结果。"""

    if not isinstance(url_value, str):
        raise UnsafeURL("url 必须是字符串")
    url = url_value.strip()
    if not url or len(url) > MAX_URL_LEN:
        raise UnsafeURL("url 为空或过长")

    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme == "fixture":
        if not allow_fixture:
            raise UnsafeURL("此处不允许 fixture URL")
        return ValidatedURL(url=url, scheme=scheme, hostname="", port=0)
    if scheme not in {"http", "https"}:
        raise UnsafeURL(f"不支持的 URL 协议：{scheme or '(empty)'}")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeURL("URL 不允许包含用户名或密码")
    if not parsed.hostname:
        raise UnsafeURL("URL 缺少主机名")

    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").rstrip(".").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
    except (UnicodeError, ValueError) as exc:
        raise UnsafeURL("URL 主机名或端口无效") from exc

    if hostname in LOCAL_HOSTNAMES or hostname.endswith(".localhost"):
        raise UnsafeURL(f"禁止访问本地主机：{hostname}")
    if port not in ALLOWED_WEB_PORTS:
        raise UnsafeURL(f"禁止访问非标准 Web 端口：{port}")

    addresses: tuple[str, ...] = ()
    try:
        literal_address = ipaddress.ip_address(hostname)
    except ValueError:
        if resolve_dns:
            addresses = _resolve_public_addresses(hostname, port)
    else:
        addresses = (_require_global_address(literal_address.compressed),)

    return ValidatedURL(
        url=url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        addresses=addresses,
    )
