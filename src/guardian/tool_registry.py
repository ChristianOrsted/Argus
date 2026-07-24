"""工具能力注册表。

完整解决“工具集超出预设”需要把不同 Agent 框架的工具能力、权限、网络出口和
业务场景统一建模。当前原型先提供一个轻量注册表：PolicyLayer 仍以安全白名单
为默认策略，但白名单不再只是工具名集合，而是带有能力标签和审计关注点的档案。
后续接入新工具时，可以先在这里登记并以旁路观察模式评估风险。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolProfile:
    """单个工具的能力画像。"""

    name: str
    capabilities: tuple[str, ...]
    risk: str
    audit_focus: tuple[str, ...]
    enabled: bool = True


TOOL_PROFILES: dict[str, ToolProfile] = {
    "run_shell": ToolProfile(
        name="run_shell",
        capabilities=("code_execution", "filesystem", "process"),
        risk="critical",
        audit_focus=("destructive_command", "download_execute", "secret_read", "reverse_shell"),
    ),
    "read_file": ToolProfile(
        name="read_file",
        capabilities=("filesystem_read",),
        risk="high",
        audit_focus=("sandbox_escape", "secret_read", "training_data_leak"),
    ),
    "write_file": ToolProfile(
        name="write_file",
        capabilities=("filesystem_write", "memory_write"),
        risk="high",
        audit_focus=("sandbox_escape", "memory_poison", "environment_pollution"),
    ),
    "web_fetch": ToolProfile(
        name="web_fetch",
        capabilities=("network_read", "untrusted_source"),
        risk="medium",
        audit_focus=("prompt_injection_source", "exfil_staging", "remote_payload"),
    ),
}


def enabled_tool_names() -> set[str]:
    """返回当前允许进入后续策略细则的工具名。"""
    return {name for name, profile in TOOL_PROFILES.items() if profile.enabled}


def get_tool_profile(name: str) -> ToolProfile | None:
    """读取工具画像；未知工具返回 None，交给策略层阻断。"""
    return TOOL_PROFILES.get(name)

