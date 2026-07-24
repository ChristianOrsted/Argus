"""工具能力注册表测试。"""

from src.guardian.policy import ALLOWED_TOOLS
from src.guardian.tool_registry import TOOL_PROFILES, enabled_tool_names, get_tool_profile


def test_enabled_tools_match_policy_allowlist():
    assert enabled_tool_names() == ALLOWED_TOOLS
    assert {"run_shell", "read_file", "write_file", "web_fetch"} <= ALLOWED_TOOLS


def test_run_shell_profile_records_critical_capability():
    profile = get_tool_profile("run_shell")
    assert profile is not None
    assert profile.risk == "critical"
    assert "code_execution" in profile.capabilities
    assert "destructive_command" in profile.audit_focus


def test_unknown_tool_has_no_profile():
    assert get_tool_profile("delete_database") is None
    assert "delete_database" not in TOOL_PROFILES

