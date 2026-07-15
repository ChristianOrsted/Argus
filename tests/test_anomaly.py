"""第 4 层序列异常的基线测试。"""

from src.guardian import Action, Context, ToolCall
from src.guardian.anomaly import AnomalyLayer, REPEAT_THRESHOLD


def test_flags_repeated_tool_calls():
    history = [ToolCall("read_file", {"path": f"{i}.txt"}) for i in range(REPEAT_THRESHOLD)]
    ctx = Context(user_request="读取多个文件", history=history)
    v = AnomalyLayer().check(ToolCall("read_file", {"path": "next.txt"}), ctx)
    assert v.action == Action.FLAG


def test_allows_mixed_tool_sequence():
    history = [
        ToolCall("read_file", {"path": "a.txt"}),
        ToolCall("write_file", {"path": "b.txt", "content": "b"}),
    ]
    ctx = Context(user_request="整理文件", history=history)
    v = AnomalyLayer().check(ToolCall("read_file", {"path": "c.txt"}), ctx)
    assert v.action == Action.ALLOW
