"""审计日志结构测试。"""

import json

from src.guardian import Action, Context, Decision, JsonlAuditLogger, ToolCall, Verdict, decision_to_record


def test_decision_to_record_shape():
    call = ToolCall("run_shell", {"command": "echo hello"})
    ctx = Context(user_request="测试")
    decision = Decision(Action.ALLOW, "ok", [Verdict("policy", Action.ALLOW, "ok")])
    record = decision_to_record(call, ctx, decision)
    assert record["tool_call"]["name"] == "run_shell"
    assert record["decision"]["action"] == "allow"
    assert record["decision"]["verdicts"][0]["layer"] == "policy"


def test_jsonl_audit_logger(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = JsonlAuditLogger(path)
    call = ToolCall("run_shell", {"command": "echo hello"})
    ctx = Context(user_request="测试")
    decision = Decision(Action.ALLOW, "ok", [Verdict("policy", Action.ALLOW, "ok")])
    logger.record(call, ctx, decision)
    line = path.read_text(encoding="utf-8").strip()
    assert json.loads(line)["decision"]["reason"] == "ok"
