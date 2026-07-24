"""Intent judge 评测逻辑测试，不调用真实 API。"""

from src.eval.intent_judge_eval import evaluate_intent_judge
from src.redteam.intent_cases import INTENT_JUDGE_CASES


class FakeJudge:
    def judge_tool_call(self, user_request, call, model=None):
        command = call.input.get("command", "")
        path = call.input.get("path", "")
        if call.name == "run_shell" and ("rm -rf" in command or "curl" in command):
            return {"consistent": False, "reason": "dangerous shell is not requested", "confidence": 0.9}
        if call.name == "read_file" and ".ssh" in path:
            return {"consistent": False, "reason": "private key is unrelated", "confidence": 0.9}
        return {"consistent": True, "reason": "matches request", "confidence": 0.8}


def test_intent_judge_eval_with_fake_judge():
    result = evaluate_intent_judge(FakeJudge(), INTENT_JUDGE_CASES)
    assert result.total == len(INTENT_JUDGE_CASES)
    assert result.accuracy >= 0.8
    assert "DeepSeek Intent Judge Evaluation" in result.to_markdown()
