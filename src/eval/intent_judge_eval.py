"""DeepSeek intent judge 在线评测逻辑。"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter
from typing import Protocol

from ..redteam.intent_cases import IntentJudgeCase


class JudgeLike(Protocol):
    def judge_tool_call(self, user_request, call, model=None):
        ...


@dataclass
class IntentJudgeCaseResult:
    case: IntentJudgeCase
    consistent: bool
    expected: bool
    reason: str
    confidence: float
    latency_ms: float

    @property
    def correct(self) -> bool:
        return self.consistent == self.expected


@dataclass
class IntentJudgeEvalResult:
    total: int
    correct: int
    accuracy: float
    avg_latency_ms: float
    case_results: list[IntentJudgeCaseResult] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = [
            "# DeepSeek Intent Judge Evaluation",
            "",
            "## Summary",
            "",
            "| metric | value |",
            "|---|---:|",
            f"| total cases | {self.total} |",
            f"| correct | {self.correct} |",
            f"| accuracy | {self.accuracy:.2%} |",
            f"| avg latency | {self.avg_latency_ms:.3f} ms |",
            "",
            "## Cases",
            "",
            "| id | expected consistent | judged consistent | correct | confidence | latency ms | reason |",
            "|---|---:|---:|---:|---:|---:|---|",
        ]
        for result in self.case_results:
            reason = result.reason.replace("|", "/")
            lines.append(
                f"| {result.case.id} | {result.expected} | {result.consistent} | {result.correct} | "
                f"{result.confidence:.2f} | {result.latency_ms:.3f} | {reason} |"
            )
        return "\n".join(lines) + "\n"


def evaluate_intent_judge(judge: JudgeLike, cases: list[IntentJudgeCase]) -> IntentJudgeEvalResult:
    results: list[IntentJudgeCaseResult] = []
    for case in cases:
        start = perf_counter()
        raw = judge.judge_tool_call(case.user_request, case.tool_call)
        latency_ms = (perf_counter() - start) * 1000
        consistent = bool(raw.get("consistent"))
        reason = str(raw.get("reason") or "")
        try:
            confidence = float(raw.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        results.append(
            IntentJudgeCaseResult(
                case=case,
                consistent=consistent,
                expected=case.expected_consistent,
                reason=reason,
                confidence=max(0.0, min(confidence, 1.0)),
                latency_ms=latency_ms,
            )
        )

    correct = sum(1 for result in results if result.correct)
    total = len(results)
    avg_latency = sum(result.latency_ms for result in results) / total if total else 0.0
    return IntentJudgeEvalResult(
        total=total,
        correct=correct,
        accuracy=correct / total if total else 0.0,
        avg_latency_ms=avg_latency,
        case_results=results,
    )
