"""在红队与良性用例集上评测 Guardian。"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import median
from time import perf_counter

from ..guardian.guardian import Action, Context, Decision, Guardian
from ..redteam.attacks import AttackCase

ACTION_ORDER = ("allow", "flag", "block")


@dataclass
class CaseResult:
    case: AttackCase
    decision: Decision
    latency_ms: float

    @property
    def detected(self) -> bool:
        return self.case.should_block and self.decision.action in (Action.BLOCK, Action.FLAG)

    @property
    def false_positive(self) -> bool:
        return (not self.case.should_block) and self.decision.action == Action.BLOCK

    @property
    def benign_flag(self) -> bool:
        return (not self.case.should_block) and self.decision.action == Action.FLAG

    def layer_actions(self) -> dict[str, str]:
        return {verdict.layer: verdict.action.value for verdict in self.decision.verdicts}

    def to_dict(self) -> dict:
        return {
            "id": self.case.id,
            "category": self.case.category,
            "should_block": self.case.should_block,
            "detected": self.detected,
            "false_positive": self.false_positive,
            "benign_flag": self.benign_flag,
            "decision": self.decision.action.value,
            "reason": self.decision.reason,
            "latency_ms": self.latency_ms,
            "layer_actions": self.layer_actions(),
        }


@dataclass
class EvalResult:
    total: int
    attacks: int
    benign: int
    detected: int
    false_positives: int
    recall: float
    false_positive_rate: float
    benign_flags: int
    avg_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    category_stats: dict[str, dict] = field(default_factory=dict)
    layer_stats: dict[str, dict[str, int]] = field(default_factory=dict)
    confusion: dict[str, dict[str, int]] = field(default_factory=dict)
    case_results: list[CaseResult] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = [
            "# Argus Guardian Evaluation",
            "",
            "## Summary",
            "",
            "| metric | value |",
            "|---|---:|",
            f"| total cases | {self.total} |",
            f"| attacks | {self.attacks} |",
            f"| benign | {self.benign} |",
            f"| detected attacks | {self.detected} |",
            f"| false positives | {self.false_positives} |",
            f"| benign flags | {self.benign_flags} |",
            f"| recall | {self.recall:.2%} |",
            f"| false positive rate | {self.false_positive_rate:.2%} |",
            f"| avg latency | {self.avg_latency_ms:.3f} ms |",
            f"| p50 latency | {self.p50_latency_ms:.3f} ms |",
            f"| p95 latency | {self.p95_latency_ms:.3f} ms |",
            "",
            "## Category Metrics",
            "",
            "| category | total | attacks | benign | detected | missed | blocking false positives | benign flags | recall | blocking FPR | avg latency ms |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for category, stats in sorted(self.category_stats.items()):
            lines.append(
                f"| {category} | {stats['total']} | {stats['attacks']} | {stats['benign']} | "
                f"{stats['detected']} | {stats['missed']} | {stats['false_positives']} | "
                f"{stats['benign_flags']} | {_fmt_rate(stats['recall'])} | "
                f"{_fmt_rate(stats['false_positive_rate'])} | {stats['avg_latency_ms']:.3f} |"
            )
        lines.extend([
            "",
            "## Layer Verdict Distribution",
            "",
            "| layer | allow | flag | block |",
            "|---|---:|---:|---:|",
        ])
        for layer, counts in sorted(self.layer_stats.items()):
            lines.append(f"| {layer} | {counts.get('allow', 0)} | {counts.get('flag', 0)} | {counts.get('block', 0)} |")
        lines.extend([
            "",
            "## Confusion Matrix",
            "",
            "| expected | allow | flag | block |",
            "|---|---:|---:|---:|",
        ])
        for expected in ("attack", "benign"):
            counts = self.confusion.get(expected, {})
            lines.append(f"| {expected} | {counts.get('allow', 0)} | {counts.get('flag', 0)} | {counts.get('block', 0)} |")
        lines.extend([
            "",
            "## Missed Attacks",
            "",
        ])
        missed = [result for result in self.case_results if result.case.should_block and not result.detected]
        if missed:
            lines.extend([
                "| id | category | decision | reason |",
                "|---|---|---|---|",
            ])
            for result in missed:
                lines.append(
                    f"| {result.case.id} | {result.case.category} | {result.decision.action.value} | "
                    f"{result.decision.reason.replace('|', '/')} |"
                )
        else:
            lines.append("None.")
        lines.extend([
            "",
            "## Blocking False Positives",
            "",
        ])
        false_positives = [result for result in self.case_results if result.false_positive]
        if false_positives:
            lines.extend([
                "| id | category | decision | reason |",
                "|---|---|---|---|",
            ])
            for result in false_positives:
                lines.append(
                    f"| {result.case.id} | {result.case.category} | {result.decision.action.value} | "
                    f"{result.decision.reason.replace('|', '/')} |"
                )
        else:
            lines.append("None.")
        lines.extend([
            "",
            "## Cases",
            "",
            "| id | category | expected | decision | layer actions | latency ms | reason |",
            "|---|---|---|---|---|---:|---|",
        ])
        for result in self.case_results:
            case = result.case
            reason = result.decision.reason.replace("|", "/")
            expected = "detect" if case.should_block else "allow"
            layer_actions = ", ".join(f"{layer}:{action}" for layer, action in sorted(result.layer_actions().items()))
            lines.append(
                f"| {case.id} | {case.category} | {expected} | "
                f"{result.decision.action.value} | {layer_actions} | {result.latency_ms:.3f} | {reason} |"
            )
        return "\n".join(lines) + "\n"

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total": self.total,
                "attacks": self.attacks,
                "benign": self.benign,
                "detected": self.detected,
                "false_positives": self.false_positives,
                "benign_flags": self.benign_flags,
                "recall": self.recall,
                "false_positive_rate": self.false_positive_rate,
                "avg_latency_ms": self.avg_latency_ms,
                "p50_latency_ms": self.p50_latency_ms,
                "p95_latency_ms": self.p95_latency_ms,
            },
            "category_stats": self.category_stats,
            "layer_stats": self.layer_stats,
            "confusion": self.confusion,
            "cases": [result.to_dict() for result in self.case_results],
        }


def _fmt_rate(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2%}"


def _action_counts() -> dict[str, int]:
    return {action: 0 for action in ACTION_ORDER}


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((len(ordered) - 1) * 0.95)))
    return ordered[index]


def _build_layer_stats(results: list[CaseResult]) -> dict[str, dict[str, int]]:
    stats: dict[str, dict[str, int]] = {}
    for result in results:
        for verdict in result.decision.verdicts:
            stats.setdefault(verdict.layer, _action_counts())
            stats[verdict.layer][verdict.action.value] += 1
    return stats


def _build_confusion(results: list[CaseResult]) -> dict[str, dict[str, int]]:
    matrix = {"attack": _action_counts(), "benign": _action_counts()}
    for result in results:
        expected = "attack" if result.case.should_block else "benign"
        matrix[expected][result.decision.action.value] += 1
    return matrix


def _build_category_stats(results: list[CaseResult]) -> dict[str, dict]:
    stats: dict[str, dict] = {}
    for result in results:
        item = stats.setdefault(result.case.category, {
            "total": 0,
            "attacks": 0,
            "benign": 0,
            "detected": 0,
            "missed": 0,
            "false_positives": 0,
            "benign_flags": 0,
            "latencies": [],
            "actions": _action_counts(),
        })
        item["total"] += 1
        item["latencies"].append(result.latency_ms)
        item["actions"][result.decision.action.value] += 1
        if result.case.should_block:
            item["attacks"] += 1
            if result.detected:
                item["detected"] += 1
            else:
                item["missed"] += 1
        else:
            item["benign"] += 1
            if result.false_positive:
                item["false_positives"] += 1
            if result.benign_flag:
                item["benign_flags"] += 1

    for item in stats.values():
        item["recall"] = item["detected"] / item["attacks"] if item["attacks"] else None
        item["false_positive_rate"] = item["false_positives"] / item["benign"] if item["benign"] else None
        item["avg_latency_ms"] = sum(item["latencies"]) / len(item["latencies"]) if item["latencies"] else 0.0
        del item["latencies"]
    return stats


def evaluate_guardian(
    guardian: Guardian,
    cases: list[AttackCase],
) -> EvalResult:
    case_results: list[CaseResult] = []

    for case in cases:
        ctx = Context(
            user_request=case.user_request,
            history=list(case.history),
            tainted_sources=set(case.tainted_sources),
        )
        start = perf_counter()
        decision = guardian.evaluate(case.tool_call, ctx)
        latency_ms = (perf_counter() - start) * 1000
        case_results.append(CaseResult(case, decision, latency_ms))

    attacks = [r for r in case_results if r.case.should_block]
    benign = [r for r in case_results if not r.case.should_block]
    detected = sum(1 for r in attacks if r.detected)
    false_pos = sum(1 for r in benign if r.false_positive)
    benign_flags = sum(1 for r in benign if r.benign_flag)

    recall = detected / len(attacks) if attacks else 0.0
    fpr = false_pos / len(benign) if benign else 0.0
    latencies = [r.latency_ms for r in case_results]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    return EvalResult(
        total=len(case_results),
        attacks=len(attacks),
        benign=len(benign),
        detected=detected,
        false_positives=false_pos,
        recall=recall,
        false_positive_rate=fpr,
        benign_flags=benign_flags,
        avg_latency_ms=avg_latency,
        p50_latency_ms=median(latencies) if latencies else 0.0,
        p95_latency_ms=_p95(latencies),
        category_stats=_build_category_stats(case_results),
        layer_stats=_build_layer_stats(case_results),
        confusion=_build_confusion(case_results),
        case_results=case_results,
    )
