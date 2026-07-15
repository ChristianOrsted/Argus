"""Argus Dashboard 本地服务。

只使用 Python 标准库：提供静态前端和 Guardian 评估 API。
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import perf_counter
from urllib.parse import unquote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.eval.benchmark import evaluate_guardian
from src.guardian import Action, Context, ToolCall, build_default_guardian
from src.redteam.attacks import EVAL_CASES, AttackCase

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "dashboard"
STATIC_ROOT = DASHBOARD_DIR.resolve()


def _case_context(case: AttackCase) -> Context:
    return Context(
        user_request=case.user_request,
        history=list(case.history),
        tainted_sources=set(case.tainted_sources),
    )


def serialize_tool_call(call: ToolCall) -> dict:
    return {
        "name": call.name,
        "input": call.input,
        "tool_use_id": call.tool_use_id,
    }


def serialize_case(case: AttackCase) -> dict:
    return {
        "id": case.id,
        "category": case.category,
        "user_request": case.user_request,
        "description": case.description,
        "should_block": case.should_block,
        "tainted_sources": sorted(case.tainted_sources),
        "history_len": len(case.history),
        "tool_call": serialize_tool_call(case.tool_call),
    }


def serialize_decision(decision) -> dict:
    return {
        "action": decision.action.value,
        "reason": decision.reason,
        "blocked": decision.blocked,
        "verdicts": [
            {
                "layer": verdict.layer,
                "action": verdict.action.value,
                "reason": verdict.reason,
                "confidence": verdict.confidence,
            }
            for verdict in decision.verdicts
        ],
    }


def normalize_tainted_sources(raw) -> set[str]:
    if isinstance(raw, str):
        return {raw} if raw else set()
    if isinstance(raw, list):
        return {str(item) for item in raw if str(item)}
    return set()


def resolve_static_path(request_path: str) -> Path | None:
    rel = unquote(request_path).lstrip("/")
    if not rel:
        rel = "index.html"
    target = (DASHBOARD_DIR / rel).resolve()
    try:
        target.relative_to(STATIC_ROOT)
    except ValueError:
        return None
    return target if target.is_file() else None


def evaluate_case(case: AttackCase) -> dict:
    guardian = build_default_guardian()
    ctx = _case_context(case)
    start = perf_counter()
    decision = guardian.evaluate(case.tool_call, ctx)
    latency_ms = (perf_counter() - start) * 1000
    return {
        "case": serialize_case(case),
        "decision": serialize_decision(decision),
        "latency_ms": latency_ms,
        "context": {
            "tainted_sources": sorted(ctx.tainted_sources),
            "history_len": len(ctx.history),
        },
    }


def evaluate_custom(payload: dict) -> dict:
    call = ToolCall(
        name=str(payload.get("tool_name") or payload.get("name") or "run_shell"),
        input=payload.get("input") if isinstance(payload.get("input"), dict) else {},
    )
    ctx = Context(
        user_request=str(payload.get("user_request") or "自定义工具调用评估"),
        tainted_sources=normalize_tainted_sources(payload.get("tainted_sources")),
    )
    start = perf_counter()
    decision = build_default_guardian().evaluate(call, ctx)
    latency_ms = (perf_counter() - start) * 1000
    return {
        "case": {
            "id": "custom",
            "category": "custom",
            "user_request": ctx.user_request,
            "description": "前端自定义工具调用",
            "should_block": False,
            "tainted_sources": sorted(ctx.tainted_sources),
            "history_len": 0,
            "tool_call": serialize_tool_call(call),
        },
        "decision": serialize_decision(decision),
        "latency_ms": latency_ms,
        "context": {
            "tainted_sources": sorted(ctx.tainted_sources),
            "history_len": 0,
        },
    }


def build_dashboard_summary() -> dict:
    result = evaluate_guardian(build_default_guardian(), EVAL_CASES)
    action_counts = {"allow": 0, "flag": 0, "block": 0}
    category_counts: dict[str, int] = {}
    layer_counts: dict[str, dict[str, int]] = {}
    rows = []

    for case_result in result.case_results:
        case = case_result.case
        decision = case_result.decision
        action_counts[decision.action.value] += 1
        category_counts[case.category] = category_counts.get(case.category, 0) + 1
        for verdict in decision.verdicts:
            layer_counts.setdefault(verdict.layer, {"allow": 0, "flag": 0, "block": 0})
            layer_counts[verdict.layer][verdict.action.value] += 1
        rows.append({
            "case": serialize_case(case),
            "decision": serialize_decision(decision),
            "latency_ms": case_result.latency_ms,
            "detected": case_result.detected,
            "false_positive": case_result.false_positive,
        })

    return {
        "summary": {
            "total": result.total,
            "attacks": result.attacks,
            "benign": result.benign,
            "detected": result.detected,
            "false_positives": result.false_positives,
            "recall": result.recall,
            "false_positive_rate": result.false_positive_rate,
            "avg_latency_ms": result.avg_latency_ms,
            "actions": action_counts,
            "categories": category_counts,
            "layers": layer_counts,
        },
        "cases": [serialize_case(case) for case in EVAL_CASES],
        "results": rows,
    }


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "ArgusDashboard/0.1"

    def log_message(self, format, *args):  # noqa: A002
        print(f"[dashboard] {self.address_string()} - {format % args}")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/summary":
            _json_response(self, 200, build_dashboard_summary())
            return
        if parsed.path == "/api/cases":
            _json_response(self, 200, {"cases": [serialize_case(case) for case in EVAL_CASES]})
            return
        self._serve_static(parsed.path)

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        try:
            payload = self._read_json()
            if parsed.path == "/api/evaluate":
                case_id = str(payload.get("case_id", ""))
                case = next((item for item in EVAL_CASES if item.id == case_id), None)
                if case is None:
                    _json_response(self, 404, {"error": f"unknown case_id: {case_id}"})
                    return
                _json_response(self, 200, evaluate_case(case))
                return
            if parsed.path == "/api/custom":
                _json_response(self, 200, evaluate_custom(payload))
                return
            if parsed.path == "/api/run-all":
                _json_response(self, 200, build_dashboard_summary())
                return
            _json_response(self, 404, {"error": "unknown endpoint"})
        except Exception as exc:  # pragma: no cover - 防止前端得到空响应
            _json_response(self, 500, {"error": str(exc)})

    def _serve_static(self, request_path: str) -> None:
        target = resolve_static_path(request_path)
        if target is None:
            self.send_error(404)
            return
        body = target.read_bytes()
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Argus Guardian dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"Argus dashboard: http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
