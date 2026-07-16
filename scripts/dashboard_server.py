"""Argus Dashboard 本地服务。

这个脚本是可演示原型系统的入口：一个 Python 进程同时承担前端静态文件服务和
后端 Guardian API。前端所有操作最终都会落到这里：

- 离线样本评估：把预置 AttackCase 交给 Guardian；
- 自定义工具调用评估：把用户输入组装成 ToolCall；
- DeepSeek 在线红队：生成攻击样本后再交给 Guardian 审计；
- 漏拦截分析：让 DeepSeek 建议受限自适应规则，并重评估；
- 历史流：把每次审计结果写入 SQLite，供前端统计和回放。
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import mimetypes
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import perf_counter
from urllib.parse import unquote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.config import AGENT_MODEL, DEEPSEEK_API_KEY
from src.eval.benchmark import evaluate_guardian
from src.guardian.adaptive_rules import append_adaptive_rules, load_adaptive_rules
from src.guardian import Context, DeepSeekIntentJudge, ToolCall, build_default_guardian
from src.redteam.attacks import EVAL_CASES, AttackCase
from src.redteam.surface_lab import (
    ATTACK_SURFACES,
    DeepSeekDefenseAnalyzer,
    DeepSeekRedTeamGenerator,
    generated_attack_to_case,
    get_attack_surface,
    serialize_surface,
)

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "dashboard"
STATIC_ROOT = DASHBOARD_DIR.resolve()
HISTORY_DB = ROOT / "sandbox_runs" / "audit" / "dashboard_history.sqlite3"


def _case_context(case: AttackCase, metadata: dict | None = None) -> Context:
    """把红队样本转换为四层 Guardian 所需的 Context。"""
    return Context(
        user_request=case.user_request,
        history=list(case.history),
        tainted_sources=set(case.tainted_sources),
        metadata=metadata or {},
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
    """把 Guardian Decision 转成前端可直接渲染的 JSON。"""
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


def _history_connect(db_path: Path = HISTORY_DB) -> sqlite3.Connection:
    """打开历史库并确保表结构存在。"""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dashboard_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            mode TEXT NOT NULL,
            surface_id TEXT,
            surface_title TEXT,
            case_id TEXT,
            category TEXT,
            user_request TEXT,
            tool_name TEXT,
            action TEXT,
            reason TEXT,
            latency_ms REAL,
            payload_json TEXT NOT NULL
        )
        """
    )
    return conn


def _history_payload(mode: str, result: dict) -> dict:
    return {
        "mode": mode,
        "surface": result.get("surface"),
        "case": result.get("case"),
        "decision": result.get("decision"),
        "latency_ms": result.get("latency_ms"),
        "redteam": result.get("redteam"),
        "intent_judge_enabled": result.get("intent_judge_enabled"),
    }


def record_history(mode: str, result: dict, db_path: Path = HISTORY_DB) -> None:
    """把一次 Dashboard 审计写入 SQLite 历史流。"""
    payload = _history_payload(mode, result)
    case = payload.get("case") or {}
    surface = payload.get("surface") or {}
    decision = payload.get("decision") or {}
    tool_call = case.get("tool_call") or {}
    with _history_connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO dashboard_events (
                created_at, mode, surface_id, surface_title, case_id, category,
                user_request, tool_name, action, reason, latency_ms, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                dt.datetime.now(dt.timezone.utc).isoformat(),
                mode,
                surface.get("id"),
                surface.get("title"),
                case.get("id"),
                case.get("category"),
                case.get("user_request"),
                tool_call.get("name"),
                decision.get("action"),
                decision.get("reason"),
                result.get("latency_ms"),
                json.dumps(payload, ensure_ascii=False),
            ),
        )


def _row_to_history_entry(row: sqlite3.Row) -> dict:
    payload = json.loads(row["payload_json"])
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "mode": row["mode"],
        "surface_id": row["surface_id"],
        "surface_title": row["surface_title"],
        "case_id": row["case_id"],
        "category": row["category"],
        "user_request": row["user_request"],
        "tool_name": row["tool_name"],
        "action": row["action"],
        "reason": row["reason"],
        "latency_ms": row["latency_ms"],
        "payload": payload,
    }


def summarize_history(entries: list[dict]) -> dict:
    """汇总历史审计，用于前端指标卡和四层防御统计。"""
    actions = {"allow": 0, "flag": 0, "block": 0}
    layers: dict[str, dict[str, int]] = {}
    categories: dict[str, int] = {}
    surfaces: dict[str, int] = {}
    latencies = []

    for entry in entries:
        action = entry.get("action") or "allow"
        if action in actions:
            actions[action] += 1
        category = entry.get("category") or "unknown"
        categories[category] = categories.get(category, 0) + 1
        surface = entry.get("surface_title") or entry.get("surface_id")
        if surface:
            surfaces[surface] = surfaces.get(surface, 0) + 1
        if entry.get("latency_ms") is not None:
            latencies.append(float(entry["latency_ms"]))
        decision = (entry.get("payload") or {}).get("decision") or {}
        for verdict in decision.get("verdicts") or []:
            layer = verdict.get("layer") or "unknown"
            layer_action = verdict.get("action") or "allow"
            layers.setdefault(layer, {"allow": 0, "flag": 0, "block": 0})
            if layer_action in layers[layer]:
                layers[layer][layer_action] += 1

    total = len(entries)
    return {
        "total": total,
        "actions": actions,
        "layers": layers,
        "categories": categories,
        "surfaces": surfaces,
        "avg_latency_ms": (sum(latencies) / len(latencies)) if latencies else 0,
    }


def load_history(limit: int = 100, db_path: Path = HISTORY_DB) -> dict:
    with _history_connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM dashboard_events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    entries = [_row_to_history_entry(row) for row in rows]
    return {
        "entries": entries,
        "summary": summarize_history(entries),
    }


def clear_history(db_path: Path = HISTORY_DB) -> None:
    with _history_connect(db_path) as conn:
        conn.execute("DELETE FROM dashboard_events")


def normalize_tainted_sources(raw) -> set[str]:
    """规范化前端传来的污点来源，兼容字符串和数组两种输入。"""
    if isinstance(raw, str):
        return {raw} if raw else set()
    if isinstance(raw, list):
        return {str(item) for item in raw if str(item)}
    return set()


def resolve_static_path(request_path: str) -> Path | None:
    """解析静态文件路径，并防止通过 URL 目录穿越读取 dashboard 外文件。"""
    rel = unquote(request_path).lstrip("/")
    if not rel:
        rel = "index.html"
    target = (DASHBOARD_DIR / rel).resolve()
    try:
        target.relative_to(STATIC_ROOT)
    except ValueError:
        return None
    return target if target.is_file() else None


def evaluate_case(case: AttackCase, guardian=None, metadata: dict | None = None) -> dict:
    """评估一个离线或在线红队样本，并返回前端所需的完整审计结果。"""
    guardian = guardian or build_default_guardian()
    ctx = _case_context(case, metadata=metadata)
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
            "metadata": ctx.metadata,
        },
    }


def evaluate_surface(surface_id: str) -> dict:
    """运行某个攻击面的确定性离线样本，保证无 API Key 也能演示。"""
    surface = get_attack_surface(surface_id)
    result = evaluate_case(surface.offline_case)
    return {
        "mode": "offline",
        "surface": serialize_surface(surface),
        **result,
    }


def _generator_generate(generator, surface, prompt_override: str = "") -> dict:
    try:
        return generator.generate(surface, prompt_override=prompt_override)
    except TypeError:
        return generator.generate(surface)


def _evaluate_generated_attack(surface, generated: dict, api_key: str = "", use_intent_judge: bool = False) -> dict:
    """把 DeepSeek 生成样本转成 AttackCase，并带着红队元数据进入 Guardian。"""
    case = generated_attack_to_case(surface, generated)
    intent_client = DeepSeekIntentJudge(api_key=api_key or DEEPSEEK_API_KEY) if use_intent_judge else None
    metadata = {
        "attack_surface": surface.id,
        "attack_goal": generated.get("attack_goal"),
        "risk_points": generated.get("risk_points", []),
        "danger_explanation": generated.get("danger_explanation"),
        "expected_guardian_action": generated.get("expected_guardian_action"),
        "raw_model_output": generated.get("raw_model_output"),
    }
    result = evaluate_case(case, guardian=build_default_guardian(intent_client=intent_client), metadata=metadata)
    return {
        "mode": "deepseek",
        "surface": serialize_surface(surface),
        "redteam": generated,
        "intent_judge_enabled": use_intent_judge,
        **result,
    }


def run_deepseek_redteam(payload: dict, generator=None) -> dict:
    """运行单条 DeepSeek 在线红队样本。保留该接口用于兼容早期前端。"""
    surface = get_attack_surface(str(payload.get("surface_id", "")))
    api_key = str(payload.get("api_key") or "")
    use_intent_judge = bool(payload.get("use_intent_judge"))
    prompt_override = str(payload.get("prompt") or "")
    generator = generator or DeepSeekRedTeamGenerator(api_key=api_key or DEEPSEEK_API_KEY)
    generated = _generator_generate(generator, surface, prompt_override=prompt_override)
    return _evaluate_generated_attack(surface, generated, api_key=api_key, use_intent_judge=use_intent_judge)


def run_deepseek_batch(payload: dict, generator=None) -> dict:
    """批量生成 DeepSeek 红队样本并逐条审计，供前端矩阵展示。"""
    surface = get_attack_surface(str(payload.get("surface_id", "")))
    api_key = str(payload.get("api_key") or "")
    count = max(1, min(int(payload.get("count") or 1), 8))
    use_intent_judge = bool(payload.get("use_intent_judge"))
    prompt_override = str(payload.get("prompt") or "")
    generator = generator or DeepSeekRedTeamGenerator(api_key=api_key or DEEPSEEK_API_KEY)
    if hasattr(generator, "generate_many"):
        generated_items = generator.generate_many(surface, count=count, prompt_override=prompt_override)
    else:
        generated_items = [_generator_generate(generator, surface, prompt_override=prompt_override) for _ in range(count)]
    results = [
        _evaluate_generated_attack(surface, generated, api_key=api_key, use_intent_judge=use_intent_judge)
        for generated in generated_items
    ]
    actions = {"allow": 0, "flag": 0, "block": 0}
    for result in results:
        action = result["decision"]["action"]
        if action in actions:
            actions[action] += 1
    return {
        "mode": "deepseek_batch",
        "surface": serialize_surface(surface),
        "count": len(results),
        "actions": actions,
        "results": results,
    }


def analyze_missed_detection(payload: dict, analyzer=None) -> dict:
    """分析漏拦截、写入受限自适应规则，并对同一攻击重评估。"""
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    surface_id = str(payload.get("surface_id") or (result.get("surface") or {}).get("id") or "")
    surface = get_attack_surface(surface_id)
    generated = result.get("redteam") if isinstance(result.get("redteam"), dict) else {}
    api_key = str(payload.get("api_key") or "")
    analyzer = analyzer or DeepSeekDefenseAnalyzer(api_key=api_key or DEEPSEEK_API_KEY)
    analysis = analyzer.analyze(surface, generated, result)
    applied = []
    recheck_result = None
    if bool(payload.get("apply_rules", True)):
        applied = append_adaptive_rules(analysis.get("suggested_rules", []))
        if generated:
            recheck_result = _evaluate_generated_attack(surface, generated)
    return {
        "surface": serialize_surface(surface),
        "analysis": analysis,
        "applied_rules": applied,
        "recheck_result": recheck_result,
        "adaptive_rules": load_adaptive_rules(),
    }


def evaluate_custom(payload: dict) -> dict:
    """评估前端手工输入的任意 ToolCall，便于课堂现场复现实验。"""
    call = ToolCall(
        name=str(payload.get("tool_name") or payload.get("name") or "run_shell"),
        input=payload.get("input") if isinstance(payload.get("input"), dict) else {},
    )
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    ctx = Context(
        user_request=str(payload.get("user_request") or "自定义工具调用评估"),
        tainted_sources=normalize_tainted_sources(payload.get("tainted_sources")),
        metadata=metadata,
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
            "metadata": ctx.metadata,
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
        "attack_surfaces": [serialize_surface(surface) for surface in ATTACK_SURFACES],
        "deepseek": {
            "env_configured": bool(DEEPSEEK_API_KEY),
            "model": AGENT_MODEL,
        },
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
        if parsed.path == "/api/attack-surfaces":
            _json_response(self, 200, {
                "attack_surfaces": [serialize_surface(surface) for surface in ATTACK_SURFACES],
                "deepseek": {"env_configured": bool(DEEPSEEK_API_KEY), "model": AGENT_MODEL},
            })
            return
        if parsed.path == "/api/history":
            _json_response(self, 200, load_history())
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
                result = evaluate_case(case)
                record_history("case", result)
                _json_response(self, 200, result)
                return
            if parsed.path == "/api/custom":
                result = evaluate_custom(payload)
                record_history("custom", result)
                _json_response(self, 200, result)
                return
            if parsed.path == "/api/rerun-surface":
                result = evaluate_surface(str(payload.get("surface_id", "")))
                record_history("surface", result)
                _json_response(self, 200, result)
                return
            if parsed.path == "/api/deepseek-redteam":
                result = run_deepseek_redteam(payload)
                record_history("deepseek", result)
                _json_response(self, 200, result)
                return
            if parsed.path == "/api/deepseek-redteam-batch":
                result = run_deepseek_batch(payload)
                for item in result["results"]:
                    record_history("deepseek", item)
                _json_response(self, 200, result)
                return
            if parsed.path == "/api/analyze-miss":
                _json_response(self, 200, analyze_missed_detection(payload))
                return
            if parsed.path == "/api/history/clear":
                clear_history()
                _json_response(self, 200, load_history())
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
