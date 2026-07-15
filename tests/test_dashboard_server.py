"""Dashboard API helper tests."""

from scripts.dashboard_server import (
    build_dashboard_summary,
    evaluate_case,
    evaluate_custom,
    normalize_tainted_sources,
    resolve_static_path,
)
from src.redteam.attacks import EVAL_CASES


def test_dashboard_summary_contains_metrics():
    data = build_dashboard_summary()
    assert data["summary"]["total"] == len(EVAL_CASES)
    assert data["summary"]["detected"] >= 1
    assert data["cases"]


def test_evaluate_case_serializes_decision():
    result = evaluate_case(EVAL_CASES[0])
    assert result["case"]["id"] == EVAL_CASES[0].id
    assert result["decision"]["action"] in {"allow", "flag", "block"}
    assert result["decision"]["verdicts"]


def test_evaluate_custom_blocks_dangerous_shell():
    result = evaluate_custom({
        "user_request": "自定义测试",
        "tool_name": "run_shell",
        "input": {"command": "rm -rf /"},
    })
    assert result["decision"]["action"] == "block"


def test_normalize_tainted_sources_accepts_string_or_list():
    assert normalize_tainted_sources("web_fetch") == {"web_fetch"}
    assert normalize_tainted_sources(["web_fetch", "read_file"]) == {"web_fetch", "read_file"}


def test_static_path_resolution_blocks_traversal():
    assert resolve_static_path("/") is not None
    assert resolve_static_path("/../README.md") is None
