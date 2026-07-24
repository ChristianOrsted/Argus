"""自适应规则只能使用运行时可观察字段。"""

from src.guardian import Context, ToolCall
import json

from src.guardian.adaptive_rules import (
    append_adaptive_rules,
    load_adaptive_rules,
    match_adaptive_rule,
    sanitize_rule,
)


def test_sanitize_rule_drops_evaluation_labels():
    rule = sanitize_rule({
        "description": "label leak probe",
        "tool_name": "web_fetch",
        "surface_id": "tool_hijack",
        "metadata_contains_any": ["expected_guardian_action=block"],
        "input_contains_any": ["evil.example"],
    })

    assert rule["input_contains_any"] == ["evil.example"]
    assert "surface_id" not in rule
    assert "metadata_contains_any" not in rule


def test_label_only_rule_is_not_persisted(tmp_path):
    path = tmp_path / "adaptive_rules.json"
    rules = append_adaptive_rules([
        {
            "surface_id": "tool_hijack",
            "metadata_contains_any": ["risk_points"],
        },
    ], path=path)

    assert rules == []


def test_legacy_label_only_rule_is_dropped_on_load(tmp_path):
    path = tmp_path / "adaptive_rules.json"
    path.write_text(json.dumps([
        {
            "tool_name": "web_fetch",
            "surface_id": "tool_hijack",
            "metadata_contains_any": ["risk_points"],
        },
    ]), encoding="utf-8")

    assert load_adaptive_rules(path) == []


def test_rule_matching_ignores_context_metadata():
    rule = sanitize_rule({
        "tool_name": "web_fetch",
        "input_contains_any": ["example.com/data"],
    })
    call = ToolCall("web_fetch", {"url": "https://example.com/data"})
    clean = Context(user_request="fetch report")
    labeled = Context(
        user_request="fetch report",
        metadata={"expected_guardian_action": "block", "risk_points": ["exfil"]},
    )

    assert match_adaptive_rule(rule, call, clean)
    assert match_adaptive_rule(rule, call, labeled)


def test_rule_without_observable_condition_never_matches():
    rule = sanitize_rule({
        "tool_name": "web_fetch",
        "surface_id": "tool_hijack",
        "metadata_contains_any": ["risk_points"],
    })
    call = ToolCall("web_fetch", {"url": "https://example.com/data"})

    assert not match_adaptive_rule(rule, call, Context(user_request="fetch report"))
