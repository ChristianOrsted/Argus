"""自适应规则只能使用运行时可观察字段。"""

import json

from src.guardian import Context, ToolCall
from src.guardian.adaptive_rules import (
    append_adaptive_rules,
    delete_adaptive_rule,
    first_matching_adaptive_rule,
    load_adaptive_rules,
    match_adaptive_rule,
    sanitize_rule,
    set_rule_enabled,
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

def test_adaptive_rule_hit_count_toggle_and_delete(tmp_path):
    path = tmp_path / "adaptive_rules.json"
    rules = append_adaptive_rules(
        [{
            "description": "block fake exfil",
            "source": "unit-test",
            "tool_name": "web_fetch",
            "input_contains_any": ["evil.example"],
        }],
        path=path,
    )
    rule_id = rules[0]["id"]

    ctx = Context(user_request="fetch report")
    call = ToolCall("web_fetch", {"url": "https://evil.example/data"})
    assert first_matching_adaptive_rule(call, ctx, path=path)["id"] == rule_id
    assert load_adaptive_rules(path)[0]["hit_count"] == 1

    assert set_rule_enabled(rule_id, False, path=path)["enabled"] is False
    assert first_matching_adaptive_rule(call, ctx, path=path) is None

    assert set_rule_enabled(rule_id, True, path=path)["enabled"] is True
    assert first_matching_adaptive_rule(call, ctx, path=path)["id"] == rule_id
    assert load_adaptive_rules(path)[0]["hit_count"] == 2

    assert delete_adaptive_rule(rule_id, path=path) is True
    assert load_adaptive_rules(path) == []
