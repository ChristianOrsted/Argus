"""Runtime adaptive-rule management tests."""

from src.guardian import Context, ToolCall
from src.guardian.adaptive_rules import (
    append_adaptive_rules,
    delete_adaptive_rule,
    first_matching_adaptive_rule,
    load_adaptive_rules,
    set_rule_enabled,
)


def test_adaptive_rule_hit_count_toggle_and_delete(tmp_path):
    path = tmp_path / "adaptive_rules.json"
    rules = append_adaptive_rules(
        [{
            "description": "block fake exfil",
            "source": "unit-test",
            "surface_id": "tool_hijack",
            "metadata_contains_any": ["evil.example"],
        }],
        path=path,
    )
    rule_id = rules[0]["id"]

    ctx = Context(
        user_request="fetch report",
        metadata={"attack_surface": "tool_hijack", "risk_points": ["send to evil.example"]},
    )
    call = ToolCall("web_fetch", {"url": "https://example.com/data"})
    assert first_matching_adaptive_rule(call, ctx, path=path)["id"] == rule_id
    assert load_adaptive_rules(path)[0]["hit_count"] == 1

    assert set_rule_enabled(rule_id, False, path=path)["enabled"] is False
    assert first_matching_adaptive_rule(call, ctx, path=path) is None

    assert set_rule_enabled(rule_id, True, path=path)["enabled"] is True
    assert first_matching_adaptive_rule(call, ctx, path=path)["id"] == rule_id
    assert load_adaptive_rules(path)[0]["hit_count"] == 2

    assert delete_adaptive_rule(rule_id, path=path) is True
    assert load_adaptive_rules(path) == []
