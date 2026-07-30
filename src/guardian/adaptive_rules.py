"""Dashboard 驱动的运行时自适应防御规则。

DeepSeek 可以在“分析漏拦截”时建议新规则，但这里故意只接受受限数据规则：
`tool_name`、`surface_id`、`*_contains_any` 等字段。PolicyLayer 只做大小写不敏感
的包含匹配，不执行模型生成的代码，也不接受正则或任意表达式。

这让项目可以演示“红队发现绕过 -> 蓝队分析原因 -> 同步防御规则 -> 重评估”的闭环，
同时避免把 LLM 生成内容直接变成可执行安全策略。
"""

from __future__ import annotations

import hashlib
import json
import datetime as dt
from pathlib import Path
from typing import Any

from ..config import PROJECT_ROOT
from .guardian import Context, ToolCall

ADAPTIVE_RULES_PATH = PROJECT_ROOT / "sandbox_runs" / "audit" / "adaptive_rules.json"
MAX_TERMS = 12
MAX_TERM_LEN = 120

TEXT_FIELDS = (
    "user_request_contains_any",
    "input_contains_any",
)


def _flatten(value) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten(item) for item in value)
    return str(value)


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _terms(value: Any) -> list[str]:
    if isinstance(value, str):
        raw = [value]
    elif isinstance(value, list):
        raw = value
    else:
        raw = []
    terms = []
    for item in raw:
        text = str(item).strip()
        if text:
            terms.append(text[:MAX_TERM_LEN])
        if len(terms) >= MAX_TERMS:
            break
    return terms


def sanitize_rule(raw: dict[str, Any]) -> dict[str, Any]:
    """把外部输入规则压缩成安全、可审计、可去重的固定格式。"""
    rule = {
        "description": str(raw.get("description") or raw.get("reason") or "adaptive dashboard rule")[:240],
        "action": "block",
    }
    tool_name = str(raw.get("tool_name") or "").strip()
    if tool_name:
        rule["tool_name"] = tool_name
    for field in TEXT_FIELDS:
        terms = _terms(raw.get(field))
        if terms:
            rule[field] = terms
    digest_src = json.dumps(rule, sort_keys=True, ensure_ascii=False)
    rule["id"] = str(raw.get("id") or hashlib.sha256(digest_src.encode("utf-8")).hexdigest()[:12])
    rule["source"] = str(raw.get("source") or raw.get("origin") or "adaptive-rule")[:120]
    rule["enabled"] = bool(raw.get("enabled", True))
    try:
        rule["hit_count"] = max(0, int(raw.get("hit_count") or 0))
    except (TypeError, ValueError):
        rule["hit_count"] = 0
    rule["created_at"] = str(raw.get("created_at") or "")
    rule["last_hit_at"] = str(raw.get("last_hit_at") or "")
    return rule


def _has_observable_condition(rule: dict[str, Any]) -> bool:
    return any(rule.get(field) for field in TEXT_FIELDS)


def load_adaptive_rules(path: Path = ADAPTIVE_RULES_PATH) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    rules = [sanitize_rule(item) for item in data if isinstance(item, dict)]
    return [rule for rule in rules if _has_observable_condition(rule)]


def save_adaptive_rules(rules: list[dict[str, Any]], path: Path = ADAPTIVE_RULES_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rules, ensure_ascii=False, indent=2), encoding="utf-8")


def append_adaptive_rules(raw_rules: list[dict[str, Any]], path: Path = ADAPTIVE_RULES_PATH) -> list[dict[str, Any]]:
    """追加规则并按 id 去重；没有任何匹配字段的规则会被丢弃。"""
    existing = load_adaptive_rules(path)
    by_id = {rule["id"]: rule for rule in existing}
    for raw in raw_rules:
        enriched = dict(raw)
        enriched.setdefault("source", "DeepSeek missed-detection analysis")
        enriched.setdefault("created_at", dt.datetime.now(dt.timezone.utc).isoformat())
        enriched.setdefault("enabled", True)
        rule = sanitize_rule(enriched)
        if _has_observable_condition(rule):
            if rule["id"] in by_id:
                rule["hit_count"] = by_id[rule["id"]].get("hit_count", 0)
                rule["created_at"] = by_id[rule["id"]].get("created_at") or rule["created_at"]
                rule["last_hit_at"] = by_id[rule["id"]].get("last_hit_at", "")
            by_id[rule["id"]] = rule
    merged = list(by_id.values())
    save_adaptive_rules(merged, path)
    return merged


def _any_term_matches(terms: list[str], haystack: str) -> bool:
    if not terms:
        return True
    text = _norm(haystack)
    return any(_norm(term) in text for term in terms)


def match_adaptive_rule(rule: dict[str, Any], call: ToolCall, ctx: Context) -> bool:
    """判断单条受限规则是否命中当前工具调用和上下文。"""
    if not rule.get("enabled", True) or not _has_observable_condition(rule):
        return False
    tool_name = rule.get("tool_name")
    if tool_name and tool_name != call.name:
        return False
    return (
        _any_term_matches(rule.get("user_request_contains_any", []), ctx.user_request)
        and _any_term_matches(rule.get("input_contains_any", []), _flatten(call.input))
    )


def first_matching_adaptive_rule(call: ToolCall, ctx: Context, path: Path = ADAPTIVE_RULES_PATH) -> dict[str, Any] | None:
    rules = load_adaptive_rules(path)
    for index, rule in enumerate(rules):
        if match_adaptive_rule(rule, call, ctx):
            rules[index]["hit_count"] = int(rule.get("hit_count") or 0) + 1
            rules[index]["last_hit_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
            save_adaptive_rules(rules, path)
            return rule
    return None


def set_rule_enabled(rule_id: str, enabled: bool, path: Path = ADAPTIVE_RULES_PATH) -> dict[str, Any] | None:
    rules = load_adaptive_rules(path)
    for rule in rules:
        if rule["id"] == rule_id:
            rule["enabled"] = bool(enabled)
            save_adaptive_rules(rules, path)
            return rule
    return None


def delete_adaptive_rule(rule_id: str, path: Path = ADAPTIVE_RULES_PATH) -> bool:
    rules = load_adaptive_rules(path)
    kept = [rule for rule in rules if rule["id"] != rule_id]
    if len(kept) == len(rules):
        return False
    save_adaptive_rules(kept, path)
    return True
