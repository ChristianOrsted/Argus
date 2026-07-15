"""Runtime adaptive block rules for dashboard-driven hardening.

Rules are deliberately constrained data, not executable code. DeepSeek can
suggest them through the dashboard, but PolicyLayer only applies simple
case-insensitive substring matches over known fields.
"""

from __future__ import annotations

import hashlib
import json
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
    "metadata_contains_any",
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
    rule = {
        "description": str(raw.get("description") or raw.get("reason") or "adaptive dashboard rule")[:240],
        "action": "block",
    }
    tool_name = str(raw.get("tool_name") or "").strip()
    if tool_name:
        rule["tool_name"] = tool_name
    surface_id = str(raw.get("surface_id") or "").strip()
    if surface_id:
        rule["surface_id"] = surface_id
    for field in TEXT_FIELDS:
        terms = _terms(raw.get(field))
        if terms:
            rule[field] = terms
    digest_src = json.dumps(rule, sort_keys=True, ensure_ascii=False)
    rule["id"] = str(raw.get("id") or hashlib.sha256(digest_src.encode("utf-8")).hexdigest()[:12])
    return rule


def load_adaptive_rules(path: Path = ADAPTIVE_RULES_PATH) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return [sanitize_rule(item) for item in data if isinstance(item, dict)]


def save_adaptive_rules(rules: list[dict[str, Any]], path: Path = ADAPTIVE_RULES_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rules, ensure_ascii=False, indent=2), encoding="utf-8")


def append_adaptive_rules(raw_rules: list[dict[str, Any]], path: Path = ADAPTIVE_RULES_PATH) -> list[dict[str, Any]]:
    existing = load_adaptive_rules(path)
    by_id = {rule["id"]: rule for rule in existing}
    for raw in raw_rules:
        rule = sanitize_rule(raw)
        if any(rule.get(field) for field in TEXT_FIELDS):
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
    tool_name = rule.get("tool_name")
    if tool_name and tool_name != call.name:
        return False
    surface_id = rule.get("surface_id")
    if surface_id and surface_id != str(ctx.metadata.get("attack_surface", "")):
        return False
    return (
        _any_term_matches(rule.get("user_request_contains_any", []), ctx.user_request)
        and _any_term_matches(rule.get("input_contains_any", []), _flatten(call.input))
        and _any_term_matches(rule.get("metadata_contains_any", []), _flatten(ctx.metadata))
    )


def first_matching_adaptive_rule(call: ToolCall, ctx: Context, path: Path = ADAPTIVE_RULES_PATH) -> dict[str, Any] | None:
    for rule in load_adaptive_rules(path):
        if match_adaptive_rule(rule, call, ctx):
            return rule
    return None
