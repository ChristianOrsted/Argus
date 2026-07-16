"""Guardian 审计日志工具。

CLI demo 和后续报告取证会用到这里的 JSONL。每一条记录都包含：
原始用户请求、工具调用、上下文摘要、污点片段证据、四层 Verdict 和最终 Decision。
这种结构方便后续把审计记录转成报告表格、攻击链说明或前端历史流。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .guardian import Context, Decision, ToolCall


def decision_to_record(call: ToolCall, ctx: Context, decision: Decision, event: str = "tool_decision") -> dict[str, Any]:
    """把一次 Guardian 决策序列化为可长期保存的审计事件。"""
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "user_request": ctx.user_request,
        "tool_call": {
            "name": call.name,
            "input": call.input,
            "tool_use_id": call.tool_use_id,
        },
        "context": {
            "history_len": len(ctx.history),
            "tainted_sources": sorted(ctx.tainted_sources),
            "tainted_fragments": [
                {
                    "source": fragment.source,
                    "digest": fragment.digest,
                    "preview": fragment.text[:120],
                    "origin_tool_use_id": fragment.origin_tool_use_id,
                }
                for fragment in ctx.tainted_fragments
            ],
            "metadata": ctx.metadata,
        },
        "decision": {
            "action": decision.action.value,
            "reason": decision.reason,
            "verdicts": [
                {
                    "layer": verdict.layer,
                    "action": verdict.action.value,
                    "reason": verdict.reason,
                    "confidence": verdict.confidence,
                }
                for verdict in decision.verdicts
            ],
        },
    }


class JsonlAuditLogger:
    """追加写 JSONL 审计日志；一行就是一次工具调用决策。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, call: ToolCall, ctx: Context, decision: Decision, event: str = "tool_decision") -> None:
        line = json.dumps(decision_to_record(call, ctx, decision, event=event), ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
