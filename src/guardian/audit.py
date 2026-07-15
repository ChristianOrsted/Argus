"""Guardian 审计日志工具。"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .guardian import Context, Decision, ToolCall


def decision_to_record(call: ToolCall, ctx: Context, decision: Decision, event: str = "tool_decision") -> dict[str, Any]:
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
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, call: ToolCall, ctx: Context, decision: Decision, event: str = "tool_decision") -> None:
        line = json.dumps(decision_to_record(call, ctx, decision, event=event), ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
