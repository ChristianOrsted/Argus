"""Argus Guardian —— 监督器核心（四层防御）。"""

from .anomaly import AnomalyLayer
from .audit import JsonlAuditLogger, decision_to_record
from .guardian import Action, Context, Decision, Guardian, TaintedFragment, ToolCall, Verdict
from .intent import DeepSeekIntentJudge, IntentLayer
from .policy import PolicyLayer
from .taint import TaintLayer

__all__ = [
    "Action", "Context", "Decision", "Guardian", "ToolCall", "Verdict",
    "DeepSeekIntentJudge", "JsonlAuditLogger", "TaintedFragment", "build_default_guardian", "decision_to_record",
]


def build_default_guardian(intent_client=None) -> Guardian:
    """组装四层防御。intent_client 传入 DeepSeekIntentJudge 或 fake 时启用第 3 层。"""
    return Guardian([
        PolicyLayer(),
        TaintLayer(),
        IntentLayer(client=intent_client),
        AnomalyLayer(),
    ])
