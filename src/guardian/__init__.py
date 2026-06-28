"""Argus Guardian —— 监督器核心（四层防御）。"""

from .anomaly import AnomalyLayer
from .guardian import Action, Context, Decision, Guardian, ToolCall, Verdict
from .intent import IntentLayer
from .policy import PolicyLayer
from .taint import TaintLayer

__all__ = [
    "Action", "Context", "Decision", "Guardian", "ToolCall", "Verdict",
    "build_default_guardian",
]


def build_default_guardian(intent_client=None) -> Guardian:
    """组装四层防御。intent_client 传入 anthropic.Anthropic() 时启用第 3 层 LLM-judge。"""
    return Guardian([
        PolicyLayer(),
        TaintLayer(),
        IntentLayer(client=intent_client),
        AnomalyLayer(),
    ])
