"""被监督的智能体：ReAct 循环 + shell/file/web 工具。"""

__all__ = ["ReActAgent", "DeepSeekReActAgent"]


def __getattr__(name: str):
    """按需导入具体 Agent，避免离线工具/测试被可选 SDK 依赖阻塞。"""
    if name == "ReActAgent":
        from .react_agent import ReActAgent

        return ReActAgent
    if name == "DeepSeekReActAgent":
        from .deepseek_agent import DeepSeekReActAgent

        return DeepSeekReActAgent
    raise AttributeError(name)
