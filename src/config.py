"""全局配置：模型 ID、沙箱目录等。

`python-dotenv` 是开发便利依赖。为了让离线测试和 Guardian 演示不被依赖安装阻塞，
这里在缺失该包时继续从系统环境变量读取配置。
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:  # pragma: no cover - 取决于本机依赖环境
    def load_dotenv(*args, **kwargs):
        return False

PROJECT_ROOT = Path(__file__).resolve().parents[1]

load_dotenv(PROJECT_ROOT / ".env")  # 读取项目根目录的 .env

# LLM Provider。阶段 1 以 DeepSeek 的 OpenAI-compatible API 为主，保留 Anthropic 兼容入口。
LLM_PROVIDER = os.environ.get("ARGUS_LLM_PROVIDER", "deepseek").lower()

_DEFAULT_AGENT_MODEL = "deepseek-chat" if LLM_PROVIDER == "deepseek" else "claude-opus-4-8"
_DEFAULT_JUDGE_MODEL = "deepseek-chat" if LLM_PROVIDER == "deepseek" else "claude-opus-4-8"

AGENT_MODEL = os.environ.get("ARGUS_AGENT_MODEL", _DEFAULT_AGENT_MODEL)
JUDGE_MODEL = os.environ.get("ARGUS_JUDGE_MODEL", _DEFAULT_JUDGE_MODEL)

# DeepSeek 采用 OpenAI-compatible chat/completions 接口。
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")

# 被监督 Agent 的工具只允许在这个沙箱目录内读写文件。
_sandbox = Path(os.environ.get("ARGUS_SANDBOX_DIR", "sandbox_runs"))
SANDBOX_DIR = (_sandbox if _sandbox.is_absolute() else PROJECT_ROOT / _sandbox).resolve()
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

DATASETS_DIR = PROJECT_ROOT / "datasets"
FIXTURE_DIR = DATASETS_DIR / "fixtures"
