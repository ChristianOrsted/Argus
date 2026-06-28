"""全局配置：模型 ID、沙箱目录等。从环境变量读取，.env 由 python-dotenv 加载。"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()  # 读取项目根目录的 .env

# 模型 ID。默认 Opus 4.8；想省钱可在 .env 里改成 claude-sonnet-4-6 / claude-haiku-4-5。
AGENT_MODEL = os.environ.get("ARGUS_AGENT_MODEL", "claude-opus-4-8")
JUDGE_MODEL = os.environ.get("ARGUS_JUDGE_MODEL", "claude-opus-4-8")

# 被监督 Agent 的工具只允许在这个沙箱目录内读写文件。
SANDBOX_DIR = Path(os.environ.get("ARGUS_SANDBOX_DIR", "sandbox_runs")).resolve()
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
