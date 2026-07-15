# Commit Summary

## Branch investigation

Date: 2026-07-15

- Local repository: `Argus`
- Original remote: `https://github.com/ChristianOrsted/Argus`
- Remote refs checked with `git ls-remote origin`
- Result: only `master` exists at `d9620414bb8a2d20f4c08194b864d506e24e6f16`
- No DeepSeek branch or PR ref was available from this remote.

Because the expected DeepSeek branch was not present, development continues from clean `master` on local branch `codex/deepseek-progress`.

## Stage 1 - DeepSeek foundation and offline demo

Commit message: `feat: add deepseek foundation and offline guardian demo`

Completed scope:

- Add a tracked architecture document that matches the README references.
- Add DeepSeek/OpenAI-compatible configuration and agent entry point.
- Make Guardian importable without optional development dependencies.
- Add fixture-based `web_fetch` for offline indirect prompt injection demos.
- Add an API-key-free offline demo path and a DeepSeek online demo path.
- Add baseline tests for policy, taint, anomaly, and fixture behavior.

Validation:

- `python scripts\offline_demo.py` passed.
- Manual Guardian/tool assertions passed.
- `python -m compileall src scripts tests` passed.
- `git diff --check` passed.
- `python -m pytest` could not run in the current machine environment because `pytest` is not installed.

## Stage 2 - Red-team seeds and benchmark loop

Commit message: `feat: add redteam benchmark loop`

Completed scope:

- Expand red-team cases from three placeholders into a mixed attack and benign seed suite.
- Add key `ToolCall` mappings, tainted-source context, and history context for offline evaluation.
- Add a tracked `datasets/seed_cases.jsonl` for course deliverables.
- Improve policy coverage for sensitive credential reads and memory poisoning.
- Replace the benchmark TODO with recall, false-positive-rate, latency, per-case result rows, and Markdown output.
- Add `scripts/run_benchmark.py` to generate `report/eval_results.md`.
- Add benchmark tests for coverage and baseline metrics.

Validation:

- `python scripts\run_benchmark.py` passed and generated `report/eval_results.md`.
- Manual benchmark assertions passed: 16 total cases, 10/10 attacks detected, 0 blocking false positives.
- `python -m compileall src scripts tests` passed.
- `git diff --check` passed.
- `python -m pytest` could not run in the current machine environment because `pytest` is not installed.
