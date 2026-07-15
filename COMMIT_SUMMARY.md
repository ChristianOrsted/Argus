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

## Stage 3 - Intent judge interface and audit trail

Commit message: `feat: add intent judge and audit logging`

Completed scope:

- Replace the `IntentLayer` TODO with a tested, pluggable judge interface.
- Add `DeepSeekIntentJudge` for DeepSeek/OpenAI-compatible JSON judging.
- Keep intent judging disabled by default so offline demos and tests do not require API keys.
- Add structured JSONL audit logging for ToolCall, context summary, verdicts, and decisions.
- Wire audit logging into the offline demo under `sandbox_runs/audit/offline_demo.jsonl`.
- Add unit tests for intent decisions and audit record shape.

Validation:

- `python scripts\offline_demo.py` passed and wrote `sandbox_runs/audit/offline_demo.jsonl`.
- `python scripts\run_benchmark.py` passed and refreshed `report/eval_results.md`.
- Manual intent judge assertion passed.
- Manual audit record assertion passed.
- `python -m compileall src scripts tests` passed.
- `git diff --check` passed.
- `python -m pytest` could not run in the current machine environment because `pytest` is not installed.

## Stage 4 - Report and reproducible attack replay

Commit message: `docs: add final report and replay workflow`

Completed scope:

- Add `scripts/replay_case.py` to reproduce a single attack or benign case by ID.
- Add `report/final_report.md` as a course-ready report draft covering threat model, design, implementation, red team, evaluation, demo, limits, and division of work.
- Update README with replay and benchmark commands.
- Mark the report outline deliverable checklist as complete with concrete file paths.

Validation:

- `python scripts\replay_case.py ii-001` passed.
- `python scripts\replay_case.py bn-005` passed.
- `python scripts\run_benchmark.py` passed and refreshed `report/eval_results.md`.
- `python -m compileall src scripts tests` passed.
- `git diff --check` passed.
- `python -m pytest` could not run in the current machine environment because `pytest` is not installed.

## Stage 5 - Project overview and pytest verification

Commit message: `docs: add project overview and verification guide`

Completed scope:

- Add `docs/project_overview.md` as a top-level explanation of project goal, modules, deliverables, and acceptance workflow.
- Link the overview from `README.md`.
- Refresh `report/eval_results.md` from the latest benchmark run.
- Re-run validation after pytest was installed in `.venv`.

Validation:

- `.\.venv\Scripts\python -m pytest` passed: 20 tests passed.
- `.\.venv\Scripts\python scripts\offline_demo.py` passed.
- `.\.venv\Scripts\python scripts\replay_case.py ii-001` passed.
- `.\.venv\Scripts\python scripts\run_benchmark.py` passed.
- `.\.venv\Scripts\python -m compileall src scripts tests` passed.
- DeepSeek online Agent smoke test passed with a temporary runtime key; no key was written to tracked files.
- DeepSeek online intent judge smoke test passed with a temporary runtime key; no key was written to tracked files.

## Stage 6 - Fragment-level taint tracking

Commit message: `feat: add fragment-level taint tracking`

Completed scope:

- Add `TaintedFragment` to Guardian context.
- Extract tainted snippets from `web_fetch` and `read_file` outputs with source, digest, and origin tool id.
- Register fragment-level taint from both DeepSeek and Anthropic agent loops.
- Upgrade `TaintLayer` to detect exact tainted-fragment flow into high-privilege tool inputs.
- Include tainted fragment evidence in JSONL audit records.
- Add tests for fragment extraction, registration, BLOCK, and FLAG paths.

Validation:

- `.\.venv\Scripts\python -m pytest` passed: 24 tests passed.
- `.\.venv\Scripts\python scripts\offline_demo.py` passed.
- `.\.venv\Scripts\python scripts\run_benchmark.py` passed.
- `.\.venv\Scripts\python -m compileall src scripts tests` passed.

## Stage 7 - DeepSeek intent judge online evaluation

Commit message: `feat: add deepseek intent judge evaluation`

Completed scope:

- Add intent judge evaluation cases covering consistent and inconsistent tool calls.
- Add reusable evaluation logic and Markdown report output.
- Add `scripts/run_intent_judge_eval.py`, which reads the DeepSeek API key from env or hidden input only.
- Add fake-judge unit tests for the evaluation path.

Validation:

- `.\.venv\Scripts\python -m pytest` passed: 25 tests passed.
- `.\.venv\Scripts\python scripts\run_intent_judge_eval.py` passed with a temporary runtime key: 5/5 cases correct.
- `.\.venv\Scripts\python -m compileall src scripts tests` passed.
- `git diff --check` passed.
- API key was provided only through hidden runtime input and was not written to tracked files.

## Stage 8 - Public jailbreak dataset conversion

Commit message: `feat: add public jailbreak dataset converter`

Completed scope:

- Add a flexible converter for AdvBench/JailbreakBench-style CSV/JSON/JSONL files.
- Support common request fields such as `goal`, `prompt`, `behavior`, `instruction`, `question`, and `query`.
- Add a small AdvBench-style sample and generated Argus jsonl seed.
- Add converter CLI and tests.
- Add `docs/update_log.md` to record future grouped changes and verification steps.

Validation:

- `.\.venv\Scripts\python scripts\convert_public_jailbreaks.py datasets\public_samples\advbench_sample.csv datasets\public_jailbreak_seed.jsonl --source advbench` passed: 3 rows converted.
- `.\.venv\Scripts\python -m pytest` passed: 27 tests passed.
- `.\.venv\Scripts\python -m compileall src scripts tests` passed.
- `git diff --check` passed.
- `git grep -n "sk-"` found only placeholder examples, no real API key.

## Stage 9 - Web dashboard and project self-audit

Commit message: `feat: add guardian dashboard`

Completed scope:

- Add a polished local web dashboard for the Argus Guardian prototype.
- Add `scripts/dashboard_server.py` with static serving and JSON API endpoints.
- Support case selection, full benchmark summary, layer statistics, threat coverage, custom ToolCall evaluation, and in-page audit stream.
- Harden dashboard rendering and static-file serving with HTML escaping, tainted-source input normalization, and path traversal protection.
- Add `docs/project_self_audit.md` to list remaining improvement areas.
- Record this change in `docs/update_log.md`.

Validation:

- Dashboard page smoke test passed: `GET http://127.0.0.1:8766/` returned `200`.
- Dashboard summary API smoke test passed: 16 total cases, 10 detected cases, 9 block actions, 2 flag actions.
- Dashboard case evaluation smoke test passed: `POST /api/evaluate` for `ii-001` returned `block`.
- Dashboard custom evaluation smoke test passed: `POST /api/custom` for `run_shell {"command":"rm -rf /"}` returned `block`.
- `.\.venv\Scripts\python -m pytest` passed: 32 tests passed.
- `.\.venv\Scripts\python -m compileall src scripts tests` passed.
- `git diff --check` passed.

## Stage 10 - Attack surface lab and DeepSeek red-team dashboard

Commit message: `feat: add deepseek redteam dashboard lab`

Completed scope:

- Add `src/redteam/surface_lab.py` with seven independent attack-surface specs.
- Cover prompt injection, model jailbreak, training-data leakage, tool hijacking, memory poisoning, environment pollution, and indirect prompt injection.
- Add Dashboard APIs for attack-surface listing, offline per-surface rerun, and DeepSeek-generated red-team runs.
- Extend the frontend with an attack-surface lab where every surface can be rerun independently.
- Extend the frontend with a DeepSeek Red Team panel that shows generated attack request, generated ToolCall, risk points, danger explanation, and Guardian decision.
- Support optional DeepSeek intent judge during the dashboard red-team run.
- Update `docs/project_overview.md`, `README.md`, and `docs/update_log.md` with the new operating workflow.

Validation:

- `.\.venv\Scripts\python -m pytest` passed: 36 tests passed.
- `.\.venv\Scripts\python -m compileall src scripts tests` passed.
- Dashboard page smoke test passed: `GET /` returned `200`.
- Attack-surface API smoke test passed: `GET /api/attack-surfaces` returned 7 surfaces.
- Offline per-surface rerun smoke test passed: `memory_poison` returned `block`.
- DeepSeek online red-team smoke test passed: `prompt_injection` generated `delete_database`, Guardian returned `block`.
- DeepSeek online red-team with intent judge smoke test passed: `tool_hijack` generated `run_shell`, Guardian returned `block`.
- API key was provided only through hidden runtime input or a local ephemeral request and was not written to tracked files.

## Stage 11 - Dashboard history and DeepSeek attack hardening

Commit message: `feat: add dashboard history and harden attack detection`

Completed scope:

- Harden `PolicyLayer` against DeepSeek-generated variants that use `cmd`, `script`, or other shell parameter names instead of `command`.
- Block suspicious red-team/exfil URLs such as `evil.example` and high-risk URL paths.
- Block external URL content being written into long-term memory.
- Block sensitive path reads and sensitive environment variable exfiltration.
- Harden `TaintLayer` so untrusted sources triggering shell or writing `memory` / `plans` / `config` style files become `BLOCK` instead of a soft `FLAG`.
- Add default tainted-source inference for DeepSeek-generated memory poisoning, environment pollution, and indirect injection cases.
- Add a persistent Dashboard SQLite history store at `sandbox_runs/audit/dashboard_history.sqlite3`.
- Add `/api/history` and `/api/history/clear`.
- Update the frontend audit stream, metric cards, threat coverage, and four-layer stats to dynamically reflect historical user requests.
- Update `README.md`, `docs/project_overview.md`, and `docs/update_log.md`.

Validation:

- `.\.venv\Scripts\python -m pytest` passed: 45 tests passed.
- `.\.venv\Scripts\python -m compileall src scripts tests` passed.
- Dashboard fixed-port smoke test passed: `GET http://127.0.0.1:8765/` returned `200`.
- Memory poisoning smoke test passed: fetching `https://evil.example/security/config.txt` for long-term memory returned `block`.
- Tool hijacking smoke test passed: `run_shell {"cmd":"ls /backup && rm -rf /data/db"}` returned `block`.
- Indirect injection smoke test passed: tainted `web_fetch` content written to `plans/next_steps.txt` returned `block`.
- History API smoke test passed: `/api/history` returned persisted requests and dynamic layer stats.
- DeepSeek online red-team retest passed: `memory_poison`, `tool_hijack`, and `indirect_injection` all returned `block`.
- API key was provided only through hidden runtime input or a local ephemeral request and was not written to tracked files.

## Stage 12 - Batch red-team matrix and adaptive defense analysis

Commit message: `feat: add batch redteam matrix and adaptive analysis`

Completed scope:

- Add `Context.metadata` so DeepSeek red-team risk points and danger explanations can participate in Guardian decisions.
- Add constrained adaptive defense rules in `src/guardian/adaptive_rules.py`.
- Harden `PolicyLayer` against tool-hijack cases where the current tool call is only `web_fetch` but red-team metadata indicates later `delete_database`, `send_http`, exfiltration, or non-whitelisted actions.
- Add DeepSeek batch generation with configurable count and prompt override.
- Add DeepSeek missed-detection analysis that returns a reason, suggested constrained rules, applies those rules, and rechecks the same attack.
- Add Dashboard APIs: `/api/deepseek-redteam-batch` and `/api/analyze-miss`.
- Replace the single DeepSeek result display with a batch matrix showing item info, total status, and layer statuses 1-4.
- Allow clicking a batch row to inspect the exact red-team JSON and Guardian verdicts.
- Add "analyze missed detection" action for non-blocked rows.
- Update README, project overview, self-audit, and update log.

Validation:

- `.\.venv\Scripts\python -m pytest` passed: 51 tests passed.
- `.\.venv\Scripts\python -m compileall src scripts tests` passed.
- Dashboard fixed-port smoke test passed: `GET http://127.0.0.1:8765/` returned `200`.
- Tool-hijack exfil smoke test passed: `web_fetch` for `internal.example.com` with user-requested `evil.example` upload returned `block`.
- DeepSeek batch red-team smoke test passed: `tool_hijack` generated 2 attacks and both returned `block` with per-layer statuses.
- DeepSeek missed-detection analysis smoke test passed: DeepSeek produced a reason and one constrained adaptive rule; rechecking the same item returned `block`.
- API key was provided only through hidden runtime input or a local ephemeral request and was not written to tracked files.
