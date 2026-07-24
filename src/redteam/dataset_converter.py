"""公开越狱/对抗数据集格式转换工具。

目标是把 AdvBench、JailbreakBench 或类似公开数据集中的 prompt/goal/behavior
字段统一转换为 Argus 使用的 jsonl 样本格式。
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

REQUEST_FIELDS = ("user_request", "prompt", "goal", "behavior", "instruction", "question", "query")
ID_FIELDS = ("id", "case_id", "behavior_id", "idx")
CATEGORY_FIELDS = ("category", "source_category", "behavior_type", "attack_type")


def _read_json_or_jsonl(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "examples", "behaviors", "items"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    raise ValueError(f"Unsupported JSON root in {path}")


def read_public_dataset(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as fh:
            return list(csv.DictReader(fh))
    if suffix in {".json", ".jsonl"}:
        return _read_json_or_jsonl(path)
    raise ValueError(f"Unsupported dataset extension: {path.suffix}")


def _first_present(row: dict[str, Any], fields: tuple[str, ...]) -> Any:
    for field in fields:
        value = row.get(field)
        if value not in (None, ""):
            return value
    return None


def convert_rows(rows: list[dict[str, Any]], source: str) -> list[dict[str, Any]]:
    converted: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        request = _first_present(row, REQUEST_FIELDS)
        if request is None:
            raise ValueError(f"Row {index} does not contain any request field: {REQUEST_FIELDS}")

        raw_id = _first_present(row, ID_FIELDS) or f"{index:04d}"
        raw_category = _first_present(row, CATEGORY_FIELDS) or "jailbreak"
        case_id = str(raw_id)
        if not case_id.startswith(f"{source}-"):
            case_id = f"{source}-{case_id}"

        converted.append({
            "id": case_id,
            "category": str(raw_category),
            "user_request": str(request),
            "should_block": True,
            "source": source,
            "original": row,
        })
    return converted


def write_jsonl(rows: list[dict[str, Any]], output_path: str | Path) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
