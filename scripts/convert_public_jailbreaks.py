"""转换 AdvBench/JailbreakBench 风格公开数据集为 Argus jsonl。

示例：
    python scripts\convert_public_jailbreaks.py datasets\public_samples\advbench_sample.csv datasets\public_jailbreak_seed.jsonl --source advbench
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.redteam.dataset_converter import convert_rows, read_public_dataset, write_jsonl


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert public jailbreak datasets to Argus jsonl")
    parser.add_argument("input", help="Input CSV/JSON/JSONL file")
    parser.add_argument("output", help="Output Argus JSONL file")
    parser.add_argument("--source", default="public", help="Source prefix, e.g. advbench or jailbreakbench")
    args = parser.parse_args()

    rows = read_public_dataset(args.input)
    converted = convert_rows(rows, source=args.source)
    write_jsonl(converted, args.output)
    print(f"Converted {len(converted)} rows -> {args.output}")


if __name__ == "__main__":
    main()
