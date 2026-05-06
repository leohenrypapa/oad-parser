"""JSONL output and validation helpers.

Runtime output is newline-delimited JSON: one parsed record per line. This is
simple to inspect with shell tools and works well with log ingestion pipelines.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Literal

from oad_parser.models import ParsedPlot

SchemaName = Literal["ecs", "legacy"]


def record_to_dict(record: ParsedPlot, schema: SchemaName = "ecs") -> dict:
    if schema == "ecs":
        return record.to_ecs_dict()
    if schema == "legacy":
        return record.to_legacy_dict()
    raise ValueError(f"unsupported schema: {schema}")


def write_jsonl(records: Iterable[ParsedPlot], output_path: str | Path, schema: SchemaName = "ecs") -> int:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record_to_dict(record, schema=schema), sort_keys=True))
            handle.write("\n")
            count += 1

    return count


def validate_jsonl(path: str | Path) -> tuple[int, list[str]]:
    errors: list[str] = []
    count = 0

    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                json.loads(stripped)
            except json.JSONDecodeError as exc:
                errors.append(f"line {line_number}: {exc}")
            else:
                count += 1

    return count, errors
