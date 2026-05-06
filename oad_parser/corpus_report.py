"""Human-readable summaries for corpus validation reports."""

from __future__ import annotations

DEFAULT_SUMMARY_LIMIT = 20
SUMMARY_JSON_INDENT = 3

import json
from pathlib import Path
from typing import Any


def load_corpus_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def summarize_corpus_report(
    report: dict[str, Any],
    show_matches: bool = False,
    limit: int = DEFAULT_SUMMARY_LIMIT,
) -> str:
    if limit < 1:
        raise ValueError("limit must be >= 1")

    files = list(report.get("files", []))
    error_files = [item for item in files if item.get("error")]
    mismatch_files = [
        item
        for item in files
        if not item.get("error") and int(item.get("mismatch_count", 0)) > 0
    ]
    zero_comparison_files = [
        item
        for item in files
        if not item.get("error") and int(item.get("comparison_count", 0)) == 0
    ]
    matched_files = [
        item
        for item in files
        if not item.get("error")
        and int(item.get("comparison_count", 0)) > 0
        and int(item.get("mismatch_count", 0)) == 0
    ]

    lines = [
        "Corpus validation summary",
        f"Root: {report.get('root', '')}",
        f"Files scanned: {int(report.get('files_scanned', 0))}",
        f"Files with errors: {int(report.get('files_with_errors', 0))}",
        f"Comparisons: {int(report.get('comparison_count', 0))}",
        f"Matches: {int(report.get('match_count', 0))}",
        f"Mismatches: {int(report.get('mismatch_count', 0))}",
        f"Zero-comparison files: {int(report.get('zero_comparison_file_count', len(zero_comparison_files)))}",
        "",
    ]

    lines.extend(_section_lines("File errors", error_files, limit, include_error=True))
    lines.append("")
    lines.extend(_section_lines("Mismatched files", mismatch_files, limit, include_error=False))
    lines.append("")
    lines.extend(_section_lines("Zero-comparison files", zero_comparison_files, limit, include_error=False))

    if show_matches:
        lines.append("")
        lines.extend(_section_lines("Matched files", matched_files, limit, include_error=False))

    return "\n".join(lines).rstrip() + "\n"


def _section_lines(
    title: str,
    items: list[dict[str, Any]],
    limit: int,
    include_error: bool,
) -> list[str]:
    lines = [f"{title}: {len(items)}"]
    if not items:
        lines.append("- none")
        return lines

    for item in items[:limit]:
        line = (
            f"- {item.get('path', '')} "
            f"kind={item.get('kind', '')} "
            f"comparisons={int(item.get('comparison_count', 0))} "
            f"matches={int(item.get('match_count', 0))} "
            f"mismatches={int(item.get('mismatch_count', 0))}"
        )
        if include_error:
            line += f" error={item.get('error')}"
        lines.append(line)

        if not include_error and int(item.get("mismatch_count", 0)) > 0:
            for mismatch in _first_mismatches(item, limit=3):
                lines.append(
                    "  - "
                    f"comparison_index={mismatch.get('comparison_index')} "
                    f"field={mismatch.get('field')} "
                    f"legacy={mismatch.get('legacy')} "
                    f"envelope={mismatch.get('envelope')}"
                )

    remaining = len(items) - limit
    if remaining > 0:
        lines.append(f"- ... {remaining} more")

    return lines


def _first_mismatches(item: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    for comparison in item.get("comparisons", []):
        comparison_index = comparison.get("index")
        for mismatch in comparison.get("mismatches", []):
            collected.append(
                {
                    "comparison_index": comparison_index,
                    "field": mismatch.get("field"),
                    "legacy": mismatch.get("legacy"),
                    "envelope": mismatch.get("envelope"),
                }
            )
            if len(collected) >= limit:
                return collected
    return collected
