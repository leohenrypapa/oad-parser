"""End-to-end local platform validation."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from oad_parser.corpus import validate_corpus_path
from oad_parser.corpus_report import summarize_corpus_report
from oad_parser.fixture_samples import generate_fixture_samples
from oad_parser.golden import check_golden_fixture


@dataclass(frozen=True)
class PlatformValidationReport:
    output_dir: str
    kept_output_dir: bool
    run_tests: bool
    tests_passed: bool | None
    tests_output: str | None
    generated_files: tuple[str, ...]
    raw_golden_match: bool
    pcap_golden_match: bool
    corpus_files_scanned: int
    corpus_files_with_errors: int
    corpus_comparison_count: int
    corpus_match_count: int
    corpus_mismatch_count: int
    passed: bool
    summary_text: str

    def to_dict(self) -> dict[str, object]:
        return {
            "output_dir": self.output_dir,
            "kept_output_dir": self.kept_output_dir,
            "run_tests": self.run_tests,
            "tests_passed": self.tests_passed,
            "tests_output": self.tests_output,
            "generated_files": list(self.generated_files),
            "raw_golden_match": self.raw_golden_match,
            "pcap_golden_match": self.pcap_golden_match,
            "corpus_files_scanned": self.corpus_files_scanned,
            "corpus_files_with_errors": self.corpus_files_with_errors,
            "corpus_comparison_count": self.corpus_comparison_count,
            "corpus_match_count": self.corpus_match_count,
            "corpus_mismatch_count": self.corpus_mismatch_count,
            "passed": self.passed,
            "summary_text": self.summary_text,
        }


def validate_platform(
    output_dir: str | Path | None = None,
    run_tests: bool = False,
) -> PlatformValidationReport:
    if output_dir is None:
        with tempfile.TemporaryDirectory() as tmp:
            return _validate_platform_in_dir(Path(tmp), kept_output_dir=False, run_tests=run_tests)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    return _validate_platform_in_dir(output_path, kept_output_dir=True, run_tests=run_tests)


def format_platform_validation_report(report: PlatformValidationReport) -> str:
    lines = [
        "Parser platform validation",
        f"Passed: {str(report.passed).lower()}",
        f"Output dir: {report.output_dir}",
        f"Kept output dir: {str(report.kept_output_dir).lower()}",
        f"Generated files: {len(report.generated_files)}",
        f"Raw golden match: {str(report.raw_golden_match).lower()}",
        f"Pcap golden match: {str(report.pcap_golden_match).lower()}",
        f"Corpus files scanned: {report.corpus_files_scanned}",
        f"Corpus files with errors: {report.corpus_files_with_errors}",
        f"Corpus comparisons: {report.corpus_comparison_count}",
        f"Corpus matches: {report.corpus_match_count}",
        f"Corpus mismatches: {report.corpus_mismatch_count}",
    ]

    if report.run_tests:
        lines.append(f"Tests passed: {str(report.tests_passed).lower()}")

    lines.extend(
        [
            "",
            "Generated files:",
            *[f"- {file_name}" for file_name in report.generated_files],
            "",
            report.summary_text.rstrip(),
        ]
    )

    return "\n".join(lines).rstrip() + "\n"


def _validate_platform_in_dir(
    output_dir: Path,
    kept_output_dir: bool,
    run_tests: bool,
) -> PlatformValidationReport:
    tests_passed: bool | None = None
    tests_output: str | None = None

    if run_tests:
        test_result = subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                "oad_parser/tests",
                "-p",
                "test_*.py",
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        tests_passed = test_result.returncode == 0
        tests_output = test_result.stdout

    fixture_result = generate_fixture_samples(output_dir)

    raw_check = check_golden_fixture(output_dir / "sample.raw-payload.golden.json")
    pcap_check = check_golden_fixture(output_dir / "sample.pcap.golden.json")

    corpus_report = validate_corpus_path(output_dir)
    corpus_report_dict = corpus_report.to_dict()
    summary_text = summarize_corpus_report(corpus_report_dict, show_matches=True)

    passed = (
        raw_check.match
        and pcap_check.match
        and corpus_report.files_with_errors == 0
        and corpus_report.mismatch_count == 0
        and (tests_passed is not False)
    )

    return PlatformValidationReport(
        output_dir=str(output_dir),
        kept_output_dir=kept_output_dir,
        run_tests=run_tests,
        tests_passed=tests_passed,
        tests_output=tests_output,
        generated_files=fixture_result.files,
        raw_golden_match=raw_check.match,
        pcap_golden_match=pcap_check.match,
        corpus_files_scanned=corpus_report.files_scanned,
        corpus_files_with_errors=corpus_report.files_with_errors,
        corpus_comparison_count=corpus_report.comparison_count,
        corpus_match_count=corpus_report.match_count,
        corpus_mismatch_count=corpus_report.mismatch_count,
        passed=passed,
        summary_text=summary_text,
    )
