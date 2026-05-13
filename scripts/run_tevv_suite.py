#!/usr/bin/env python3
"""Run release-hardening TEVV gates and emit structured evidence.

The runner orchestrates existing repo validation commands. It does not inspect
real PCAPs, capture traffic, add parser semantics, or generate customer packs.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT_DIR = Path("reports/tevv")
PASS_STATUSES = {"passed", "skipped", "not_applicable"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def command_text(command: List[str]) -> str:
    return shlex.join(command)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def run_command_gate(
    *,
    name: str,
    owner_role: str,
    profile: str,
    classification: str,
    command: List[str],
    report_dir: Path,
    stdout_path: Optional[Path] = None,
    stderr_path: Optional[Path] = None,
    expected_return_code: int = 0,
    evidence_files: Optional[List[Path]] = None,
    limitations: Optional[List[str]] = None,
    pass_json_path: Optional[Path] = None,
    pass_json_expr: Optional[str] = None,
) -> Dict[str, Any]:
    start_time = utc_now()
    started = datetime.now(timezone.utc)

    result = subprocess.run(
        command,
        cwd=str(REPO_ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    end_time = utc_now()

    evidence = list(evidence_files or [])
    if stdout_path is not None:
        write_text(stdout_path, result.stdout)
        evidence.append(stdout_path)
    if stderr_path is not None:
        write_text(stderr_path, result.stderr)
        evidence.append(stderr_path)

    status = "passed" if result.returncode == expected_return_code else "failed"
    gate_limitations = list(limitations or [])

    if status == "passed" and pass_json_path is not None and pass_json_expr is not None:
        try:
            data = load_json(pass_json_path)
            if not bool(eval(pass_json_expr, {}, {"data": data})):
                status = "failed"
                gate_limitations.append("JSON pass expression evaluated false: %s" % pass_json_expr)
        except Exception as exc:
            status = "failed"
            gate_limitations.append("JSON pass expression error: %s" % exc)

    elapsed_seconds = (datetime.now(timezone.utc) - started).total_seconds()

    return {
        "gate": name,
        "owner_role": owner_role,
        "classification": classification,
        "command": command_text(command),
        "profile": profile,
        "start_time": start_time,
        "end_time": end_time,
        "elapsed_seconds": elapsed_seconds,
        "return_code": result.returncode,
        "status": status,
        "evidence_files": [rel(item) for item in evidence],
        "limitations": gate_limitations,
    }


def skipped_gate(
    *,
    name: str,
    owner_role: str,
    profile: str,
    classification: str,
    command: str,
    evidence_files: Optional[List[str]] = None,
    limitations: Optional[List[str]] = None,
    status: str = "skipped",
) -> Dict[str, Any]:
    now = utc_now()
    return {
        "gate": name,
        "owner_role": owner_role,
        "classification": classification,
        "command": command,
        "profile": profile,
        "start_time": now,
        "end_time": now,
        "elapsed_seconds": 0.0,
        "return_code": None,
        "status": status,
        "evidence_files": evidence_files or [],
        "limitations": limitations or [],
    }


def run_local_gates(args: argparse.Namespace, report_dir: Path) -> List[Dict[str, Any]]:
    py = sys.executable
    gates: List[Dict[str, Any]] = []

    reports_tests = report_dir / "junit.xml"
    platform_json = report_dir / "platform-validation.json"
    source_pack_dir = report_dir / "source-pack"
    source_pack_result = source_pack_dir / "source-pack-result.json"
    source_pack_tar = source_pack_dir / "oad-parser-source-pack-smoke.tar.gz"
    source_pack_check = source_pack_dir / "source-pack-manifest-check.json"
    acceptance_json = report_dir / "live-acceptance-6100pps.json"

    gates.append(
        run_command_gate(
            name="Python version check",
            owner_role="Python maintainer",
            profile=args.profile,
            classification="local",
            command=[
                py,
                "-c",
                "import sys; assert sys.version_info[:3] == (3, 9, 2), sys.version; print(sys.version)",
            ],
            report_dir=report_dir,
            stdout_path=report_dir / "python-version.txt",
            stderr_path=report_dir / "python-version.stderr.txt",
            limitations=["Validates the interpreter used by this TEVV run."],
        )
    )

    gates.append(
        run_command_gate(
            name="Compile and syntax checks",
            owner_role="Python maintainer",
            profile=args.profile,
            classification="local",
            command=[py, "-m", "compileall", "-q", "oad_parser", "scripts"],
            report_dir=report_dir,
            stdout_path=report_dir / "compile.stdout.txt",
            stderr_path=report_dir / "compile.stderr.txt",
            limitations=["Syntax check only; does not validate target runtime behavior."],
        )
    )

    junit_script = REPO_ROOT / "scripts" / "run_tests_junit.py"
    if junit_script.exists():
        unit_command = [
            py,
            "scripts/run_tests_junit.py",
            "--tests-dir",
            "oad_parser/tests",
            "--pattern",
            "test_*.py",
            "--output",
            str(reports_tests),
        ]
    else:
        unit_command = [py, "-m", "unittest", "discover", "-s", "oad_parser/tests", "-p", "test_*.py"]

    gates.append(
        run_command_gate(
            name="Unit tests",
            owner_role="Python maintainer",
            profile=args.profile,
            classification="local",
            command=unit_command,
            report_dir=report_dir,
            stdout_path=report_dir / "unit-tests.stdout.txt",
            stderr_path=report_dir / "unit-tests.stderr.txt",
            evidence_files=[reports_tests] if junit_script.exists() else [],
            limitations=["Uses repo synthetic fixtures only."],
        )
    )

    gates.append(
        run_command_gate(
            name="CLI compatibility",
            owner_role="Python maintainer",
            profile=args.profile,
            classification="local",
            command=[py, "-m", "oad_parser", "--help"],
            report_dir=report_dir,
            stdout_path=report_dir / "cli-help.txt",
            stderr_path=report_dir / "cli-help.stderr.txt",
            limitations=["Dev-only CLI commands may remain; customer sanitization is handled through package profiles and docs."],
        )
    )

    gates.append(
        run_command_gate(
            name="Live CLI compatibility",
            owner_role="Python maintainer",
            profile=args.profile,
            classification="local",
            command=[py, "-m", "oad_parser", "live", "--help"],
            report_dir=report_dir,
            stdout_path=report_dir / "cli-live-help.txt",
            stderr_path=report_dir / "cli-live-help.stderr.txt",
            limitations=["Static CLI help check only; does not open raw sockets."],
        )
    )

    gates.append(
        run_command_gate(
            name="Config validation",
            owner_role="Production maintainer",
            profile=args.profile,
            classification="local",
            command=[
                py,
                "-c",
                "from oad_parser.config import load_live_parser_config; c=load_live_parser_config('config/ecg_conf.example.ini'); assert c.interface; assert c.output_json_file; print(c.interface); print(c.output_json_file)",
            ],
            report_dir=report_dir,
            stdout_path=report_dir / "config-validation.txt",
            stderr_path=report_dir / "config-validation.stderr.txt",
            limitations=["Validates example config only; site config remains target-environment evidence."],
        )
    )

    gates.append(
        run_command_gate(
            name="Parser correctness",
            owner_role="Python maintainer",
            profile=args.profile,
            classification="local",
            command=[py, "-m", "oad_parser", "validate-platform", "--json"],
            report_dir=report_dir,
            stdout_path=platform_json,
            stderr_path=report_dir / "platform-validation.stderr.txt",
            evidence_files=[platform_json],
            pass_json_path=platform_json,
            pass_json_expr='data.get("passed") is True',
            limitations=["Synthetic platform validation only; no operational radar semantic validation."],
        )
    )

    gates.append(
        run_command_gate(
            name="Systemd template static validation",
            owner_role="Production maintainer",
            profile=args.profile,
            classification="local",
            command=[py, "-m", "unittest", "oad_parser.tests.test_systemd_template"],
            report_dir=report_dir,
            stdout_path=report_dir / "systemd-template.stdout.txt",
            stderr_path=report_dir / "systemd-template.stderr.txt",
            limitations=["Static validation only; root/systemd target execution remains a target gate."],
        )
    )

    gates.append(
        run_command_gate(
            name="Filebeat/Elastic handoff docs",
            owner_role="SIEM engineer and release engineer",
            profile=args.profile,
            classification="local",
            command=[py, "-m", "unittest", "oad_parser.tests.test_filebeat_elastic_handoff"],
            report_dir=report_dir,
            stdout_path=report_dir / "filebeat-elastic-handoff.stdout.txt",
            stderr_path=report_dir / "filebeat-elastic-handoff.stderr.txt",
            limitations=["Static documentation validation only; SIEM owner must confirm site-specific Filebeat/Elastic Agent 8.17.3 config."],
        )
    )

    gates.append(
        run_command_gate(
            name="Source-pack hygiene smoke",
            owner_role="Release engineer",
            profile=args.profile,
            classification="local",
            command=[
                py,
                "-m",
                "oad_parser",
                "create-source-pack",
                "--output",
                str(source_pack_tar),
                "--tracked-only",
                "--json",
            ],
            report_dir=report_dir,
            stdout_path=source_pack_result,
            stderr_path=source_pack_dir / "source-pack-result.stderr.txt",
            evidence_files=[source_pack_result, source_pack_tar],
            limitations=["Internal engineering source pack remains separate from customer runtime/operator handoff pack."],
        )
    )

    gates.append(
        run_command_gate(
            name="Source-pack manifest check",
            owner_role="Release engineer",
            profile=args.profile,
            classification="local",
            command=[
                py,
                "scripts/check_source_pack_manifest.py",
                "--pack",
                str(source_pack_tar),
                "--output-json",
                str(source_pack_check),
            ],
            report_dir=report_dir,
            stdout_path=source_pack_dir / "source-pack-manifest-check.stdout.txt",
            stderr_path=source_pack_dir / "source-pack-manifest-check.stderr.txt",
            evidence_files=[source_pack_check],
            pass_json_path=source_pack_check,
            pass_json_expr='data.get("status") == "pass"',
            limitations=["Validates internal engineering source-pack hygiene, not customer-pack hygiene."],
        )
    )

    gates.append(
        skipped_gate(
            name="customer-pack validation",
            owner_role="Release engineer and sanitization reviewer",
            profile=args.profile,
            classification="planned local",
            command="planned scripts/make_customer_pack.sh and scripts/validate_customer_pack.py",
            evidence_files=["reports/customer-pack/customer-pack-validation.json"],
            limitations=["skipped until Issue #40 and Issue #41 implement customer-pack generation and validation."],
        )
    )

    gates.append(
        run_command_gate(
            name="6100 PPS synthetic acceptance",
            owner_role="TEVV planner",
            profile=args.profile,
            classification="local",
            command=[
                py,
                "scripts/run_live_acceptance_6100pps.py",
                "--duration-seconds",
                "1",
                "--target-pps",
                "6100",
                "--output",
                str(acceptance_json),
            ],
            report_dir=report_dir,
            stdout_path=report_dir / "live-acceptance-6100pps.stdout.txt",
            stderr_path=report_dir / "live-acceptance-6100pps.stderr.txt",
            evidence_files=[acceptance_json],
            pass_json_path=acceptance_json,
            pass_json_expr='data.get("best_effort_target_met") is True and data.get("contains_real_pcap") is False and data.get("contains_operational_payloads") is False',
            limitations=["Synthetic in-memory frames only; no real PCAP replay, live capture, or operational payloads."],
        )
    )

    gates.append(
        skipped_gate(
            name="Optional one-hour 6100 PPS acceptance",
            owner_role="TEVV planner and production maintainer",
            profile=args.profile,
            classification="optional target",
            command="planned one-hour mode for scripts/run_live_acceptance_6100pps.py",
            evidence_files=["reports/validation/live-acceptance-6100pps-1hr.json"],
            limitations=["skipped because one-hour mode is optional P1 and not implemented in Issue #38."],
        )
    )

    return gates


def add_target_oracle_gates(args: argparse.Namespace) -> List[Dict[str, Any]]:
    root_available = hasattr(os, "geteuid") and os.geteuid() == 0
    limitations = [
        "Manual target-oracle gate.",
        "Oracle Linux Server 9.6 target validation is not claimed by this runner unless executed on target.",
        "Target evidence may contain site-sensitive values and must not be committed by default.",
    ]
    if not root_available:
        limitations.append("skipped because runner is not executing as root.")

    if not args.target_interface:
        limitations.append("skipped because --target-interface was not provided.")

    if not args.target_config:
        limitations.append("skipped because --target-config was not provided.")

    status = "skipped"
    if root_available and args.target_interface and args.target_config:
        limitations.append("Target command execution is intentionally not automated in Issue #38; use the target-environment checklist.")
        status = "skipped"

    return [
        skipped_gate(
            name="target-oracle root runtime and systemd validation",
            owner_role="Production maintainer",
            profile=args.profile,
            classification="target-oracle manual",
            command="docs/release/target-environment-validation.md checklist after Issue #42",
            evidence_files=["reports/target/target-environment-validation.md"],
            limitations=limitations,
            status=status,
        )
    ]


def summarize(gates: List[Dict[str, Any]]) -> str:
    failed = [gate for gate in gates if gate["status"] not in PASS_STATUSES]
    if failed:
        return "failed"
    return "passed"


def write_json_report(report_dir: Path, profile: str, gates: List[Dict[str, Any]]) -> Dict[str, Any]:
    report = {
        "schema_version": "tevv-suite.v1",
        "profile": profile,
        "generated_at_utc": utc_now(),
        "status": summarize(gates),
        "gate_count": len(gates),
        "passed_count": sum(1 for gate in gates if gate["status"] == "passed"),
        "failed_count": sum(1 for gate in gates if gate["status"] == "failed"),
        "skipped_count": sum(1 for gate in gates if gate["status"] == "skipped"),
        "not_applicable_count": sum(1 for gate in gates if gate["status"] == "not_applicable"),
        "gates": gates,
        "limitations": [
            "This runner orchestrates existing local gates and planned/manual target gates.",
            "Generated reports are not committed by default.",
            "No real PCAPs, raw operational payloads, secrets, or runtime outputs are included by this runner.",
            "Customer-pack validation is skipped until Issue #40 and Issue #41 are complete.",
        ],
    }

    report_path = report_dir / "tevv-report.json"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def write_manifest(report_dir: Path, report: Dict[str, Any]) -> None:
    files = []
    for gate in report["gates"]:
        files.extend(gate.get("evidence_files", []))
    files.extend([rel(report_dir / "tevv-report.json"), rel(report_dir / "tevv-report.md")])

    manifest = {
        "schema_version": "tevv-evidence-manifest.v1",
        "generated_at_utc": utc_now(),
        "profile": report["profile"],
        "status": report["status"],
        "evidence_files": sorted(set(files)),
        "committed_by_default": False,
        "limitations": [
            "Evidence paths under reports/ are generated artifacts and are not committed by default.",
            "Review target evidence for site-sensitive values before sharing.",
        ],
    }

    (report_dir / "tevv-evidence-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_markdown_report(report_dir: Path, report: Dict[str, Any]) -> None:
    lines = [
        "# TEVV Suite Report",
        "",
        "- Profile: `%s`" % report["profile"],
        "- Status: `%s`" % report["status"],
        "- Generated at UTC: `%s`" % report["generated_at_utc"],
        "- Gate count: `%s`" % report["gate_count"],
        "- Passed: `%s`" % report["passed_count"],
        "- Failed: `%s`" % report["failed_count"],
        "- Skipped: `%s`" % report["skipped_count"],
        "",
        "Generated reports under `reports/` are not committed by default.",
        "",
        "## Gates",
        "",
        "| Gate | Status | Classification | Evidence | Limitations |",
        "|---|---|---|---|---|",
    ]

    for gate in report["gates"]:
        evidence = "<br>".join("`%s`" % item for item in gate.get("evidence_files", [])) or "-"
        limitations = "<br>".join(gate.get("limitations", [])) or "-"
        lines.append(
            "| %s | `%s` | %s | %s | %s |"
            % (
                gate["gate"],
                gate["status"],
                gate["classification"],
                evidence,
                limitations,
            )
        )

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- customer-pack validation is intentionally `skipped` until Issue #40 and Issue #41 are complete.")
    lines.append("- 6100 PPS synthetic acceptance is local synthetic evidence only.")
    lines.append("- Optional one-hour 6100 PPS acceptance is P1 and not a blocker for initial customer handoff.")
    lines.append("")

    (report_dir / "tevv-report.md").write_text("\n".join(lines), encoding="utf-8")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run OAD parser TEVV release-hardening gates.")
    parser.add_argument("--profile", choices=["local", "target-oracle"], default="local")
    parser.add_argument("--report-dir", default=str(DEFAULT_REPORT_DIR))
    parser.add_argument("--target-interface", default="", help="Target ECG interface for target-oracle checklist context.")
    parser.add_argument("--target-config", default="", help="Target config path for target-oracle checklist context.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    report_dir = Path(args.report_dir)

    gates = run_local_gates(args, report_dir)

    if args.profile == "target-oracle":
        gates.extend(add_target_oracle_gates(args))

    report = write_json_report(report_dir, args.profile, gates)
    write_markdown_report(report_dir, report)
    write_manifest(report_dir, report)

    print("TEVV suite complete")
    print("profile=%s" % args.profile)
    print("status=%s" % report["status"])
    print("report=%s" % rel(report_dir / "tevv-report.json"))
    print("markdown=%s" % rel(report_dir / "tevv-report.md"))
    print("manifest=%s" % rel(report_dir / "tevv-evidence-manifest.json"))

    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
