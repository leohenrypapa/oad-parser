#!/usr/bin/env python3
"""Run unittest discovery and emit minimal JUnit XML evidence."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path


def write_junit_xml(output_path, returncode, elapsed):
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    suite = ET.Element(
        "testsuite",
        {
            "name": "oad_parser.unittest.discover",
            "tests": "1",
            "failures": "0" if returncode == 0 else "1",
            "errors": "0",
            "skipped": "0",
            "time": "%.6f" % elapsed,
        },
    )
    case = ET.SubElement(
        suite,
        "testcase",
        {
            "classname": "unittest.discover",
            "name": "oad_parser_tests",
            "time": "%.6f" % elapsed,
        },
    )
    if returncode != 0:
        failure = ET.SubElement(case, "failure", {"message": "unittest discovery failed"})
        failure.text = "See CI or terminal output for unittest failure details."
    system_out = ET.SubElement(case, "system-out")
    system_out.text = "unittest discovery return code: %s" % returncode
    ET.ElementTree(suite).write(str(output), encoding="utf-8", xml_declaration=True)


def main():
    parser = argparse.ArgumentParser(description="Run unittest discovery and emit JUnit XML.")
    parser.add_argument("--tests-dir", default="oad_parser/tests")
    parser.add_argument("--pattern", default="test_*.py")
    parser.add_argument("--output", default="reports/tests/junit.xml")
    args = parser.parse_args()

    if not Path(args.tests_dir).exists():
        raise SystemExit("tests directory not found: %s" % args.tests_dir)

    command = [
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "-s",
        args.tests_dir,
        "-p",
        args.pattern,
    ]
    started = time.monotonic()
    result = subprocess.run(command, check=False)
    elapsed = time.monotonic() - started
    write_junit_xml(args.output, result.returncode, elapsed)
    print("wrote JUnit XML: %s" % args.output)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
