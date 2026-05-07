#!/usr/bin/env python3
"""Validate OAD source-pack manifest reviewability and safety."""

from __future__ import annotations

import argparse
import json
import re
import tarfile
from datetime import datetime, timezone
from pathlib import PurePosixPath

REQUIRED_KEYS = {
    "schema_version",
    "generated_at_utc",
    "source_repository_identifier",
    "selected_profile",
    "task_scope",
    "included_paths",
    "excluded_paths",
    "file_count",
    "byte_count",
    "file_hashes",
    "warnings",
    "validation",
    "manual_controls",
}

FORBIDDEN_INCLUDED_PATTERNS = [
    r"(^|/)\.git(/|$)",
    r"(^|/)(__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.venv|venv)(/|$)",
    r"\.(pcap|pcapng|cap|bin|payload|ecg|jsonl|log|tmp|tar|gz|zip)$",
    r"(^|/)(credentials|token|secret|private[_-]?key)(\.|$)",
    r"(^|/)reports(/|$)",
]

LOCAL_PATH_PATTERNS = [
    r"/home/",
    r"/mnt/",
    r"/Users/",
    r"[A-Za-z]:\\\\",
]

REQUIRED_MANUAL_TERMS = [
    "GitLab",
    "CODEOWNERS",
    "Registry1",
    "controlled-data",
]


def load_manifest_from_pack(pack_path):
    with tarfile.open(pack_path, "r:gz") as archive:
        try:
            member = archive.getmember("SOURCE-PACK-MANIFEST.json")
        except KeyError:
            raise SystemExit("SOURCE-PACK-MANIFEST.json missing from source pack")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise SystemExit("SOURCE-PACK-MANIFEST.json could not be read")
        data = json.loads(extracted.read().decode("utf-8"))
        names = set(archive.getnames())
    return data, names


def has_term(items, term):
    needle = term.lower()
    return needle in json.dumps(items, sort_keys=True).lower()


def validate(pack_path):
    findings = []
    data, names = load_manifest_from_pack(pack_path)

    missing = sorted(REQUIRED_KEYS - set(data.keys()))
    for key in missing:
        findings.append({"check": "required_key", "path": "SOURCE-PACK-MANIFEST.json", "message": "missing key: %s" % key})

    included = data.get("included_paths", data.get("files", []))
    if not isinstance(included, list) or not all(isinstance(item, str) for item in included):
        findings.append({"check": "included_paths", "path": "SOURCE-PACK-MANIFEST.json", "message": "included_paths must be a list of strings"})
        included = []

    legacy_files = data.get("files", [])
    if legacy_files != included:
        findings.append({"check": "legacy_files_match", "path": "SOURCE-PACK-MANIFEST.json", "message": "files must match included_paths for extracted-pack reuse"})

    if data.get("file_count") != len(included):
        findings.append({"check": "file_count", "path": "SOURCE-PACK-MANIFEST.json", "message": "file_count must match included_paths length"})

    packaged_files = names - {"SOURCE-PACK-MANIFEST.json"}
    if set(included) != packaged_files:
        findings.append({"check": "packaged_files", "path": "SOURCE-PACK-MANIFEST.json", "message": "included_paths must match packaged files"})

    hashes = data.get("file_hashes", {})
    if not isinstance(hashes, dict):
        findings.append({"check": "file_hashes", "path": "SOURCE-PACK-MANIFEST.json", "message": "file_hashes must be an object"})
        hashes = {}
    for item in included:
        digest = hashes.get(item)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            findings.append({"check": "file_hash", "path": item, "message": "missing or invalid sha256"})

    for item in included:
        rel = PurePosixPath(item)
        if item.startswith("/") or ".." in rel.parts:
            findings.append({"check": "safe_relative_path", "path": item, "message": "included path is not safe relative path"})
        for pattern in FORBIDDEN_INCLUDED_PATTERNS:
            if re.search(pattern, item, flags=re.IGNORECASE):
                findings.append({"check": "forbidden_included_path", "path": item, "message": "matches forbidden pattern: %s" % pattern})

    text = json.dumps(data, sort_keys=True)
    for pattern in LOCAL_PATH_PATTERNS:
        if re.search(pattern, text):
            findings.append({"check": "local_path_leakage", "path": "SOURCE-PACK-MANIFEST.json", "message": "manifest contains local path pattern: %s" % pattern})

    excluded = data.get("excluded_paths", [])
    if not isinstance(excluded, list) or not excluded:
        findings.append({"check": "excluded_paths", "path": "SOURCE-PACK-MANIFEST.json", "message": "excluded_paths must list exclusions and reasons"})
    else:
        for item in excluded:
            if not isinstance(item, dict) or not item.get("path") or not item.get("reason"):
                findings.append({"check": "excluded_path_reason", "path": "SOURCE-PACK-MANIFEST.json", "message": "each excluded path entry needs path and reason"})

    validation = data.get("validation", {})
    if not isinstance(validation, dict) or not validation.get("command_used") or not validation.get("result"):
        findings.append({"check": "validation", "path": "SOURCE-PACK-MANIFEST.json", "message": "validation command and result are required"})

    manual_controls = data.get("manual_controls", [])
    if not isinstance(manual_controls, list) or not manual_controls:
        findings.append({"check": "manual_controls", "path": "SOURCE-PACK-MANIFEST.json", "message": "manual_controls must be non-empty"})
    else:
        for term in REQUIRED_MANUAL_TERMS:
            if not has_term(manual_controls, term):
                findings.append({"check": "manual_control_term", "path": "SOURCE-PACK-MANIFEST.json", "message": "manual control missing term: %s" % term})

    return {
        "schema_version": "1.0",
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "pack": pack_path,
        "status": "pass" if not findings else "fail",
        "file_count": len(included),
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="Validate an OAD source-pack manifest.")
    parser.add_argument("--pack", required=True)
    parser.add_argument("--output-json", default="reports/source-pack/source-pack-manifest-check.json")
    args = parser.parse_args()

    report = validate(args.pack)
    with open(args.output_json, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")

    if report["status"] == "pass":
        print("source-pack manifest check passed; report=%s" % args.output_json)
        return 0

    print("source-pack manifest check failed; report=%s" % args.output_json)
    for finding in report["findings"]:
        print("- {path}: {check}: {message}".format(**finding))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
