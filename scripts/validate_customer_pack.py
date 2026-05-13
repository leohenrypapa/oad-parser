#!/usr/bin/env python3
"""Validate the customer runtime/operator handoff pack.

This validator inspects entries inside the archive. It intentionally does not
reject the outer archive path just because it ends in .tar.gz.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


REQUIRED_ENTRIES = [
    "CUSTOMER-PACK-MANIFEST.json",
    "README.md",
    "START_HERE.md",
    "USER_MANUAL.md",
    "CHANGELOG.md",
    "config/ecg_conf.example.ini",
    "deploy/systemd/ecg-parser@.service",
    "docs/TROUBLESHOOTING.md",
    "docs/ops/systemd-live-parser.md",
    "docs/ops/filebeat-elastic-agent-handoff.md",
    "docs/release/CUSTOMER_HANDOFF.md",
    "docs/release/RELEASE_CHECKLIST.md",
    "oad_parser/__main__.py",
    "oad_parser/cli.py",
    "oad_parser/config.py",
    "oad_parser/live/service.py",
    "oad_parser/live/writer.py",
    "oad_parser/live/storage.py",
    "oad_parser/ingest/live_socket.py",
    "oad_parser/transformers/legacy_ecg.py",
]

FORBIDDEN_EXACT = [
    "AI_CONTEXT.md",
    ".gitlab-ci.yml",
    "CODEOWNERS",
    "standards-manifest.json",
    "SOURCE-PACK-MANIFEST.json",
    "scripts/make_source_pack.sh",
    "scripts/check_source_pack_manifest.py",
    "scripts/validate_sanitized_release.sh",
    "scripts/validate_release_readiness.sh",
    "scripts/verify.sh",
    "scripts/run_tests_junit.py",
    "scripts/validate_local_pcaps.sh",
    "scripts/inspect_pcap.sh",
    "docs/release/STANDARDS_ADOPTION_CHECKLIST.md",
]

FORBIDDEN_PREFIXES = [
    "oad_parser/tests/",
    "reports/",
    "dist/",
    "build/",
    ".git/",
    "__pycache__/",
    ".pytest_cache/",
    ".mypy_cache/",
]

FORBIDDEN_SUFFIXES = [
    ".pcap",
    ".pcapng",
    ".cap",
    ".bin",
    ".payload",
    ".ecg",
    ".jsonl",
    ".tar",
    ".gz",
    ".zip",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".crt",
    ".csr",
    ".env",
]

SECRET_NAME_FRAGMENTS = [
    "secret",
    "token",
    "password",
    "passwd",
    "credential",
    "credentials",
    "private_key",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_entry(name: str) -> str:
    return name.replace("\\", "/").lstrip("./")


def sha256_bytes(data: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(data)
    return digest.hexdigest()


def check_result(name: str, passed: bool, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    result = {"name": name, "status": "passed" if passed else "failed"}
    if details:
        result.update(details)
    return result


def read_archive(pack_path: Path) -> Tuple[List[str], Dict[str, bytes], List[str]]:
    errors: List[str] = []
    entries: List[str] = []
    file_bytes: Dict[str, bytes] = {}

    try:
        with tarfile.open(str(pack_path), "r:gz") as archive:
            for member in archive.getmembers():
                name = normalize_entry(member.name)
                entries.append(name)

                if member.isdir():
                    continue

                if not member.isfile():
                    errors.append("non-regular archive entry: %s" % name)
                    continue

                extracted = archive.extractfile(member)
                if extracted is None:
                    errors.append("unable to read archive entry: %s" % name)
                    continue
                file_bytes[name] = extracted.read()
    except Exception as exc:
        errors.append("failed to read tar.gz archive: %s" % exc)

    return sorted(entries), file_bytes, errors


def validate_required(entries: Iterable[str]) -> List[Dict[str, Any]]:
    entry_set = set(entries)
    checks = []
    for required in REQUIRED_ENTRIES:
        checks.append(check_result(required, required in entry_set, {"required": True, "present": required in entry_set}))
    return checks


def is_forbidden_prefix(entry: str) -> Optional[str]:
    for prefix in FORBIDDEN_PREFIXES:
        if entry == prefix.rstrip("/") or entry.startswith(prefix):
            return prefix
    parts = entry.split("/")
    if "__pycache__" in parts:
        return "__pycache__/"
    if ".pytest_cache" in parts:
        return ".pytest_cache/"
    if ".mypy_cache" in parts:
        return ".mypy_cache/"
    return None


def is_forbidden_suffix(entry: str) -> Optional[str]:
    lower = entry.lower()
    for suffix in FORBIDDEN_SUFFIXES:
        if lower.endswith(suffix):
            return suffix
    return None


def has_secret_name(entry: str) -> Optional[str]:
    lower = Path(entry).name.lower()
    for fragment in SECRET_NAME_FRAGMENTS:
        if fragment in lower:
            return fragment
    return None


def validate_forbidden(entries: Iterable[str]) -> List[Dict[str, Any]]:
    entry_set = set(entries)
    checks: List[Dict[str, Any]] = []

    for forbidden in FORBIDDEN_EXACT:
        present = forbidden in entry_set
        checks.append(check_result(forbidden, not present, {"forbidden": True, "present": present}))

    for entry in sorted(entry_set):
        prefix = is_forbidden_prefix(entry)
        if prefix:
            checks.append(check_result("forbidden prefix: %s" % entry, False, {"entry": entry, "matched_prefix": prefix}))

    return checks


def validate_unsafe(entries: Iterable[str]) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    for entry in sorted(set(entries)):
        suffix = is_forbidden_suffix(entry)
        if suffix:
            checks.append(check_result("forbidden suffix: %s" % entry, False, {"entry": entry, "matched_suffix": suffix}))
        secret_fragment = has_secret_name(entry)
        if secret_fragment:
            checks.append(check_result("secret-like entry name: %s" % entry, False, {"entry": entry, "matched_fragment": secret_fragment}))

    if not checks:
        checks.append(check_result("unsafe artifact scan", True, {"entry_count": len(list(entries))}))
    return checks


def parse_manifest(file_bytes: Dict[str, bytes]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    checks: List[Dict[str, Any]] = []

    raw = file_bytes.get("CUSTOMER-PACK-MANIFEST.json")
    if raw is None:
        return None, [check_result("CUSTOMER-PACK-MANIFEST.json present", False)]

    checks.append(check_result("CUSTOMER-PACK-MANIFEST.json present", True))

    try:
        manifest = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return None, checks + [check_result("CUSTOMER-PACK-MANIFEST.json parse", False, {"error": str(exc)})]

    checks.append(check_result("CUSTOMER-PACK-MANIFEST.json parse", True))

    expected_profile = manifest.get("package_profile") == "customer-runtime-operator"
    checks.append(check_result("manifest package_profile", expected_profile, {"value": manifest.get("package_profile")}))

    included = manifest.get("included_files")
    checks.append(check_result("manifest included_files list", isinstance(included, list), {"type": type(included).__name__}))

    return manifest, checks


def validate_manifest_hashes(manifest: Optional[Dict[str, Any]], file_bytes: Dict[str, bytes]) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []

    if not manifest or not isinstance(manifest.get("included_files"), list):
        return [check_result("manifest hash validation", False, {"reason": "manifest missing or included_files invalid"})]

    manifest_entries = manifest["included_files"]
    seen_paths = set()

    for item in manifest_entries:
        if not isinstance(item, dict):
            checks.append(check_result("manifest entry object", False, {"entry": repr(item)}))
            continue

        path = normalize_entry(str(item.get("path", "")))
        seen_paths.add(path)
        expected_hash = item.get("sha256")
        expected_size = item.get("size_bytes")

        if path not in file_bytes:
            checks.append(check_result("manifest path present: %s" % path, False, {"path": path}))
            continue

        data = file_bytes[path]
        checks.append(check_result("manifest path present: %s" % path, True, {"path": path}))

        if expected_hash:
            actual_hash = sha256_bytes(data)
            checks.append(
                check_result(
                    "manifest sha256: %s" % path,
                    actual_hash == expected_hash,
                    {"path": path, "expected": expected_hash, "actual": actual_hash},
                )
            )

        if isinstance(expected_size, int):
            checks.append(
                check_result(
                    "manifest size: %s" % path,
                    len(data) == expected_size,
                    {"path": path, "expected": expected_size, "actual": len(data)},
                )
            )

    archive_files_without_manifest = sorted(path for path in file_bytes if path != "CUSTOMER-PACK-MANIFEST.json")
    missing_from_manifest = [path for path in archive_files_without_manifest if path not in seen_paths]
    checks.append(check_result("all archive files recorded in manifest", not missing_from_manifest, {"missing_from_manifest": missing_from_manifest}))

    return checks


def overall_status(*groups: List[Dict[str, Any]]) -> str:
    for group in groups:
        for item in group:
            if item.get("status") != "passed":
                return "failed"
    return "passed"


def write_report(path: Optional[Path], report: Dict[str, Any]) -> None:
    if path is None:
        print(json.dumps(report, indent=2, sort_keys=True))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate OAD parser customer runtime/operator handoff pack.")
    parser.add_argument("--pack", required=True, help="Path to customer runtime/operator tar.gz pack.")
    parser.add_argument("--output-json", help="Path to write validation JSON report.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    pack_path = Path(args.pack).resolve()
    output_json = Path(args.output_json).resolve() if args.output_json else None

    entries, file_bytes, archive_errors = read_archive(pack_path)

    archive_checks = [
        check_result("pack path exists", pack_path.exists(), {"pack_path": str(pack_path)}),
        check_result("pack archive read", not archive_errors, {"errors": archive_errors}),
    ]

    required_checks = validate_required(entries)
    forbidden_checks = validate_forbidden(entries)
    unsafe_artifact_checks = validate_unsafe(entries)
    manifest, manifest_parse_checks = parse_manifest(file_bytes)
    manifest_hash_checks = validate_manifest_hashes(manifest, file_bytes)
    manifest_checks = manifest_parse_checks + manifest_hash_checks

    status = overall_status(
        archive_checks,
        required_checks,
        forbidden_checks,
        manifest_checks,
        unsafe_artifact_checks,
    )

    report = {
        "schema_version": "customer-pack-validation.v1",
        "generated_at_utc": utc_now(),
        "status": status,
        "pack_path": str(pack_path),
        "entry_count": len(entries),
        "required_checks": required_checks,
        "forbidden_checks": forbidden_checks,
        "manifest_checks": manifest_checks,
        "unsafe_artifact_checks": unsafe_artifact_checks,
        "archive_checks": archive_checks,
        "limitations": [
            "Validates entries inside the archive, not the outer archive filename.",
            "Does not execute customer-pack code.",
            "Does not validate target Oracle Linux Server 9.6 runtime behavior.",
            "Does not validate site-specific SIEM owner configuration.",
            "Does not certify absence of sensitive values inside arbitrary text beyond filename/path policy and manifest checks.",
        ],
    }

    write_report(output_json, report)

    if status == "passed":
        print("customer-pack validation passed; report=%s" % (output_json or "stdout"))
        return 0

    print("customer-pack validation failed; report=%s" % (output_json or "stdout"), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
