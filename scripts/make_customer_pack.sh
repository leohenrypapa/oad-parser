#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

OUT="${1:-}"
if [ -z "$OUT" ]; then
  echo "Usage: $0 /path/to/oad-parser-customer-runtime.tar.gz" >&2
  exit 2
fi

DEFAULT_PYTHON="python3.9"
PY="${PYTHON_BIN:-${PYTHON:-$DEFAULT_PYTHON}}"

if [ ! -x "$PY" ]; then
  if command -v "$PY" >/dev/null 2>&1; then
    PY="$(command -v "$PY")"
  else
    echo "ERROR: Python interpreter is not executable or resolvable on PATH: $PY" >&2
    echo "Set PYTHON_BIN to the repo Python 3.9.2 interpreter if needed." >&2
    exit 1
  fi
fi

"$PY" - "$OUT" "$ROOT_DIR" <<'PY'
import hashlib
import json
import os
import platform
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

allow_ci_patch_drift = os.environ.get("OAD_ALLOW_CI_PY39_PATCH_DRIFT") == "1"
allow_site_patch_drift = os.environ.get("OAD_ALLOW_SITE_PY39_PATCH_DRIFT") == "1"
allow_py39_patch_drift = allow_ci_patch_drift or allow_site_patch_drift
if allow_py39_patch_drift:
    if sys.version_info[:2] != (3, 9) or sys.version_info < (3, 9, 2):
        raise SystemExit(
            "ERROR: Python 3.9.x with patch >= 3.9.2 is required when patch drift is allowed; found %s.%s.%s"
            % sys.version_info[:3]
        )
else:
    if sys.version_info[:3] != (3, 9, 2):
        raise SystemExit("ERROR: Python 3.9.2 is required; found %s.%s.%s" % sys.version_info[:3])

out_path = Path(sys.argv[1]).resolve()
repo = Path(sys.argv[2]).resolve()

if not (repo / "pyproject.toml").is_file() or not (repo / "oad_parser").is_dir():
    raise SystemExit(f"ERROR: repo root does not look like oad-parser: {repo}")

TOP_LEVEL_REQUIRED = [
    ".gitignore",
    "README.md",
    "START_HERE.md",
    "USER_MANUAL.md",
    "CHANGELOG.md",
    "pyproject.toml",
]

CONFIG_REQUIRED = [
    "config/ecg_conf.example.ini",
    "config/ecg-alerts.example.json",
    "config/oad-parser.example.ini",
    "config/oad-cd2-profile.example.ini",
]

DEPLOY_REQUIRED = [
    "deploy/systemd/ecg-parser@.service",
]

DOCS_REQUIRED = [
    "docs/TROUBLESHOOTING.md",
    "docs/ops/systemd-live-parser.md",
    "docs/ops/filebeat-elastic-agent-handoff.md",
    "docs/release/CUSTOMER_HANDOFF.md",
    "docs/release/RELEASE_CHECKLIST.md",
    "docs/release/target-environment-validation.md",
]

SCRIPT_REQUIRED = [
    "scripts/install_customer_runtime.py",
    "scripts/make_customer_pack.sh",
]

EXCLUDED_EXACT = {
    ".git",
    ".gitlab-ci.yml",
    "AI_CONTEXT.md",
    "CODEOWNERS",
    "SOURCE-PACK-MANIFEST.json",
    "standards-manifest.json",
    "docs/release/STANDARDS_ADOPTION_CHECKLIST.md",
    "scripts/make_source_pack.sh",
    "scripts/check_source_pack_manifest.py",
    "scripts/validate_sanitized_release.sh",
    "scripts/validate_release_readiness.sh",
    "scripts/verify.sh",
    "scripts/run_tests_junit.py",
    "scripts/validate_local_pcaps.sh",
    "scripts/inspect_pcap.sh",
    "scripts/quickstart_check.sh",
    "scripts/validate_customer_pack.py",
    "scripts/validate_pre_site_readiness.sh",
    "scripts/run_live_acceptance_6100pps.py",
    "oad_parser/corpus.py",
    "oad_parser/corpus_report.py",
    "oad_parser/fixture_samples.py",
    "oad_parser/golden.py",
    "oad_parser/platform_validation.py",
    "oad_parser/source_pack.py",
}

EXCLUDED_PREFIXES = (
    ".git/",
    ".pytest_cache/",
    "__pycache__/",
    "reports/",
    "dist/",
    "build/",
    "htmlcov/",
    "oad_parser/tests/",
)

EXCLUDED_SUFFIXES = (
    ".pcap",
    ".pcapng",
    ".cap",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".zip",
    ".7z",
    ".pyc",
    ".pyo",
    ".log",
)

SECRET_NAME_FRAGMENTS = (
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
    ".pem",
    ".key",
    ".p12",
    ".pfx",
)

INCLUDE_EXACT = set(TOP_LEVEL_REQUIRED + CONFIG_REQUIRED + DEPLOY_REQUIRED + DOCS_REQUIRED + SCRIPT_REQUIRED)
GENERATED_FILES = {
    "oad_parser/_customer_runtime_profile.py": b'"""Marker module for the customer runtime/operator CLI profile."""\n\nCUSTOMER_RUNTIME_PROFILE = True\n',
}


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data):
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git_output(args):
    try:
        result = subprocess.run(["git"] + args, cwd=str(repo), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return result.stdout.strip()
    except Exception:
        return None


def git_dirty_status():
    status = git_output(["status", "--porcelain"])
    if status is None:
        return "unknown-non-git-source-tree"
    return "dirty" if status else "clean"


def source_provenance(validation_report):
    generator = "scripts/make_customer_pack.sh"
    validation_path = None
    validation_hash = None
    if validation_report:
        candidate = Path(validation_report)
        validation_path = str(candidate)
        if candidate.is_file():
            validation_hash = sha256_file(candidate)
    return {
        "source_commit": git_output(["rev-parse", "HEAD"]) or "unavailable-non-git-source-tree",
        "source_branch": git_output(["rev-parse", "--abbrev-ref", "HEAD"]) or "unavailable-non-git-source-tree",
        "source_remote_or_project": "rapid-capabilities-oad-parser",
        "generator_script_path": generator,
        "generator_script_sha256": sha256_file(repo / generator),
        "dirty_tree_status_at_generation": git_dirty_status(),
        "validation_report_path": validation_path,
        "validation_report_sha256": validation_hash,
        "generated_at_utc": utc_now(),
        "generated_by_python": platform.python_version(),
        "pack_format_version": "customer-runtime-operator-pack.v2",
    }


def is_excluded(rel):
    rel = rel.replace("\\", "/")
    name = rel.lower()
    base = Path(rel).name.lower()
    if rel in EXCLUDED_EXACT:
        return True
    if any(rel.startswith(prefix) for prefix in EXCLUDED_PREFIXES):
        return True
    if any(name.endswith(suffix) for suffix in EXCLUDED_SUFFIXES):
        return True
    if any(fragment in base for fragment in SECRET_NAME_FRAGMENTS):
        return True
    if "/__pycache__/" in name:
        return True
    if "/.pytest_cache/" in name:
        return True
    return False


def include_candidate(rel):
    rel = rel.replace("\\", "/")
    if is_excluded(rel):
        return False
    if rel in INCLUDE_EXACT:
        return True
    if rel.startswith("oad_parser/") and not rel.startswith("oad_parser/tests/") and rel.endswith(".py"):
        return True
    return False


def get_filesystem_files():
    files = []
    for path in repo.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(repo).as_posix()
        if include_candidate(rel):
            files.append(rel)
    return sorted(set(files))


def get_tracked_files():
    result = git_output(["ls-files"])
    tracked = [line.strip() for line in result.splitlines() if line.strip()] if result else []
    # Include newly added runtime files before they are committed so pre-commit customer-pack validation
    # uses the same production files that the working tree and tests are validating.
    return sorted(set(tracked + get_filesystem_files()))

included = []
for rel in sorted(set(get_tracked_files())):
    if include_candidate(rel):
        path = repo / rel
        if path.is_file():
            included.append(rel)

for rel in sorted(INCLUDE_EXACT):
    if rel not in included:
        path = repo / rel
        if not path.is_file():
            raise SystemExit(f"ERROR: required customer-pack file missing: {rel}")
        if is_excluded(rel):
            raise SystemExit(f"ERROR: required customer-pack file is excluded by policy: {rel}")
        included.append(rel)

included = sorted(set(included))
unsafe_included = [rel for rel in included if is_excluded(rel)]
if unsafe_included:
    raise SystemExit("ERROR: unsafe entries selected for customer pack: " + ", ".join(unsafe_included))

manifest_entries = []
for rel in included:
    path = repo / rel
    manifest_entries.append({"path": rel, "size_bytes": path.stat().st_size, "sha256": sha256_file(path)})
for rel, data in sorted(GENERATED_FILES.items()):
    manifest_entries.append({"path": rel, "size_bytes": len(data), "sha256": sha256_bytes(data), "generated": True})

provenance = source_provenance(os.environ.get("CUSTOMER_PACK_VALIDATION_REPORT"))
manifest = {
    "schema_version": "customer-pack-manifest.v2",
    "generated_at_utc": provenance["generated_at_utc"],
    "package_profile": "customer-runtime-operator",
    "committed_by_default": False,
    "purpose": "Customer runtime/operator handoff package for the Sprint 2 live parser foundation.",
    "entry_count": len(manifest_entries) + 1,
    "included_files": manifest_entries,
    "excluded_by_default": sorted(EXCLUDED_EXACT),
    "excluded_prefixes": list(EXCLUDED_PREFIXES),
    "excluded_suffixes": list(EXCLUDED_SUFFIXES),
    "runtime_install_model": {
        "installer": "scripts/install_customer_runtime.py",
        "service_python": "/opt/oad-parser/venv/bin/python",
        "systemd_exec_start": "/opt/oad-parser/venv/bin/python -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface %i",
        "import_model": "runtime package copied into service venv; no current-working-directory import dependency",
    },
    "source_provenance": provenance,
    "runtime_entry_points": [
        "python -m oad_parser --help",
        "python -m oad_parser live --help",
    ],
    "operational_paths": {
        "config": "/etc/oad-parser/ecg_conf.ini",
        "active_jsonl": "/nsm/ecg/ecg-current.json",
        "audit_jsonl": "/nsm/ecg/ecg-audit.jsonl",
        "status_json": "/nsm/ecg/ecg-status.json",
    },
    "notes": [
        "This customer runtime/operator pack is separate from the internal engineering source pack.",
        "Development-only CI, tests, source-pack, corpus, golden-fixture, and AI/dev workflow files are excluded by default.",
        "/nsm/ecg/ecg-current.json contains JSON Lines despite the .json suffix.",
        "Filebeat/Elastic Agent 8.17.3 remains an expected assumption; final version and site config must be confirmed by the SIEM owner.",
        "This pack must not contain real PCAPs, raw operational payloads, secrets, local reports, runtime outputs, or site-specific values.",
    ],
}

out_path.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory() as tmp:
    tmpdir = Path(tmp)
    manifest_path = tmpdir / "CUSTOMER-PACK-MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with tarfile.open(out_path, "w:gz") as tar:
        for rel in included:
            tar.add(str(repo / rel), arcname=rel, recursive=False)
        for rel, data in GENERATED_FILES.items():
            generated_path = tmpdir / rel
            generated_path.parent.mkdir(parents=True, exist_ok=True)
            generated_path.write_bytes(data)
            tar.add(str(generated_path), arcname=rel, recursive=False)
        tar.add(str(manifest_path), arcname="CUSTOMER-PACK-MANIFEST.json", recursive=False)

print(f"created customer pack: {out_path}")
print(f"files: {len(manifest_entries) + 1}")
print("manifest: CUSTOMER-PACK-MANIFEST.json")
PY

echo
echo "== customer pack =="
echo "$OUT"
if command -v du >/dev/null 2>&1; then
  du -h "$OUT"
else
  echo "du not available; skipping customer-pack size display"
fi
