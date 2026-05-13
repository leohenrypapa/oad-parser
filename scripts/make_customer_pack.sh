#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

OUT="${1:-}"
if [ -z "$OUT" ]; then
  echo "Usage: $0 /path/to/oad-parser-customer-runtime.tar.gz" >&2
  exit 2
fi

DEFAULT_PYTHON="$ROOT_DIR/.venv/bin/python"
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

"$PY" - "$OUT" <<'PY'
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

allow_ci_patch_drift = os.environ.get("OAD_ALLOW_CI_PY39_PATCH_DRIFT") == "1"
if allow_ci_patch_drift:
    if sys.version_info[:2] != (3, 9):
        raise SystemExit(
            "ERROR: Python 3.9.x is required in CI; found %s.%s.%s"
            % sys.version_info[:3]
        )
else:
    if sys.version_info[:3] != (3, 9, 2):
        raise SystemExit(
            "ERROR: Python 3.9.2 is required; found %s.%s.%s"
            % sys.version_info[:3]
        )

out_path = Path(sys.argv[1]).resolve()
repo = Path.cwd().resolve()

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

EXCLUDED_EXACT = {
    ".git",
    ".gitlab-ci.yml",
    "AI_CONTEXT.md",
    "CODEOWNERS",
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

CUSTOMER_ALLOWED_PREFIXES = (
    "oad_parser/",
    "config/",
    "deploy/systemd/",
    "docs/ops/",
    "docs/release/",
)

INCLUDE_EXACT = set(TOP_LEVEL_REQUIRED + CONFIG_REQUIRED + DEPLOY_REQUIRED + DOCS_REQUIRED)

def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

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

def get_tracked_files():
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=str(repo),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except Exception as exc:
        raise SystemExit(f"ERROR: failed to list tracked files with git: {exc}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]

tracked_files = get_tracked_files()

# Include the just-added pack script even before it is committed/tracked.
script_rel = "scripts/make_customer_pack.sh"
if (repo / script_rel).exists() and script_rel not in tracked_files:
    tracked_files.append(script_rel)

included = []
excluded = []

for rel in sorted(set(tracked_files)):
    if include_candidate(rel):
        path = repo / rel
        if path.is_file():
            included.append(rel)
    else:
        excluded.append(rel)

for rel in sorted(INCLUDE_EXACT):
    if rel not in included:
        path = repo / rel
        if not path.is_file():
            raise SystemExit(f"ERROR: required customer-pack file missing: {rel}")
        if is_excluded(rel):
            raise SystemExit(f"ERROR: required customer-pack file is excluded by policy: {rel}")
        included.append(rel)

# Include customer-pack generator for release/operator reproducibility.
if script_rel not in included and (repo / script_rel).is_file():
    included.append(script_rel)

included = sorted(set(included))

unsafe_included = [rel for rel in included if is_excluded(rel)]
if unsafe_included:
    raise SystemExit("ERROR: unsafe entries selected for customer pack: " + ", ".join(unsafe_included))

manifest_entries = []
for rel in included:
    path = repo / rel
    manifest_entries.append(
        {
            "path": rel,
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    )

manifest = {
    "schema_version": "customer-pack-manifest.v1",
    "generated_at_utc": utc_now(),
    "package_profile": "customer-runtime-operator",
    "committed_by_default": False,
    "purpose": "Customer runtime/operator handoff package for the Sprint 2 live parser foundation.",
    "entry_count": len(manifest_entries) + 1,
    "included_files": manifest_entries,
    "excluded_by_default": sorted(EXCLUDED_EXACT),
    "excluded_prefixes": list(EXCLUDED_PREFIXES),
    "excluded_suffixes": list(EXCLUDED_SUFFIXES),
    "runtime_entry_points": [
        "python -m oad_parser --help",
        "python -m oad_parser live --help"
    ],
    "operational_paths": {
        "config": "/etc/oad-parser/ecg_conf.ini",
        "active_jsonl": "/nsm/ecg/ecg-current.json",
        "audit_jsonl": "/nsm/ecg/ecg-audit.jsonl",
        "status_json": "/nsm/ecg/ecg-status.json"
    },
    "notes": [
        "This customer runtime/operator pack is separate from the internal engineering source pack.",
        "Development-only CI, tests, source-pack, corpus, golden-fixture, and AI/dev workflow files are excluded by default.",
        "/nsm/ecg/ecg-current.json contains JSON Lines despite the .json suffix.",
        "Filebeat/Elastic Agent 8.17.3 remains an expected assumption; final version and site config must be confirmed by the SIEM owner.",
        "This pack must not contain real PCAPs, raw operational payloads, secrets, local reports, runtime outputs, or site-specific values."
    ],
}

out_path.parent.mkdir(parents=True, exist_ok=True)

with tempfile.TemporaryDirectory() as tmp:
    tmpdir = Path(tmp)
    manifest_path = tmpdir / "CUSTOMER-PACK-MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with tarfile.open(out_path, "w:gz") as tar:
        for rel in included:
            path = repo / rel
            tar.add(str(path), arcname=rel, recursive=False)
        tar.add(str(manifest_path), arcname="CUSTOMER-PACK-MANIFEST.json", recursive=False)

print(f"created customer pack: {out_path}")
print(f"files: {len(included) + 1}")
print("manifest: CUSTOMER-PACK-MANIFEST.json")
PY

echo
echo "== customer pack =="
echo "$OUT"
du -h "$OUT"
