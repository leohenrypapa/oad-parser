#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

DEFAULT_PYTHON="$ROOT_DIR/.venv/bin/python"
PYTHON_BIN="${PYTHON_BIN:-$DEFAULT_PYTHON}"

if [ ! -x "$PYTHON_BIN" ]; then
  echo "ERROR: Python interpreter is not executable: $PYTHON_BIN" >&2
  echo "Set PYTHON_BIN to the repo Python 3.9.2 interpreter if needed." >&2
  exit 1
fi

mkdir -p reports/tests reports/validation reports/source-pack

"$PYTHON_BIN" - <<'PYVER'
import sys
if sys.version_info[:3] != (3, 9, 2):
    raise SystemExit(
        "ERROR: Python 3.9.2 is required; found %s.%s.%s"
        % sys.version_info[:3]
    )
PYVER

python_version="$($PYTHON_BIN --version 2>&1)"
echo "== Python =="
echo "$python_version"

run_step() {
  local name="$1"
  shift
  echo
  echo "== $name =="
  "$@"
}

run_step "compile package" "$PYTHON_BIN" -m compileall -q oad_parser
run_step "unit tests with JUnit evidence" "$PYTHON_BIN" scripts/run_tests_junit.py --tests-dir oad_parser/tests --pattern 'test_*.py' --output reports/tests/junit.xml

echo
echo "== CLI help =="
"$PYTHON_BIN" -m oad_parser --help > reports/validation/cli-help.txt
cat reports/validation/cli-help.txt

echo
echo "== platform validation =="
"$PYTHON_BIN" -m oad_parser validate-platform --json > reports/validation/platform-validation.json
cat reports/validation/platform-validation.json

echo
echo "== quickstart check =="
PYTHON_BIN="$PYTHON_BIN" bash scripts/quickstart_check.sh | tee reports/validation/quickstart-check.txt

echo
echo "== source-pack smoke =="
"$PYTHON_BIN" -m oad_parser create-source-pack --output reports/source-pack/oad-parser-source-pack-smoke.tar.gz --tracked-only --json > reports/source-pack/source-pack-result.json
cat reports/source-pack/source-pack-result.json

run_step "source-pack manifest check" "$PYTHON_BIN" scripts/check_source_pack_manifest.py --pack reports/source-pack/oad-parser-source-pack-smoke.tar.gz --output-json reports/source-pack/source-pack-manifest-check.json

"$PYTHON_BIN" - <<'PYREPORT'
import json
from datetime import datetime, timezone
from pathlib import Path

root = Path(".")
checks = []

def add(name, path):
    p = root / path
    checks.append({"name": name, "path": path, "exists": p.exists(), "bytes": p.stat().st_size if p.exists() else 0})

add("junit", "reports/tests/junit.xml")
add("platform_validation", "reports/validation/platform-validation.json")
add("quickstart", "reports/validation/quickstart-check.txt")
add("source_pack_result", "reports/source-pack/source-pack-result.json")
add("source_pack_manifest_check", "reports/source-pack/source-pack-manifest-check.json")

status = "pass" if all(item["exists"] for item in checks) else "fail"
manifest_check = json.loads((root / "reports/source-pack/source-pack-manifest-check.json").read_text(encoding="utf-8"))
if manifest_check.get("status") != "pass":
    status = "fail"

report = {
    "schema_version": "1.0",
    "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "status": status,
    "python": "$PYTHON_BIN",
    "checks": checks,
    "manual_platform_controls": [
        "Replace CODEOWNERS placeholder owners before enforcing CODEOWNERS approvals.",
        "Set OAD_PARSER_CI_IMAGE to an approved Registry1 image pinned by digest before enabling CI verification.",
        "Configure protected main, protected v* tags, MR approvals, passing-pipeline requirements, protected/masked variables, and release restrictions in GitLab.",
        "Approve data classification and controlled-data handling before customer, release, or external AI handoff."
    ]
}
out = root / "reports/standards-verify-report.json"
out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print("standards verification %s; report=%s" % (status, out))
raise SystemExit(0 if status == "pass" else 1)
PYREPORT
