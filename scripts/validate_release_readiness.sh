#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: $(basename "$0") must run from a Git checkout. Extracted source packs do not include .git." >&2
  echo "For extraction-only validation, run unit tests and python3 -m oad_parser validate-platform." >&2
  exit 2
fi

optional_pcap="${1:-}"
report="${OAD_PARSER_RELEASE_REPORT:-/tmp/oad-parser-release-readiness-$(date +%Y%m%d-%H%M%S).md}"
pack="/tmp/oad-parser-release-readiness-source-pack.tar.gz"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

section() {
  echo
  echo "== $1 =="
}

run_and_report() {
  local title="$1"
  shift

  {
    echo
    echo "## $title"
    echo
    echo "Command:"
    echo
    printf '    %q' "$@"
    echo
    echo
    echo "Output:"
    echo
  } >> "$report"

  "$@" 2>&1 | tee /tmp/oad-parser-release-command.txt
  sed 's/^/    /' /tmp/oad-parser-release-command.txt >> "$report"
}

mkdir -p "$(dirname "$report")"

{
  echo "# OAD Parser Release Readiness Report"
  echo
  echo "Generated: $(date -Is)"
  echo "Repo: $repo_root"
  echo "Commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  if [ -n "$optional_pcap" ]; then
    echo "Optional pcap: $optional_pcap"
  fi
} > "$report"

section "start git status"
start_status="$(git status --short)"
echo "$start_status"
if [ -n "$start_status" ]; then
  echo "WARN: git tree is not clean at start; continuing for pre-commit validation"
fi

section "required file checks"
required_files=(
  ".gitignore"
  ".gitlab-ci.yml"
  "README.md"
  "START_HERE.md"
  "USER_MANUAL.md"
  "AI_CONTEXT.md"
  "CHANGELOG.md"
  "docs/TROUBLESHOOTING.md"
  "docs/release/RELEASE_CHECKLIST.md"
  "docs/release/CUSTOMER_HANDOFF.md"
  "docs/design/TRACEABILITY_MATRIX.md"
  "docs/adr/0001-platform-foundation-scope.md"
  "pyproject.toml"
  "poetry.toml"
  "makefile"
  "config/oad-parser.example.ini"
  "config/oad-cd2-profile.example.ini"
  "docs/design/parser-platform-operator-handbook.md"
  "docs/design/cd2-parser-roadmap.md"
  "docs/design/input-output-contract.md"
  "docs/design/protocol-layer-map.md"
  "oad_parser/__main__.py"
  "oad_parser/cli.py"
  "oad_parser/parsers/cd2.py"
  "oad_parser/parsers/ecg.py"
  "oad_parser/compare.py"
  "oad_parser/corpus.py"
  "oad_parser/corpus_report.py"
  "oad_parser/golden.py"
  "oad_parser/fixture_samples.py"
  "oad_parser/platform_validation.py"
  "oad_parser/source_pack.py"
  "scripts/make_source_pack.sh"
  "scripts/validate_sanitized_release.sh"
)

for path in "${required_files[@]}"; do
  [ -e "$path" ] || fail "missing required file: $path"
  echo "OK: $path"
done

section "tracked artifact policy"
if git ls-files | grep -E '(^|/)(__pycache__|.pytest_cache|.mypy_cache|.ruff_cache|.venv|venv)(/|$)' >/tmp/oad-parser-bad-tracked-cache.txt; then
  cat /tmp/oad-parser-bad-tracked-cache.txt
  fail "cache or virtualenv paths are tracked"
fi
echo "OK: no tracked cache or virtualenv paths"

if git ls-files | grep -E '(.pcap$|.pcapng$|.cap$|.bin$|.payload$|.ecg$|.jsonl$|corpus-report.json$|corpus-summary.txt$|.zip$|.tar$|.gz$)' >/tmp/oad-parser-bad-artifacts.txt; then
  cat /tmp/oad-parser-bad-artifacts.txt
  fail "runtime/source-pack artifacts are tracked"
fi
echo "OK: no tracked private/runtime artifacts"

section "script syntax"
bash -n scripts/*.sh
echo "OK: script syntax checks passed"

section "python compile"
python3 -m compileall -q oad_parser
echo "OK: compileall passed"

section "unit tests"
run_and_report "Unit tests" python3 -m unittest discover -s oad_parser/tests -p "test_*.py"

section "platform validation"
run_and_report "Platform validation" python3 -m oad_parser validate-platform

section "cli help"
run_and_report "CLI help" python3 -m oad_parser --help

if [ -n "$optional_pcap" ]; then
  section "optional pcap validation"
  [ -f "$optional_pcap" ] || fail "optional pcap not found: $optional_pcap"
  run_and_report "Optional pcap validation" scripts/validate_local_pcaps.sh "$optional_pcap"
fi

section "source pack"
rm -f "$pack"
run_and_report "Source pack generation" scripts/make_source_pack.sh "$pack"

{
  echo
  echo "## Source pack"
  echo
  echo "Path: $pack"
} >> "$report"

section "final git status"
end_status="$(git status --short)"
echo "$end_status"
if [ -n "$end_status" ]; then
  echo "WARN: git tree is not clean at end; final release should be regenerated from committed tree"
fi

{
  echo
  echo "## Final result"
  echo
  echo "PASS"
  echo
  echo "Source pack: $pack"
} >> "$report"

echo
echo "PASS: release readiness validation complete"
echo "Report: $report"
