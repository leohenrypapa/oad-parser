#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: $(basename "$0") must run from a Git checkout. Extracted source packs do not include .git." >&2
  echo "For extraction-only validation, run unit tests and python3 -m oad_parser validate-platform." >&2
  exit 2
fi

report="${OAD_PARSER_SANITIZE_REPORT:-/tmp/oad-parser-sanitized-release-$(date +%Y%m%d-%H%M%S).md}"
pack="/tmp/oad-parser-sanitized-release-source-pack.tar.gz"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

section() {
  echo
  echo "== $1 =="
}

mkdir -p "$(dirname "$report")"

{
  echo "# OAD Parser Sanitized Release Report"
  echo
  echo "Generated: $(date -Is)"
  echo "Repo: $repo_root"
  echo "Commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
} > "$report"

section "git cleanliness"
status="$(git status --short)"
echo "$status"
if [ -n "$status" ]; then
  echo "WARN: git tree is not clean at start; continuing for pre-commit validation"
fi

section "tracked file policy"
if git ls-files | grep -E '(^|/)(__pycache__|.pytest_cache|.mypy_cache|.ruff_cache|.venv|venv)(/|$)' >/tmp/oad-parser-bad-tracked.txt; then
  cat /tmp/oad-parser-bad-tracked.txt
  fail "cache or virtualenv paths are tracked"
fi
echo "OK: no tracked cache or virtualenv paths"

if git ls-files | grep -E '(.pcap$|.pcapng$|.cap$|.bin$|.payload$|.ecg$|.jsonl$|corpus-report.json$|corpus-summary.txt$|.zip$|.tar$|.gz$)' >/tmp/oad-parser-bad-artifacts.txt; then
  cat /tmp/oad-parser-bad-artifacts.txt
  fail "private/runtime/archive artifacts are tracked"
fi
echo "OK: no tracked private/runtime/archive artifacts"

section "required handoff docs"
required_docs=(
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
  "docs/design/parser-platform-operator-handbook.md"
  "docs/design/cd2-parser-roadmap.md"
  "docs/design/input-output-contract.md"
  "docs/design/protocol-layer-map.md"
)

for path in "${required_docs[@]}"; do
  [ -f "$path" ] || fail "missing doc: $path"
  echo "OK: $path"
done

section "script syntax"
bash -n scripts/*.sh
echo "OK: script syntax checks passed"

section "python compile"
python3 -m compileall -q oad_parser
echo "OK: compileall passed"

section "unit tests"
python3 -m unittest discover -s oad_parser/tests -p "test_*.py"

section "platform validation"
python3 -m oad_parser validate-platform

section "source pack check"
rm -f "$pack"
scripts/make_source_pack.sh "$pack"

tar -tzf "$pack" > /tmp/oad-parser-sanitize-pack-files.txt

required_pack=(
  ".gitignore"
  "README.md"
  "START_HERE.md"
  "AI_CONTEXT.md"
  "CHANGELOG.md"
  "SOURCE-PACK-MANIFEST.json"
  "docs/release/RELEASE_CHECKLIST.md"
  "docs/release/CUSTOMER_HANDOFF.md"
  "docs/design/TRACEABILITY_MATRIX.md"
  "docs/adr/0001-platform-foundation-scope.md"
  "docs/design/parser-platform-operator-handbook.md"
  "docs/design/cd2-parser-roadmap.md"
  "config/oad-cd2-profile.example.ini"
  "scripts/make_source_pack.sh"
)

for suffix in "${required_pack[@]}"; do
  grep -qx "$suffix" /tmp/oad-parser-sanitize-pack-files.txt || fail "pack missing $suffix"
  echo "OK pack contains: $suffix"
done

unsafe_pattern='(^.git/|(^|/)demo.sh$|.pcap$|.pcapng$|.cap$|.bin$|.payload$|.ecg$|corpus-report.json$|corpus-summary.txt$|.zip$|.tar$|.gz$)'
if grep -E "$unsafe_pattern" /tmp/oad-parser-sanitize-pack-files.txt; then
  fail "source pack contains excluded private/runtime files"
fi
echo "OK: source pack excludes private/runtime files"

section "final git cleanliness"
end_status="$(git status --short)"
echo "$end_status"
if [ -n "$end_status" ]; then
  echo "WARN: git tree is not clean at end; final release should be regenerated from committed tree"
fi

{
  echo
  echo "## Result"
  echo
  echo "PASS"
  echo
  echo "Source pack: $pack"
} >> "$report"

echo
echo "PASS: sanitized release validation complete"
echo "Report: $report"
