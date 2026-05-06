#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
  echo "usage: scripts/validate_local_pcaps.sh PATH_TO_PCAP [PATH_TO_PCAP ...]"
  echo
  echo "Use only with local sanitized/private pcaps. This script does not require or ship pcaps."
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ "$#" -lt 1 ]; then
  usage >&2
  exit 2
fi

report="${OAD_PARSER_VALIDATION_REPORT:-/tmp/oad-parser-local-pcap-validation-$(date +%Y%m%d-%H%M%S).md}"
mkdir -p "$(dirname "$report")"

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

  "$@" 2>&1 | tee /tmp/oad-parser-command-output.txt
  sed 's/^/    /' /tmp/oad-parser-command-output.txt >> "$report"
}

{
  echo "# Local PCAP Validation"
  echo
  echo "Generated: $(date -Is)"
  echo "Repo: $repo_root"
  echo "Commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo
  echo "## Inputs"
  for pcap in "$@"; do
    echo "- $pcap"
  done
} > "$report"

run_and_report "Unit tests" python3 -m unittest discover -s oad_parser/tests -p "test_*.py"
run_and_report "Platform validation" python3 -m oad_parser validate-platform

index=0
for pcap in "$@"; do
  index=$((index + 1))

  if [ ! -f "$pcap" ]; then
    echo "ERROR: file not found: $pcap" >&2
    exit 1
  fi

  run_and_report "PCAP ${index} inspection" scripts/inspect_pcap.sh "$pcap"

  if python3 -m oad_parser --help 2>&1 | grep -q "parse-pcap"; then
    out="/tmp/oad-parser-local-pcap-${index}.jsonl"
    run_and_report "PCAP ${index} parse" python3 -m oad_parser parse-pcap "$pcap" --output "$out" --detect
    run_and_report "PCAP ${index} JSONL validation" python3 -m oad_parser validate "$out"

    {
      echo
      echo "PCAP ${index} output: $out"
      echo "PCAP ${index} output lines: $(wc -l < "$out")"
      echo
      echo "PCAP ${index} first 3 records:"
      sed -n '1,3p' "$out" | sed 's/^/    /'
    } >> "$report"
  else
    {
      echo
      echo "PCAP ${index} parse skipped: current CLI does not expose parse-pcap."
    } >> "$report"
  fi
done

echo "PASS: local pcap validation complete"
echo "Report: $report"
