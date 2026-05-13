#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
  echo "usage: scripts/make_source_pack.sh [OUTPUT_TAR_GZ]"
  echo "       scripts/make_source_pack.sh --output OUTPUT_TAR_GZ"
}

case "$#" in
  0)
    timestamp="$(date +%Y%m%d-%H%M%S)"
    output_dir="${OAD_PARSER_PACK_OUTPUT_DIR:-${repo_root}/dist/source-packs}"
    output="${output_dir}/oad-parser-source-pack-${timestamp}.tar.gz"
    ;;
  1)
    if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
      usage
      exit 0
    fi
    output="$1"
    ;;
  2)
    if [ "$1" != "--output" ]; then
      usage >&2
      exit 2
    fi
    output="$2"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

mkdir -p "$(dirname "$output")"

python3 -m oad_parser create-source-pack --output "$output" --tracked-only

echo
echo "== source pack =="
echo "$output"
du -h "$output"

echo
echo "== required entries =="
pack_list="$(mktemp)"
manifest_file="$(mktemp)"
trap 'rm -f "$pack_list" "$manifest_file"' EXIT

tar -tzf "$output" > "$pack_list"

required_entries=(
  ".gitignore"
  "README.md"
  "START_HERE.md"
  "USER_MANUAL.md"
  "AI_CONTEXT.md"
  "CHANGELOG.md"
  "SOURCE-PACK-MANIFEST.json"
  "pyproject.toml"
  "oad_parser/cli.py"
  "oad_parser/source_pack.py"
  "docs/TROUBLESHOOTING.md"
  "docs/release/RELEASE_CHECKLIST.md"
  "docs/release/CUSTOMER_HANDOFF.md"
  "docs/design/TRACEABILITY_MATRIX.md"
  "docs/adr/0001-platform-foundation-scope.md"
  "docs/design/parser-platform-operator-handbook.md"
  "docs/design/cd2-parser-roadmap.md"
  "config/oad-cd2-profile.example.ini"
  "config/ecg_conf.example.ini"
  "docs/design/live-parser-design-delta.md"
  "oad_parser/live/__init__.py"
  "oad_parser/live/classifier.py"
  "oad_parser/live/metrics.py"
  "oad_parser/live/records.py"
  "oad_parser/transformers/__init__.py"
  "oad_parser/transformers/legacy_ecg.py"
  "oad_parser/tests/test_legacy_ecg_transformer.py"
  "oad_parser/tests/test_live_classifier.py"
  "oad_parser/tests/test_live_metrics.py"
  "oad_parser/tests/test_live_parse_errors.py"
  "oad_parser/tests/test_live_records.py"
  "deploy/systemd/ecg-parser@.service"
  "docs/ops/systemd-live-parser.md"
  "docs/ops/filebeat-elastic-agent-handoff.md"
  "scripts/make_source_pack.sh"
)

for entry in "${required_entries[@]}"; do
  if grep -qx "$entry" "$pack_list"; then
    echo "OK: $entry"
  else
    echo "ERROR: source pack missing required entry: $entry" >&2
    exit 1
  fi
done

echo
echo "== unsafe artifact check =="
unsafe_pattern='(^.git/|(^|/)demo.sh$|.pcap$|.pcapng$|.cap$|.bin$|.payload$|.ecg$|corpus-report.json$|corpus-summary.txt$|.zip$|.tar$|.gz$)'
unsafe="$(grep -E "$unsafe_pattern" "$pack_list" || true)"
if [ -n "$unsafe" ]; then
  echo "$unsafe"
  echo "ERROR: source pack contains excluded artifact(s)" >&2
  exit 1
fi
echo "OK: no unsafe source-pack entries"

echo
echo "== manifest content check =="
tar -xOzf "$output" SOURCE-PACK-MANIFEST.json > "$manifest_file"
python3 - "$manifest_file" <<'PY'
import json
import re
import sys
from pathlib import PurePosixPath

path = sys.argv[1]
data = json.load(open(path, "r", encoding="utf-8"))
for forbidden_key in ("repo_root", "output_path"):
    if forbidden_key in data:
        raise SystemExit(f"manifest contains forbidden key: {forbidden_key}")
if data.get("file_count_basis") != "packaged files excluding SOURCE-PACK-MANIFEST.json":
    raise SystemExit("manifest file_count_basis is missing or unexpected")
files = data.get("files")
if not isinstance(files, list):
    raise SystemExit("manifest files field is not a list")
if data.get("file_count") != len(files):
    raise SystemExit("manifest file_count does not match files length")
text = json.dumps(data, sort_keys=True)
patterns = [r"/home/", r"/mnt/", r"/Users/", r"[A-Za-z]:\\\\", r"\\$HOME/"]
for pattern in patterns:
    if re.search(pattern, text):
        raise SystemExit(f"manifest contains local path pattern: {pattern}")
for item in files:
    if item.startswith("/") or ".." in PurePosixPath(item).parts:
        raise SystemExit(f"manifest contains unsafe path: {item}")
print("OK: manifest contains customer-safe relative metadata")
PY

echo
echo "== preview =="
sed -n '1,180p' "$pack_list"
