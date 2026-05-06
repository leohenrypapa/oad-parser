#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF_USAGE'
Usage: scripts/quickstart_check.sh [--with-tests]

Runs the extraction-safe first-run validation path for oad-parser.
This script does not require .git metadata and does not use private pcaps.

Options:
  --with-tests    Also run the unittest suite.
EOF_USAGE
}

WITH_TESTS=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --with-tests)
            WITH_TESTS=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

PYTHON_BIN=""
for candidate in python3.9 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "ERROR: no Python interpreter found. Install Python 3.9.2 or newer." >&2
    exit 1
fi

PY_VERSION="$($PYTHON_BIN -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
"$PYTHON_BIN" - <<'EOF_PYVER'
import sys
if sys.version_info < (3, 9, 2):
    raise SystemExit(
        "ERROR: Python 3.9.2 or newer is required; found %s.%s.%s"
        % sys.version_info[:3]
    )
EOF_PYVER

echo "== oad-parser quickstart check =="
echo "Repo root: $REPO_ROOT"
echo "Python: $PYTHON_BIN ($PY_VERSION)"

echo "== Compile package =="
"$PYTHON_BIN" -m compileall -q oad_parser

echo "== CLI help check =="
"$PYTHON_BIN" -m oad_parser --help >/dev/null

echo "== Platform validation =="
"$PYTHON_BIN" -m oad_parser validate-platform

if [ "$WITH_TESTS" -eq 1 ]; then
    echo "== Unit tests =="
    "$PYTHON_BIN" -m unittest discover -s oad_parser/tests -p "test_*.py"
fi

echo "== PASS: oad-parser quickstart check complete =="
