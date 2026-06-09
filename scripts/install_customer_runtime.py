#!/usr/bin/env python3
"""Install the customer runtime pack into a service-owned Python environment.

The customer runtime pack is intentionally not imported from the current working
folder by systemd. This installer creates a virtual environment and copies the
runtime package into that environment so /opt/oad-parser/venv/bin/python can run
`python -m oad_parser` from any working directory.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import Optional


def run(args: list[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=str(cwd) if cwd else None, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)


def venv_python(venv: Path) -> Path:
    if sys.platform == "win32":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def purelib_for(python_bin: Path) -> Path:
    result = run([str(python_bin), "-c", "import json, sysconfig; print(json.dumps(sysconfig.get_paths()))"])
    paths = json.loads(result.stdout)
    return Path(paths["purelib"])


def copy_runtime_package(source: Path, purelib: Path) -> None:
    src = source / "oad_parser"
    if not src.is_dir():
        raise SystemExit("ERROR: source does not contain oad_parser package: %s" % source)

    dst = purelib / "oad_parser"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def write_runtime_metadata(source: Path, purelib: Path) -> None:
    manifest = source / "CUSTOMER-PACK-MANIFEST.json"
    metadata_dir = purelib / "oad_parser_customer_runtime-0.dist-info"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    metadata = [
        "Metadata-Version: 2.1",
        "Name: oad-parser-customer-runtime",
        "Version: 0",
        "Summary: Installed OAD parser customer runtime pack",
        "",
    ]
    (metadata_dir / "METADATA").write_text("\n".join(metadata), encoding="utf-8")
    if manifest.is_file():
        shutil.copy2(manifest, metadata_dir / "CUSTOMER-PACK-MANIFEST.json")


def validate_runtime(python_bin: Path, cwd: Path) -> None:
    checks = [
        [str(python_bin), "-c", "import oad_parser; print(oad_parser.__version__)"],
        [str(python_bin), "-m", "oad_parser", "--help"],
        [str(python_bin), "-m", "oad_parser", "live", "--help"],
    ]
    for command in checks:
        run(command, cwd=cwd)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install OAD customer runtime pack into a venv.")
    parser.add_argument("--source", default=".", help="Extracted customer pack root. Defaults to current directory.")
    parser.add_argument("--prefix", default="/opt/oad-parser", help="Install prefix. Default: /opt/oad-parser.")
    parser.add_argument("--python", default=sys.executable, help="Python interpreter used to create the venv.")
    parser.add_argument("--force", action="store_true", help="Replace an existing venv under the prefix.")
    parser.add_argument("--no-validate", action="store_true", help="Skip post-install import/help checks.")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    source = Path(args.source).resolve()
    prefix = Path(args.prefix).resolve()
    venv = prefix / "venv"

    if sys.version_info[:2] != (3, 9) or sys.version_info < (3, 9, 2):
        raise SystemExit("ERROR: Python 3.9.x with patch >= 3.9.2 is required")

    if venv.exists():
        if not args.force:
            raise SystemExit("ERROR: venv already exists; use --force to replace: %s" % venv)
        shutil.rmtree(venv)

    prefix.mkdir(parents=True, exist_ok=True)
    run([args.python, "-m", "venv", str(venv)])
    py = venv_python(venv)
    purelib = purelib_for(py)
    copy_runtime_package(source, purelib)
    write_runtime_metadata(source, purelib)

    if not args.no_validate:
        outside = prefix / "runtime-import-check"
        outside.mkdir(parents=True, exist_ok=True)
        validate_runtime(py, outside)

    print("installed OAD customer runtime")
    print("prefix=%s" % prefix)
    print("python=%s" % py)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
