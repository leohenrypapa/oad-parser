"""Source-pack generation for AI/developer handoff.

The source pack is intentionally conservative. It packages code, tests, config,
and design docs while excluding local scratch files, generated runtime artifacts,
packet captures, caches, and VCS internals.
"""

from __future__ import annotations

import json
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_INCLUDED_TOP_LEVEL = {
    "config",
    "docs",
    "scripts",
    "oad_parser",
    "README.md",
    "START_HERE.md",
    "USER_MANUAL.md",
    "AI_CONTEXT.md",
    "CHANGELOG.md",
    "pyproject.toml",
    "poetry.toml",
    "Makefile",
    "makefile",
    ".gitlab-ci.yml",
    ".gitignore",
}

EXCLUDED_DIR_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".tox",
    ".ruff_cache",
    ".idea",
    ".vscode",
}

EXCLUDED_FILE_NAMES = {
    "demo.sh",
    "corpus-report.json",
    "corpus-summary.txt",
}

EXCLUDED_SUFFIXES = {
    ".pcap",
    ".cap",
    ".pcapng",
    ".bin",
    ".payload",
    ".ecg",
    ".pyc",
    ".pyo",
    ".log",
    ".tmp",
    ".tar",
    ".gz",
    ".zip",
}

ALLOWED_DOTFILES = {
    ".gitlab-ci.yml",
    ".gitignore",
}

INCLUDED_DOC_SUBDIRS = {
    "adr",
    "design",
    "release",
}

INCLUDED_TOP_LEVEL_DOC_FILES = {
    "TROUBLESHOOTING.md",
}

DOCS_TOP_LEVEL_DIR = "docs"
GIT_DIR_NAME = ".git"
GIT_INDEX_NAME = "index"
GIT_LS_FILES_COMMAND = ("git", "ls-files", "--error-unmatch", "--")
PATH_PARENT_MARKER = ".."
SOURCE_PACK_MANIFEST_NAME = "SOURCE-PACK-MANIFEST.json"
SOURCE_PACK_MANIFEST_SCHEMA_VERSION = "1"
SOURCE_PACK_MANIFEST_FILES_KEY = "files"
SOURCE_PACK_TAR_WRITE_MODE = "w:gz"
SOURCE_PACK_POLICY = (
    "git-tracked files by default; extracted source packs reuse "
    "SOURCE-PACK-MANIFEST.json; untracked files require explicit opt-in"
)
SOURCE_PACK_FILE_COUNT_BASIS = (
    "packaged files excluding SOURCE-PACK-MANIFEST.json"
)
TRACKED_ONLY_MISSING_CONTEXT_MESSAGE = (
    "tracked-only source-pack mode requires .git/index or "
    "SOURCE-PACK-MANIFEST.json; use --include-untracked only for internal snapshots"
)
INVALID_MANIFEST_FILES_MESSAGE = "SOURCE-PACK-MANIFEST.json has an invalid files list"


@dataclass(frozen=True)
class SourcePackResult:
    repo_root: str
    output_path: str
    file_count: int
    manifest_name: str
    files: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "repo_root": self.repo_root,
            "output_path": self.output_path,
            "file_count": self.file_count,
            "manifest_name": self.manifest_name,
            "files": list(self.files),
        }


def create_source_pack(
    repo_root: str | Path,
    output_path: str | Path,
    include_untracked: bool = False,
) -> SourcePackResult:
    root = Path(repo_root).resolve()
    output = Path(output_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    files = tuple(iter_source_pack_files(root, include_untracked=include_untracked))
    manifest_name = SOURCE_PACK_MANIFEST_NAME
    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "manifest_schema_version": SOURCE_PACK_MANIFEST_SCHEMA_VERSION,
        "file_count": len(files),
        "file_count_basis": SOURCE_PACK_FILE_COUNT_BASIS,
        "include_untracked": include_untracked,
        "source_pack_policy": SOURCE_PACK_POLICY,
        SOURCE_PACK_MANIFEST_FILES_KEY: list(files),
    }

    with tempfile.TemporaryDirectory() as tmp:
        manifest_path = Path(tmp) / manifest_name
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        with tarfile.open(output, SOURCE_PACK_TAR_WRITE_MODE) as archive:
            for relative in files:
                source = root / relative
                archive.add(source, arcname=relative, recursive=False)
            archive.add(manifest_path, arcname=manifest_name, recursive=False)

    return SourcePackResult(
        repo_root=str(root),
        output_path=str(output),
        file_count=len(files),
        manifest_name=manifest_name,
        files=files,
    )


def iter_source_pack_files(
    repo_root: str | Path,
    include_untracked: bool = False,
) -> list[str]:
    root = Path(repo_root).resolve()
    results: list[str] = []
    manifest_files = None
    if not include_untracked and not _has_git_index(root):
        manifest_files = _source_pack_manifest_files(root)

    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        relative_posix = relative.as_posix()

        if not should_include_source_pack_path(relative):
            continue

        if path.is_symlink():
            raise ValueError(f"source pack refuses symlink: {relative_posix}")

        if not path.is_file():
            continue

        if not include_untracked:
            if manifest_files is not None:
                if relative_posix not in manifest_files:
                    continue
            elif not _is_git_tracked(root, relative_posix):
                continue

        results.append(relative_posix)

    return results


def should_include_source_pack_path(relative_path: str | Path) -> bool:
    relative = Path(relative_path)
    parts = relative.parts

    if not parts:
        return False

    if any(part in EXCLUDED_DIR_NAMES for part in parts[:-1]):
        return False

    name = relative.name
    if name in EXCLUDED_FILE_NAMES:
        return False

    if name.startswith(".") and name not in ALLOWED_DOTFILES:
        return False

    suffixes = set(relative.suffixes)
    if suffixes & EXCLUDED_SUFFIXES:
        return False

    if relative.suffix.lower() in EXCLUDED_SUFFIXES:
        return False

    top = parts[0]
    if top not in DEFAULT_INCLUDED_TOP_LEVEL:
        return False

    if top == DOCS_TOP_LEVEL_DIR and len(parts) > 1:
        if len(parts) == 2 and parts[1] in INCLUDED_TOP_LEVEL_DOC_FILES:
            return True
        if parts[1] not in INCLUDED_DOC_SUBDIRS:
            return False

    return True


def _has_git_index(root: Path) -> bool:
    return (root / GIT_DIR_NAME / GIT_INDEX_NAME).exists()


def _source_pack_manifest_files(root: Path) -> set[str]:
    manifest_path = root / SOURCE_PACK_MANIFEST_NAME
    if not manifest_path.exists():
        raise ValueError(TRACKED_ONLY_MISSING_CONTEXT_MESSAGE)

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = data.get(SOURCE_PACK_MANIFEST_FILES_KEY)
    if not isinstance(files, list) or not all(isinstance(item, str) for item in files):
        raise ValueError(INVALID_MANIFEST_FILES_MESSAGE)

    safe_files = set()
    for item in files:
        relative = Path(item)
        if relative.is_absolute() or PATH_PARENT_MARKER in relative.parts:
            raise ValueError(f"SOURCE-PACK-MANIFEST.json contains unsafe path: {item}")
        safe_files.add(relative.as_posix())
    return safe_files


def _is_git_tracked(root: Path, relative_posix: str) -> bool:
    import subprocess

    result = subprocess.run(
        [*GIT_LS_FILES_COMMAND, relative_posix],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0
