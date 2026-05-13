"""Source-pack generation for AI/developer handoff.

The source pack is intentionally conservative. It packages code, tests, config,
and design docs while excluding local scratch files, generated runtime artifacts,
packet captures, caches, credentials, and VCS internals.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Union


DEFAULT_INCLUDED_TOP_LEVEL = {
    "config",
    "deploy",
    "docs",
    "scripts",
    "oad_parser",
    "README.md",
    "START_HERE.md",
    "USER_MANUAL.md",
    "AI_CONTEXT.md",
    "CHANGELOG.md",
    "CODEOWNERS",
    "standards-manifest.json",
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
    "reports",
}

EXCLUDED_FILE_NAMES = {
    "demo.sh",
    "corpus-report.json",
    "corpus-summary.txt",
    ".env",
    ".env.local",
    "credentials.json",
    "token.json",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}

EXCLUDED_SUFFIXES = {
    ".pcap",
    ".cap",
    ".pcapng",
    ".bin",
    ".payload",
    ".ecg",
    ".jsonl",
    ".pyc",
    ".pyo",
    ".log",
    ".tmp",
    ".tar",
    ".gz",
    ".zip",
    ".pem",
    ".key",
    ".pfx",
    ".p12",
}

ALLOWED_DOTFILES = {
    ".gitlab-ci.yml",
    ".gitignore",
}

INCLUDED_DOC_SUBDIRS = {
    "adr",
    "design",
    "ops",
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
SOURCE_PACK_MANIFEST_SCHEMA_VERSION = "2.0"
SOURCE_PACK_MANIFEST_FILES_KEY = "files"
SOURCE_PACK_TAR_WRITE_MODE = "w:gz"
SOURCE_PACK_PROFILE = "parser-project"
SOURCE_PACK_TASK_SCOPE = (
    "OAD Parser source, tests, docs, config, governance, verification scripts, "
    "CI configuration, and customer-safe handoff files"
)
SOURCE_PACK_POLICY = (
    "git-tracked files by default; extracted source packs reuse "
    "SOURCE-PACK-MANIFEST.json; untracked files require explicit opt-in"
)
SOURCE_PACK_FILE_COUNT_BASIS = "packaged files excluding SOURCE-PACK-MANIFEST.json"
TRACKED_ONLY_MISSING_CONTEXT_MESSAGE = (
    "tracked-only source-pack mode requires .git/index or "
    "SOURCE-PACK-MANIFEST.json; use --include-untracked only for internal snapshots"
)
INVALID_MANIFEST_FILES_MESSAGE = "SOURCE-PACK-MANIFEST.json has an invalid files list"
VALIDATION_COMMAND_USED = "python3 -m oad_parser validate-platform"
VALIDATION_RESULT_NOT_RUN = "not_run_by_source_pack_generator"
SOURCE_REPOSITORY_IDENTIFIER = "oad-parser"

MANUAL_CONTROLS = [
    "GitLab protected main branch must be configured in the platform.",
    "GitLab protected v* tags must be configured in the platform.",
    "GitLab merge request approvals and CODEOWNERS approval must be configured after placeholder owners are replaced.",
    "GitLab protected and masked CI variables must be configured in the platform.",
    "Registry1 approved Python CI image pinned by digest must be supplied by the platform owner.",
    "Release and publish permissions must be restricted in the platform.",
    "controlled-data handling, data classification, and external AI/customer handoff approval remain manual controls.",
    "SBOM, signing, and provenance evidence are manual/platform controls until approved tooling is added.",
]

EXCLUDED_PATH_REASONS = [
    {"path": ".git/", "reason": "Git internals are not part of customer or AI handoff."},
    {"path": "reports/", "reason": "Generated validation evidence is not committed or source-packed by default."},
    {"path": "dist/", "reason": "Build outputs and archives are excluded by default."},
    {"path": "build/", "reason": "Build outputs are excluded by default."},
    {"path": "__pycache__/", "reason": "Python caches are excluded by default."},
    {"path": ".pytest_cache/", "reason": "Test caches are excluded by default."},
    {"path": ".mypy_cache/", "reason": "Type-check caches are excluded by default."},
    {"path": ".ruff_cache/", "reason": "Lint caches are excluded by default."},
    {"path": ".venv/", "reason": "Local virtual environments are excluded by default."},
    {"path": "venv/", "reason": "Local virtual environments are excluded by default."},
    {"path": "*.pcap", "reason": "Packet captures may contain private or controlled data."},
    {"path": "*.pcapng", "reason": "Packet captures may contain private or controlled data."},
    {"path": "*.cap", "reason": "Packet captures may contain private or controlled data."},
    {"path": "*.bin", "reason": "Raw payload files may contain private or controlled data."},
    {"path": "*.payload", "reason": "Raw payload files may contain private or controlled data."},
    {"path": "*.ecg", "reason": "Raw ECG payload files may contain private or controlled data."},
    {"path": "*.jsonl", "reason": "Generated parser output may contain operational artifacts."},
    {"path": "*.tar", "reason": "Archives are excluded unless explicitly generated as the source pack."},
    {"path": "*.gz", "reason": "Archives are excluded unless explicitly generated as the source pack."},
    {"path": "*.zip", "reason": "Archives are excluded unless explicitly generated as the source pack."},
    {"path": "*.pem", "reason": "Private keys or certificates are excluded."},
    {"path": "*.key", "reason": "Private keys are excluded."},
    {"path": ".env", "reason": "Local environment and secret files are excluded."},
    {"path": "credentials.json", "reason": "Credential files are excluded."},
    {"path": "token.json", "reason": "Token files are excluded."},
]


@dataclass(frozen=True)
class SourcePackResult:
    repo_root: str
    output_path: str
    file_count: int
    manifest_name: str
    files: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "repo_root": self.repo_root,
            "output_path": self.output_path,
            "file_count": self.file_count,
            "manifest_name": self.manifest_name,
            "files": list(self.files),
        }


def create_source_pack(
    repo_root: Union[str, Path],
    output_path: Union[str, Path],
    include_untracked: bool = False,
) -> SourcePackResult:
    root = Path(repo_root).resolve()
    output = Path(output_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    files = tuple(iter_source_pack_files(root, include_untracked=include_untracked))
    manifest_name = SOURCE_PACK_MANIFEST_NAME
    file_hashes = _file_hashes(root, files)
    byte_count = sum((root / relative).stat().st_size for relative in files)
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    manifest = {
        "schema_version": SOURCE_PACK_MANIFEST_SCHEMA_VERSION,
        "manifest_schema_version": SOURCE_PACK_MANIFEST_SCHEMA_VERSION,
        "generated_at_utc": timestamp,
        "created_utc": timestamp,
        "source_repository_identifier": SOURCE_REPOSITORY_IDENTIFIER,
        "selected_profile": SOURCE_PACK_PROFILE,
        "profile": SOURCE_PACK_PROFILE,
        "task_scope": SOURCE_PACK_TASK_SCOPE,
        "file_count": len(files),
        "file_count_basis": SOURCE_PACK_FILE_COUNT_BASIS,
        "byte_count": byte_count,
        "include_untracked": include_untracked,
        "source_pack_policy": SOURCE_PACK_POLICY,
        "included_paths": list(files),
        "excluded_paths": EXCLUDED_PATH_REASONS,
        "file_hashes": file_hashes,
        "warnings": [],
        "validation": {
            "command_used": VALIDATION_COMMAND_USED,
            "result": VALIDATION_RESULT_NOT_RUN,
            "note": "Run bash scripts/verify.sh before release or customer handoff evidence collection.",
        },
        "manual_controls": MANUAL_CONTROLS,
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
    repo_root: Union[str, Path],
    include_untracked: bool = False,
) -> List[str]:
    root = Path(repo_root).resolve()
    results = []
    manifest_files = None
    if not include_untracked and not _has_git_index(root):
        manifest_files = _source_pack_manifest_files(root)

    for current_dir, dirnames, filenames in os.walk(str(root)):
        current_path = Path(current_dir)
        relative_dir = current_path.relative_to(root)

        pruned_dirs = []
        for dirname in sorted(dirnames):
            if dirname in EXCLUDED_DIR_NAMES:
                continue
            if relative_dir.parts == () and dirname not in DEFAULT_INCLUDED_TOP_LEVEL:
                continue
            if relative_dir.parts == (DOCS_TOP_LEVEL_DIR,) and dirname not in INCLUDED_DOC_SUBDIRS:
                continue
            pruned_dirs.append(dirname)
        dirnames[:] = pruned_dirs

        for filename in sorted(filenames):
            path = current_path / filename
            relative = path.relative_to(root)
            relative_posix = relative.as_posix()

            if not should_include_source_pack_path(relative):
                continue

            if path.is_symlink():
                raise ValueError("source pack refuses symlink: %s" % relative_posix)

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


def should_include_source_pack_path(relative_path: Union[str, Path]) -> bool:
    # SPRINT2_OPERATOR_HANDOFF_INCLUDES: keep operator handoff docs self-contained in source packs.
    explicit_sprint2_operator_handoff_includes = {
        "deploy/systemd/ecg-parser@.service",
        "docs/ops/systemd-live-parser.md",
        "docs/ops/filebeat-elastic-agent-handoff.md",
    }
    normalized_relative_path = str(relative_path).replace("\\", "/").lstrip("./")
    if normalized_relative_path in explicit_sprint2_operator_handoff_includes:
        return True

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


def _source_pack_manifest_files(root: Path) -> set:
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
            raise ValueError("SOURCE-PACK-MANIFEST.json contains unsafe path: %s" % item)
        safe_files.add(relative.as_posix())
    return safe_files


def _is_git_tracked(root: Path, relative_posix: str) -> bool:
    import subprocess

    if shutil.which("git") is None:
        return True

    try:
        result = subprocess.run(
            [*GIT_LS_FILES_COMMAND, relative_posix],
            cwd=root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except FileNotFoundError:
        return True

    return result.returncode == 0

def _file_hashes(root: Path, files: Tuple[str, ...]) -> Dict[str, str]:
    hashes = {}
    for relative in files:
        hashes[relative] = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    return hashes
