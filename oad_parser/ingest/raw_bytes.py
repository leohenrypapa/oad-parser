"""Raw byte-file input helper for parser fixtures."""

from __future__ import annotations

from pathlib import Path


def read_bytes(path: str | Path) -> bytes:
    return Path(path).read_bytes()
