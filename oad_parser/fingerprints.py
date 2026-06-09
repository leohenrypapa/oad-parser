"""Hash helpers for parser fingerprints.

Parser fingerprints are non-security identifiers used for deterministic
comparison and test fixtures. SHA-256 is the authoritative fingerprint format.
The MD5 helper remains only for legacy fixture compatibility.
"""

from __future__ import annotations

import hashlib
from typing import Any


def md5(data: bytes = b"", *args: Any, **kwargs: Any) -> "hashlib._Hash":
    """Return an MD5 hash object for non-security parser fingerprints.

    Python 3.9+ supports the usedforsecurity keyword in hashlib constructors.
    Older compatible interpreters may not, so this helper falls back only when
    the keyword is unsupported.
    """

    if "usedforsecurity" not in kwargs:
        kwargs["usedforsecurity"] = False

    try:
        return hashlib.md5(data, *args, **kwargs)
    except TypeError:
        compat_kwargs = dict(kwargs)
        compat_kwargs.pop("usedforsecurity", None)
        return hashlib.md5(data, *args, **compat_kwargs)



def sha256(data: bytes = b"", *args: Any, **kwargs: Any) -> "hashlib._Hash":
    """Return a SHA-256 hash object for parser fingerprints."""

    return hashlib.sha256(data, *args, **kwargs)
