"""Linux raw-socket live capture adapter.

This is intentionally isolated from parser core. Live capture usually requires
root privileges or equivalent Linux capabilities.
"""

from __future__ import annotations

from collections.abc import Iterator
from socket import AF_PACKET, SOCK_RAW, htons, socket


ETH_P_ALL = 0x0003
DEFAULT_CAPTURE_BUFFER_BYTES = 65535


def iter_live_frames(
    interface: str,
    max_frames: int | None = None,
    buffer_size: int = DEFAULT_CAPTURE_BUFFER_BYTES,
) -> Iterator[bytes]:
    if not interface:
        raise ValueError("interface is required")

    count = 0

    with socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) as sock:
        sock.bind((interface, 0))

        while max_frames is None or count < max_frames:
            frame, _address = sock.recvfrom(buffer_size)
            count += 1
            yield frame
