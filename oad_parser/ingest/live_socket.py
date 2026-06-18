"""Linux raw-socket live capture adapter.

This is intentionally isolated from parser core. Live capture usually requires
root privileges or equivalent Linux capabilities.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
import select
from socket import AF_PACKET, SO_RCVBUF, SOCK_RAW, SOL_SOCKET, htons, socket
from typing import Callable, Optional, Protocol

from oad_parser.config import LiveParserConfig
from oad_parser.live.records import LiveCaptureFrame


ETH_P_ALL = 0x0003
DEFAULT_CAPTURE_BUFFER_BYTES = 65535

SocketFactory = Callable[[int, int, int], object]
NowFn = Callable[[], datetime]
SelectFn = Callable[[object, object, object, float], tuple]


class StopEvent(Protocol):
    def is_set(self) -> bool:
        ...


def iter_live_frames(
    interface: str,
    max_frames: int | None = None,
    buffer_size: int = DEFAULT_CAPTURE_BUFFER_BYTES,
    *,
    receive_buffer_bytes: Optional[int] = None,
    socket_factory: Optional[SocketFactory] = None,
    stop_event: Optional[StopEvent] = None,
) -> Iterator[bytes]:
    """Yield raw frame bytes for the legacy bounded capture path."""

    for capture_frame in iter_live_capture_frames(
        interface,
        max_frames=max_frames,
        buffer_size=buffer_size,
        receive_buffer_bytes=receive_buffer_bytes,
        socket_factory=socket_factory,
        stop_event=stop_event,
    ):
        if capture_frame is None:
            continue
        yield capture_frame.frame_bytes


def iter_live_capture_frames(
    interface: str,
    max_frames: int | None = None,
    buffer_size: int = DEFAULT_CAPTURE_BUFFER_BYTES,
    *,
    receive_buffer_bytes: Optional[int] = None,
    socket_factory: Optional[SocketFactory] = None,
    now_fn: Optional[NowFn] = None,
    stop_event: Optional[StopEvent] = None,
    idle_poll_seconds: float = 1.0,
    select_fn: Optional[SelectFn] = None,
) -> Iterator[Optional[LiveCaptureFrame]]:
    """Yield timestamped LiveCaptureFrame objects from a Linux raw socket."""

    if not interface:
        raise ValueError("interface is required")
    if max_frames is not None and max_frames < 0:
        raise ValueError("max_frames must be >= 0")
    if buffer_size < 1:
        raise ValueError("buffer_size must be >= 1")
    if receive_buffer_bytes is not None and receive_buffer_bytes < 1:
        raise ValueError("receive_buffer_bytes must be >= 1")
    if idle_poll_seconds <= 0:
        raise ValueError("idle_poll_seconds must be > 0")

    resolved_socket_factory = socket_factory if socket_factory is not None else socket
    resolved_now_fn = now_fn if now_fn is not None else _utc_now
    resolved_select_fn = select_fn if select_fn is not None else _select_readable

    count = 0

    with resolved_socket_factory(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) as sock:
        if receive_buffer_bytes is not None:
            sock.setsockopt(SOL_SOCKET, SO_RCVBUF, receive_buffer_bytes)

        sock.bind((interface, 0))

        while max_frames is None or count < max_frames:
            if stop_event is not None and stop_event.is_set():
                break
            if hasattr(sock, "fileno"):
                readable, _writable, _errors = resolved_select_fn([sock], [], [], idle_poll_seconds)
                if not readable:
                    yield None
                    continue
            frame, _address = sock.recvfrom(buffer_size)
            count += 1
            yield LiveCaptureFrame(
                frame_bytes=frame,
                interface=interface,
                capture_time_utc=resolved_now_fn(),
                frame_length=len(frame),
                sequence_number=count,
            )


def iter_live_capture_frames_from_config(
    config: LiveParserConfig,
    *,
    max_frames: int | None = None,
    buffer_size: int = DEFAULT_CAPTURE_BUFFER_BYTES,
    socket_factory: Optional[SocketFactory] = None,
    now_fn: Optional[NowFn] = None,
    stop_event: Optional[StopEvent] = None,
    idle_poll_seconds: float = 1.0,
) -> Iterator[Optional[LiveCaptureFrame]]:
    """Yield capture frames using interface and receive buffer from config."""

    return iter_live_capture_frames(
        config.interface,
        max_frames=max_frames,
        buffer_size=buffer_size,
        receive_buffer_bytes=config.receive_buffer_bytes,
        socket_factory=socket_factory,
        now_fn=now_fn,
        stop_event=stop_event,
        idle_poll_seconds=idle_poll_seconds,
    )


def _select_readable(read_list, write_list, error_list, timeout):
    return select.select(read_list, write_list, error_list, timeout)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
