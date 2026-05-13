"""Unit tests for live socket constants and helpers."""

from datetime import datetime, timezone
import unittest

from oad_parser.config import LiveParserConfig
from oad_parser.ingest.live_socket import (
    DEFAULT_CAPTURE_BUFFER_BYTES,
    ETH_P_ALL,
    iter_live_capture_frames,
    iter_live_capture_frames_from_config,
    iter_live_frames,
)


FIXED_TIME = datetime(2026, 5, 12, 19, 0, 0, tzinfo=timezone.utc)


class FakeSocket:
    def __init__(self, frames):
        self.frames = list(frames)
        self.bound_address = None
        self.recv_buffer_sizes = []
        self.recvfrom_sizes = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.closed = True
        return False

    def bind(self, address):
        self.bound_address = address

    def setsockopt(self, level, option, value):
        self.recv_buffer_sizes.append((level, option, value))

    def recvfrom(self, size):
        self.recvfrom_sizes.append(size)
        if not self.frames:
            raise RuntimeError("fake socket exhausted")
        return self.frames.pop(0), ("eno1", 0)


class SocketFactory:
    def __init__(self, fake_socket):
        self.fake_socket = fake_socket
        self.calls = []

    def __call__(self, family, sock_type, proto):
        self.calls.append((family, sock_type, proto))
        return self.fake_socket


class LiveSocketTests(unittest.TestCase):
    def test_eth_p_all_constant_matches_linux_packet_capture_value(self):
        self.assertEqual(ETH_P_ALL, 0x0003)

    def test_iter_live_capture_frames_yields_timestamped_metadata(self):
        fake_socket = FakeSocket([b"first", b"second"])
        factory = SocketFactory(fake_socket)

        frames = list(
            iter_live_capture_frames(
                "eno1",
                max_frames=2,
                buffer_size=4096,
                socket_factory=factory,
                now_fn=lambda: FIXED_TIME,
            )
        )

        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0].frame_bytes, b"first")
        self.assertEqual(frames[0].interface, "eno1")
        self.assertEqual(frames[0].capture_time_utc, FIXED_TIME)
        self.assertEqual(frames[0].frame_length, 5)
        self.assertEqual(frames[0].sequence_number, 1)
        self.assertEqual(frames[1].sequence_number, 2)
        self.assertEqual(fake_socket.bound_address, ("eno1", 0))
        self.assertEqual(fake_socket.recvfrom_sizes, [4096, 4096])
        self.assertTrue(fake_socket.closed)
        self.assertEqual(len(factory.calls), 1)

    def test_iter_live_frames_preserves_raw_bytes_behavior(self):
        fake_socket = FakeSocket([b"first", b"second"])
        factory = SocketFactory(fake_socket)

        frames = list(
            iter_live_frames(
                "eno2",
                max_frames=2,
                socket_factory=factory,
            )
        )

        self.assertEqual(frames, [b"first", b"second"])
        self.assertEqual(fake_socket.bound_address, ("eno2", 0))
        self.assertEqual(
            fake_socket.recvfrom_sizes,
            [DEFAULT_CAPTURE_BUFFER_BYTES, DEFAULT_CAPTURE_BUFFER_BYTES],
        )

    def test_iter_live_capture_frames_applies_receive_buffer(self):
        fake_socket = FakeSocket([b"frame"])
        factory = SocketFactory(fake_socket)

        frames = list(
            iter_live_capture_frames(
                "eno3",
                max_frames=1,
                receive_buffer_bytes=1048576,
                socket_factory=factory,
                now_fn=lambda: FIXED_TIME,
            )
        )

        self.assertEqual(len(frames), 1)
        self.assertEqual(len(fake_socket.recv_buffer_sizes), 1)
        _level, _option, value = fake_socket.recv_buffer_sizes[0]
        self.assertEqual(value, 1048576)

    def test_iter_live_capture_frames_from_config_uses_interface_and_receive_buffer(self):
        fake_socket = FakeSocket([b"frame"])
        factory = SocketFactory(fake_socket)
        config = LiveParserConfig(interface="eno4", receive_buffer_bytes=2097152)

        frames = list(
            iter_live_capture_frames_from_config(
                config,
                max_frames=1,
                socket_factory=factory,
                now_fn=lambda: FIXED_TIME,
            )
        )

        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].interface, "eno4")
        self.assertEqual(fake_socket.bound_address, ("eno4", 0))
        self.assertEqual(fake_socket.recv_buffer_sizes[0][2], 2097152)

    def test_live_capture_frame_to_dict_includes_sequence_number_when_available(self):
        fake_socket = FakeSocket([b"frame"])
        factory = SocketFactory(fake_socket)

        frame = list(
            iter_live_capture_frames(
                "eno5",
                max_frames=1,
                socket_factory=factory,
                now_fn=lambda: FIXED_TIME,
            )
        )[0]

        self.assertEqual(
            frame.to_dict(),
            {
                "interface": "eno5",
                "capture_time_utc": "2026-05-12T19:00:00Z",
                "frame_length": 5,
                "sequence_number": 1,
            },
        )

    def test_rejects_invalid_capture_arguments(self):
        with self.assertRaises(ValueError):
            list(iter_live_capture_frames("", max_frames=0))

        with self.assertRaises(ValueError):
            list(iter_live_capture_frames("eno1", max_frames=-1))

        with self.assertRaises(ValueError):
            list(iter_live_capture_frames("eno1", max_frames=0, buffer_size=0))

        with self.assertRaises(ValueError):
            list(iter_live_capture_frames("eno1", max_frames=0, receive_buffer_bytes=0))


if __name__ == "__main__":
    unittest.main()
