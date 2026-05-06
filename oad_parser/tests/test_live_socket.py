"""Unit tests for live socket constants and helpers."""

import unittest

from oad_parser.ingest.live_socket import ETH_P_ALL


class LiveSocketTests(unittest.TestCase):
    def test_eth_p_all_constant_matches_linux_packet_capture_value(self):
        self.assertEqual(ETH_P_ALL, 0x0003)


if __name__ == "__main__":
    unittest.main()
