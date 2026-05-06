"""Unit tests for parsed record models."""

import unittest

from oad_parser.models import ParsedPlot


class ParsedPlotTests(unittest.TestCase):
    def test_ecs_serialization_uses_dotted_fields(self):
        record = ParsedPlot(
            source_ip="10.0.0.1",
            source_port=1234,
            destination_ip="10.0.0.2",
            destination_port=5678,
            observer_interface="eth0",
            sequence=7,
        )

        output = record.to_ecs_dict()

        self.assertEqual(output["source.ip"], "10.0.0.1")
        self.assertEqual(output["source.port"], 1234)
        self.assertEqual(output["destination.ip"], "10.0.0.2")
        self.assertEqual(output["destination.port"], 5678)
        self.assertEqual(output["observer.interface"], "eth0")
        self.assertEqual(output["sequence"], 7)

    def test_legacy_serialization_adds_aliases(self):
        record = ParsedPlot(source_ip="10.0.0.1", destination_ip="10.0.0.2")
        output = record.to_legacy_dict()

        self.assertEqual(output["source.ip"], "10.0.0.1")
        self.assertEqual(output["source_ip"], "10.0.0.1")
        self.assertEqual(output["destination.ip"], "10.0.0.2")
        self.assertEqual(output["destination_ip"], "10.0.0.2")


if __name__ == "__main__":
    unittest.main()
