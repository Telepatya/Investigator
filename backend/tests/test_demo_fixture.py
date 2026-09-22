from __future__ import annotations

import unittest
from pathlib import Path

from app.ingest.parsers import parse_file


class SyntheticDemoFixtureTests(unittest.TestCase):
    def test_demo_case_parses_expected_records_and_categories(self) -> None:
        fixture = (
            Path(__file__).resolve().parents[2]
            / "demo"
            / "synthetic-case"
            / "synthetic-defender.jsonl"
        )
        events = list(parse_file(fixture, fixture.name))

        self.assertEqual(len(events), 9)
        self.assertEqual({event["host"] for event in events}, {"EXAMPLE-WKS"})
        self.assertSetEqual(
            {event["category"] for event in events},
            {"filesystem", "process", "persistence", "network", "account"},
        )
        self.assertTrue(all(event["timestamp"] is not None for event in events))
        self.assertTrue(all("example.invalid" not in str(event.get("host", "")) for event in events))


if __name__ == "__main__":
    unittest.main()
