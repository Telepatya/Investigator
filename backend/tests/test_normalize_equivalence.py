from __future__ import annotations

# ruff: noqa: E402
#
# Golden-value equivalence tests locking the Phase-1 ingest hot-path
# optimizations to the behavior of the pre-optimization implementation.
# The expected values below were captured from the unmodified code.

import sys
import types
import unittest
from datetime import datetime, timezone

sys.modules.setdefault("keyring", types.SimpleNamespace(
    get_password=lambda *_a, **_k: None,
    set_password=lambda *_a, **_k: None,
    delete_password=lambda *_a, **_k: None,
    errors=types.SimpleNamespace(PasswordDeleteError=Exception),
))
sys.modules.setdefault("pydantic", types.SimpleNamespace(
    BaseModel=object,
    Field=lambda default=None, default_factory=None, **_k: default_factory() if default_factory else default,
))

from app.ingest.normalize import decode_win_codes, parse_timestamp, summarize_row
from app.ingest.parsers import _json_safe


# (input, expected ISO string or None) captured from unmodified parse_timestamp.
_TS_GOLDEN = {
    "2021-05-03T12:34:56.123456+00:00": "2021-05-03T12:34:56.123456+00:00",
    "2021-05-03T12:34:56+00:00": "2021-05-03T12:34:56+00:00",
    "2021-05-03 12:34:56.123456+00:00": "2021-05-03T12:34:56.123456+00:00",
    "2021-05-03 12:34:56+00:00": "2021-05-03T12:34:56+00:00",
    "2021-05-03T12:34:56.123456": "2021-05-03T12:34:56.123456+00:00",
    "2021-05-03T12:34:56": "2021-05-03T12:34:56+00:00",
    "2021-05-03 12:34:56.123456": "2021-05-03T12:34:56.123456+00:00",
    "2021-05-03 12:34:56": "2021-05-03T12:34:56+00:00",
    "2021-05-03 12:34:56 UTC": "2021-05-03T12:34:56+00:00",
    "05/03/2021 12:34:56": "2021-05-03T12:34:56+00:00",
    "03/05/2021 12:34:56": "2021-03-05T12:34:56+00:00",
    "03/May/2021:12:34:56 +0000": "2021-05-03T12:34:56+00:00",
    "03/May/2021:12:34:56": "2021-05-03T12:34:56+00:00",
    "2021-05-03T12:34:56.123456789Z": "2021-05-03T12:34:56.123456+00:00",
    "2021-05-03T12:34:56Z": "2021-05-03T12:34:56+00:00",
    "-": None,
    "N/A": None,
    "0": None,
    "": None,
    "   ": None,
    "1620045296": "2021-05-03T12:34:56+00:00",
    "1620045296123": "2021-05-03T12:34:56.123000+00:00",
    "1620045296123456": "2021-05-03T12:34:56.123456+00:00",
    "1620045296123456789": "2021-05-03T12:34:56.123457+00:00",
    "1620045296.5": "2021-05-03T12:34:56.500000+00:00",
    "not a date at all": None,
}

_TS_NUM_GOLDEN = {
    0: None,
    -5: None,
    1620045296: "2021-05-03T12:34:56+00:00",
    1620045296123: "2021-05-03T12:34:56.123000+00:00",
    1620045296123456: "2021-05-03T12:34:56.123456+00:00",
    1620045296123456789: "2021-05-03T12:34:56.123457+00:00",
    1620045296.5: "2021-05-03T12:34:56.500000+00:00",
}


class NormalizeEquivalenceTests(unittest.TestCase):
    def test_parse_timestamp_strings(self) -> None:
        for value, expected in _TS_GOLDEN.items():
            result = parse_timestamp(value)
            got = result.isoformat() if result else None
            self.assertEqual(got, expected, f"parse_timestamp({value!r})")

    def test_parse_timestamp_numbers(self) -> None:
        for value, expected in _TS_NUM_GOLDEN.items():
            result = parse_timestamp(value)
            got = result.isoformat() if result else None
            self.assertEqual(got, expected, f"parse_timestamp({value!r})")

    def test_parse_timestamp_datetime_passthrough(self) -> None:
        naive = datetime(2021, 5, 3, 12, 34, 56)
        self.assertEqual(parse_timestamp(naive), naive.replace(tzinfo=timezone.utc))
        aware = datetime(2021, 5, 3, 12, 34, 56, tzinfo=timezone.utc)
        self.assertIs(parse_timestamp(aware), aware)

    def test_parse_timestamp_cache_is_consistent(self) -> None:
        # Repeated calls (cache hits) return equal values.
        first = parse_timestamp("2021-05-03T12:34:56")
        second = parse_timestamp("2021-05-03T12:34:56")
        self.assertEqual(first, second)

    def test_decode_win_codes(self) -> None:
        self.assertEqual(
            decode_win_codes({"a": "%%1842", "b": "plain", "c": "%%9999", "d": 123}),
            {"a": "Enabled", "b": "plain", "c": "%%9999", "d": 123},
        )
        # Fast path: no codes -> content identical (and same object returned).
        row = {"x": "y", "n": 1, "lst": [1, 2]}
        self.assertEqual(decode_win_codes(row), {"x": "y", "n": 1, "lst": [1, 2]})

    def test_summarize_row(self) -> None:
        self.assertEqual(
            summarize_row({"Message": "hello world", "EventID": 4624, "extra": "x"}),
            "Message=hello world; EventID=4624",
        )
        self.assertEqual(summarize_row({"weird": "only", "nested": {"a": 1}}), "weird=only")
        self.assertEqual(summarize_row({}), "{}")

    def test_json_safe_plain_passthrough(self) -> None:
        obj = {"a": 1, "b": [1, 2, {"c": "x"}], "d": None, "e": True, "f": 1.5}
        self.assertIs(_json_safe(obj), obj)

    def test_json_safe_non_plain_matches_old_behavior(self) -> None:
        from pathlib import Path

        for obj in (
            {"t": datetime(2021, 1, 1)},
            {"p": Path("/tmp/x")},
            {"b": b"bytes"},
            {"tup": (1, 2, 3)},
            {1: "int-key"},
            {"nested": {"dt": datetime(2020, 5, 5), "ok": 1}},
            {"floatkey": 1.5, "boolkey": False, "nonekey": None},
        ):
            self.assertEqual(
                _json_safe(obj), _reference_json_safe(obj), f"_json_safe({obj!r})"
            )


def _reference_json_safe(obj):
    """Verbatim copy of the pre-optimization _json_safe, for equivalence checks."""
    import json

    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        return json.loads(json.dumps(obj, default=str))


if __name__ == "__main__":
    unittest.main()
