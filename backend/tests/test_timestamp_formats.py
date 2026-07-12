from __future__ import annotations

# Regression coverage for timestamp parsing, especially the Sentinel / Log
# Analytics / Defender portal grid locale formats ("7/8/2026, 11:57:31.123 AM")
# added to fix Sentinel exports vanishing from the timeline. Also pins the
# pre-existing formats so the order-sensitive list can't silently regress.

import unittest
from datetime import datetime, timedelta, timezone

from app.ingest.normalize import (
    _parse_timestamp_str,
    extract_timestamp,
    parse_timestamp,
)


def _utc(*args) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


class LocaleTimestampTests(unittest.TestCase):
    def setUp(self) -> None:
        # _parse_timestamp_str is lru_cached; clear so format changes take effect
        # and results never leak between assertions.
        _parse_timestamp_str.cache_clear()

    def test_portal_grid_am_pm(self) -> None:
        self.assertEqual(parse_timestamp("7/8/2026, 11:57:31.123 AM"),
                         _utc(2026, 7, 8, 11, 57, 31, 123000))
        self.assertEqual(parse_timestamp("7/8/2026, 11:57:31 PM"),
                         _utc(2026, 7, 8, 23, 57, 31))
        self.assertEqual(parse_timestamp("12/25/2026, 12:00:00 AM"),
                         _utc(2026, 12, 25, 0, 0, 0))

    def test_seven_fractional_digits_with_am_suffix(self) -> None:
        # _FRAC_TRIM_RE must trim to 6 digits WITHOUT dropping the trailing " AM".
        self.assertEqual(parse_timestamp("7/8/2026 11:57:31.1234567 AM"),
                         _utc(2026, 7, 8, 11, 57, 31, 123456))

    def test_no_comma_and_24h_locale_variants(self) -> None:
        self.assertEqual(parse_timestamp("7/8/2026 11:57:31 PM"),
                         _utc(2026, 7, 8, 23, 57, 31))
        self.assertEqual(parse_timestamp("07/08/2026, 23:57:31"),
                         _utc(2026, 7, 8, 23, 57, 31))

    def test_us_order_precedence_for_ambiguous_days(self) -> None:
        # day <= 12 is ambiguous; documented behaviour is US-order (%m/%d) first.
        self.assertEqual(parse_timestamp("03/04/2026, 01:02:03"),
                         _utc(2026, 3, 4, 1, 2, 3))

    def test_extract_timestamp_from_labelled_column_with_locale_value(self) -> None:
        row = {"TimeGenerated [UTC]": "7/8/2026, 11:57:31 AM", "DeviceName": "WKS-01"}
        self.assertEqual(extract_timestamp(row), _utc(2026, 7, 8, 11, 57, 31))


class PreExistingFormatRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        _parse_timestamp_str.cache_clear()

    def test_iso_and_epoch_still_parse(self) -> None:
        self.assertEqual(parse_timestamp("2026-04-14T13:20:00.7654321Z"),
                         _utc(2026, 4, 14, 13, 20, 0, 765432))
        self.assertEqual(parse_timestamp("2026-07-08 11:58:00"),
                         _utc(2026, 7, 8, 11, 58, 0))
        # epoch seconds and micros
        self.assertEqual(parse_timestamp(1752300000), _utc(2025, 7, 12, 6, 0, 0))
        self.assertEqual(parse_timestamp("1752300000123456"),
                         _utc(2025, 7, 12, 6, 0, 0, 123456))

    def test_clf_web_log_format_still_parses(self) -> None:
        ts = parse_timestamp("10/Oct/2000:13:55:36 -0700")
        self.assertEqual(ts, datetime(2000, 10, 10, 13, 55, 36,
                                      tzinfo=timezone(timedelta(hours=-7))))


if __name__ == "__main__":
    unittest.main()
