from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from app.ingest import parsers


class ArchiveLimitTests(unittest.TestCase):
    def make_zip(self, root: Path, members: dict[str, bytes]) -> Path:
        archive = root / "evidence.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        return archive

    def test_member_count_and_total_expansion_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = self.make_zip(root, {"one.log": b"123456", "two.log": b"abcdef"})
            extract = root / "extract"
            extract.mkdir()
            with (
                patch.object(parsers, "MAX_ARCHIVE_MEMBERS", 2),
                patch.object(parsers, "MAX_ARCHIVE_MEMBER_BYTES", 100),
                patch.object(parsers, "MAX_ARCHIVE_TOTAL_BYTES", 10),
                patch.object(parsers, "COMPRESSION_RATIO_MIN_BYTES", 10_000),
            ):
                extracted = list(parsers.iter_zip_members(archive, extract))

            self.assertEqual([path.name for path, _source in extracted], ["one.log"])
            self.assertEqual((extract / "one.log").read_bytes(), b"123456")
            self.assertFalse((extract / "two.log").exists())

    def test_suspicious_real_compression_ratio_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = self.make_zip(root, {"bomb.log": b"A" * 10_000})
            extract = root / "extract"
            extract.mkdir()
            with (
                patch.object(parsers, "MAX_ARCHIVE_MEMBERS", 10),
                patch.object(parsers, "MAX_ARCHIVE_MEMBER_BYTES", 20_000),
                patch.object(parsers, "MAX_ARCHIVE_TOTAL_BYTES", 20_000),
                patch.object(parsers, "COMPRESSION_RATIO_MIN_BYTES", 100),
                patch.object(parsers, "COMPRESSION_RATIO_LIMIT", 2),
            ):
                extracted = list(parsers.iter_zip_members(archive, extract))

            self.assertEqual(extracted, [])
            self.assertFalse((extract / "bomb.log").exists())

    def test_parsable_member_count_stops_further_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = self.make_zip(root, {"one.log": b"1", "two.log": b"2"})
            extract = root / "extract"
            extract.mkdir()
            with (
                patch.object(parsers, "MAX_ARCHIVE_MEMBERS", 1),
                patch.object(parsers, "MAX_ARCHIVE_MEMBER_BYTES", 100),
                patch.object(parsers, "MAX_ARCHIVE_TOTAL_BYTES", 100),
            ):
                extracted = list(parsers.iter_zip_members(archive, extract))

            self.assertEqual(len(extracted), 1)
            self.assertEqual(len(list(extract.iterdir())), 1)


if __name__ == "__main__":
    unittest.main()
