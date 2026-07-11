from __future__ import annotations

# Regression tests for the upload path-traversal fix: client-supplied filenames
# must be reduced to a bare basename so an upload can never escape the case's
# uploads directory (e.g. "../../../etc/cron.d/x" or a Windows "..\\..\\x").

import sys
import types
import unittest

# Match the stubbing style used by the other API tests so this suite runs even
# when optional native deps aren't installed; real packages win when present.
sys.modules.setdefault("keyring", types.SimpleNamespace(
    get_password=lambda *_a, **_k: None,
    set_password=lambda *_a, **_k: None,
    delete_password=lambda *_a, **_k: None,
    errors=types.SimpleNamespace(PasswordDeleteError=Exception),
))

from app.ingest.evidence import sanitize_upload_filename  # noqa: E402


class UploadFilenameSafetyTests(unittest.TestCase):
    def test_plain_name_passes_through(self) -> None:
        self.assertEqual(sanitize_upload_filename("collection.zip"), "collection.zip")

    def test_posix_traversal_is_stripped_to_basename(self) -> None:
        self.assertEqual(sanitize_upload_filename("../../../etc/passwd"), "passwd")

    def test_windows_traversal_is_stripped_to_basename(self) -> None:
        # Backslashes are normalized to "/" first so this is neutralized on POSIX.
        self.assertEqual(
            sanitize_upload_filename("..\\..\\Windows\\system32\\evil.dll"), "evil.dll"
        )

    def test_absolute_path_is_stripped_to_basename(self) -> None:
        self.assertEqual(sanitize_upload_filename("/var/tmp/loot.json"), "loot.json")

    def test_trailing_separator_reduces_to_final_segment(self) -> None:
        self.assertEqual(sanitize_upload_filename("some/dir/report.csv"), "report.csv")

    def test_empty_and_dot_only_names_are_rejected(self) -> None:
        for bad in ("", None, "..", ".", "../", "..\\", "/"):
            self.assertIsNone(sanitize_upload_filename(bad))


if __name__ == "__main__":
    unittest.main()
