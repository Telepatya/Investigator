from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from reverse_sandbox.minidump_core import MiniDump, MiniDumpError


def synthetic_minidump(payload: bytes, *, declared_size: int | None = None) -> bytes:
    stream_count = 11
    directory_rva = 32
    system_rva = directory_rva + stream_count * 12
    system = struct.pack("<HHHBBIIII", 0, 6, 0, 2, 1, 10, 0, 19045, 2) + b"\0" * 32
    memory64_rva = system_rva + len(system)
    memory64_size = 32
    data_rva = memory64_rva + memory64_size
    memory64 = struct.pack("<QQQQ", 1, data_rva, 0x400000, declared_size or len(payload))
    directories = [struct.pack("<III", 7, len(system), system_rva),
                   struct.pack("<III", 9, len(memory64), memory64_rva)]
    directories.extend(struct.pack("<III", 100 + index, 0, 0) for index in range(9))
    header = b"MDMP" + struct.pack("<IIIIIQ", 0xA793, stream_count, directory_rva, 0, 0, 0)
    return header + b"".join(directories) + system + memory64 + payload


class ReverseMiniDumpToolTests(unittest.TestCase):
    def test_enumerates_eleven_streams_and_reads_virtual_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calc.dmp"
            path.write_bytes(synthetic_minidump(b"MZ\x90\x90payload"))
            dump = MiniDump(path)
        self.assertEqual(len(dump.streams), 11)
        self.assertEqual(dump.architecture["name"], "x86")
        content, missing = dump.read_virtual(0x400000, 4)
        self.assertEqual(content, b"MZ\x90\x90")
        self.assertEqual(missing, [])

    def test_missing_backing_bytes_are_reported_precisely(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "partial.dmp"
            path.write_bytes(synthetic_minidump(b"ABCD", declared_size=0x1000))
            dump = MiniDump(path)
        content, missing = dump.read_virtual(0x400000, 0x1000)
        self.assertEqual(content, b"")
        self.assertEqual(missing[0]["start"], 0x400000)
        self.assertEqual(missing[0]["end"], 0x401000)

    def test_rejects_non_minidump(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.exe"
            path.write_bytes(b"MZ" + b"\0" * 100)
            with self.assertRaisesRegex(MiniDumpError, "not a MiniDump"):
                MiniDump(path)


if __name__ == "__main__":
    unittest.main()
