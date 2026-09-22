from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from threading import Lock
from unittest.mock import patch

from app.memory import memprocfs_runner
from app.memory.memprocfs_runner import MemProcFSRunner


class FakeMemory:
    def read(self, _address: int, _size: int) -> bytes:
        return b"MZ" + b"\x00" * 62


class FakeMaps:
    def vad(self, _identify_modules: bool = True):
        return [{
            "start": 0x1000,
            "end": 0x1fff,
            "protection": "PAGE_EXECUTE_READWRITE",
            "private": True,
            "commit_charge": 1,
            "tag": "VadS",
        }]

    def thread(self):
        return [{"tid": 7, "pid": 123, "va-win32start": 0x1010, "time-create-str": "2024-01-01 00:00:00 UTC"}]

    def handle(self):
        return [{"handle": 4, "type": "File", "name": r"C:\temp\a.txt"}]


class FakeProcess:
    pid = 123
    ppid = 4
    name = "evil.exe"
    fullname = "evil.exe"
    pathuser = r"C:\Temp\evil.exe"
    pathkernel = r"\Device\HarddiskVolume1\Temp\evil.exe"
    cmdline = r"C:\Temp\evil.exe -x"

    def __init__(self):
        self.maps = FakeMaps()
        self.memory = FakeMemory()

    def module_list(self):
        return [types.SimpleNamespace(name="evil.exe", fullname=r"C:\Temp\evil.exe", base=0x400000, image_size=4096)]


class RaisingPathProcess(FakeProcess):
    @property
    def pathuser(self):
        raise RuntimeError("Process.pathuser(): Failed.")


class RaisingMaps:
    def vad(self, _identify_modules: bool = True):
        raise AssertionError("pseudo-process VADs should be skipped")

    def thread(self):
        raise AssertionError("pseudo-process threads should be skipped")

    def handle(self):
        raise AssertionError("pseudo-process handles should be skipped")


class SystemProcess:
    pid = 4
    ppid = 0
    name = "System"
    fullname = "System"
    pathuser = ""
    pathkernel = ""
    cmdline = ""

    def __init__(self):
        self.maps = RaisingMaps()
        self.memory = FakeMemory()

    def module_list(self):
        raise AssertionError("pseudo-process modules should be skipped")


class FakeVmm:
    closed = False
    args = None

    def __init__(self, args):
        FakeVmm.closed = False
        FakeVmm.args = args
        self.maps = types.SimpleNamespace(
            net=lambda: [{"pid": 123, "src-ip": "10.0.0.5", "src-port": 4444, "dst-ip": "8.8.8.8", "dst-port": 443, "state": "ESTABLISHED"}],
            service=lambda: {1: {"name": "badsvc", "path-image": r"C:\Users\Public\bad.exe", "dwCurrentState": 4, "pid": 123}},
            kdriver=lambda: [{"name": "ntoskrnl.exe", "path": r"\SystemRoot\system32\ntoskrnl.exe", "va": 0x100000}],
        )

    def process_list(self):
        return [FakeProcess()]

    def close(self):
        FakeVmm.closed = True


class FakeVfs:
    files = {
        "/forensic/progress_percent.txt": b"100",
        "/forensic/csv/timeline_all.csv": b"Time,Type,Name\n2024-01-01 00:00:00,Process,evil.exe\n",
        "/forensic/csv/findevil.csv": b"PID,Process,Reason\n123,evil.exe,injected\n",
        "/misc/eventlog/Security.evtx": b"EVTX",
    }

    def list(self, path):
        if path == "/forensic/csv":
            return {
                "timeline_all.csv": {"size": len(self.files["/forensic/csv/timeline_all.csv"])},
                "findevil.csv": {"size": len(self.files["/forensic/csv/findevil.csv"])},
            }
        if path == "/misc/eventlog":
            return {"Security.evtx": {"size": len(self.files["/misc/eventlog/Security.evtx"])}}
        return {}

    def read(self, path, length, offset):
        data = self.files[path]
        return data[offset:offset + length]

    def write(self, path, data, offset=0):
        self.files[path] = bytes(data)
        return len(data)


class FakeForensicVmm(FakeVmm):
    def __init__(self, args):
        super().__init__(args)
        self.vfs = FakeVfs()


class MemProcFSRunnerTests(unittest.TestCase):
    def test_collect_normalizes_memprocfs_maps(self) -> None:
        fake_module = types.SimpleNamespace(Vmm=FakeVmm)
        with patch.dict(sys.modules, {"memprocfs": fake_module}):
            with MemProcFSRunner(Path("sample.raw")) as runner:
                results = runner.collect()

        self.assertTrue(FakeVmm.closed)
        self.assertEqual(FakeVmm.args, ["-device", "sample.raw", "-forensic", "1"])
        self.assertEqual(results["pslist"][0]["PID"], 123)
        self.assertEqual(results["cmdline"][0]["Args"], r"C:\Temp\evil.exe -x")
        self.assertEqual(results["dlllist"][0]["Path"], r"C:\Temp\evil.exe")
        self.assertEqual(results["threads"][0]["StartAddress"], 0x1010)
        self.assertEqual(results["handles"], [])
        self.assertEqual(results["netscan"][0]["ForeignAddr"], "8.8.8.8")
        self.assertEqual(results["svcscan"][0]["Name"], "badsvc")
        self.assertEqual(results["modules"][0]["Name"], "ntoskrnl.exe")
        self.assertEqual(results["malfind"][0]["Hexdump"][:5], "4d 5a")
        self.assertNotIn("psscan", runner.unsupported_capabilities())

    def test_process_property_failures_fall_back_to_defaults(self) -> None:
        class PathRaisingVmm(FakeVmm):
            def process_list(self):
                return [RaisingPathProcess()]

        fake_module = types.SimpleNamespace(Vmm=PathRaisingVmm)
        with patch.dict(sys.modules, {"memprocfs": fake_module}):
            with MemProcFSRunner(Path("sample.raw")) as runner:
                results = runner.collect()

        self.assertEqual(results["pslist"][0]["Path"], r"\Device\HarddiskVolume1\Temp\evil.exe")

    def test_kernel_pseudo_processes_skip_deep_maps(self) -> None:
        class SystemFirstVmm(FakeVmm):
            def process_list(self):
                return [SystemProcess(), FakeProcess()]

        progress_messages: list[str] = []
        fake_module = types.SimpleNamespace(Vmm=SystemFirstVmm)
        with patch.dict(sys.modules, {"memprocfs": fake_module}):
            with MemProcFSRunner(Path("sample.raw")) as runner:
                results = runner.collect(progress_messages.append)

        self.assertEqual([row["PID"] for row in results["pslist"]], [4, 123])
        self.assertEqual(len(results["dlllist"]), 1)
        self.assertTrue(any("inventory only" in msg for msg in progress_messages))

    def test_vmm_closes_when_collection_raises(self) -> None:
        class RaisingVmm(FakeVmm):
            def process_list(self):
                raise RuntimeError("boom")

        fake_module = types.SimpleNamespace(Vmm=RaisingVmm)
        with patch.dict(sys.modules, {"memprocfs": fake_module}):
            with self.assertRaises(RuntimeError):
                with MemProcFSRunner(Path("sample.raw")) as runner:
                    runner._vmm.process_list()

        self.assertTrue(FakeVmm.closed)

    def test_extract_forensic_artifacts_copies_vfs_outputs_and_manifest(self) -> None:
        fake_module = types.SimpleNamespace(Vmm=FakeForensicVmm)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "derived"
            with patch.dict(sys.modules, {"memprocfs": fake_module}):
                with MemProcFSRunner(Path("sample.raw")) as runner:
                    manifest = runner.extract_forensic_artifacts(out)

            self.assertTrue(FakeVmm.closed)
            self.assertTrue((out / "forensic" / "csv" / "timeline_all.csv").is_file())
            self.assertTrue((out / "forensic" / "csv" / "findevil.csv").is_file())
            self.assertTrue((out / "eventlog" / "Security.evtx").is_file())
            self.assertEqual(len(manifest["artifacts"]), 3)
            manifest_on_disk = (out / "manifest.json").read_text(encoding="utf-8")
            self.assertIn("/forensic/csv/timeline_all.csv", manifest_on_disk)

    def test_extract_forensic_artifacts_respects_disabled_options(self) -> None:
        fake_module = types.SimpleNamespace(Vmm=FakeForensicVmm)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "derived"
            with patch.dict(sys.modules, {"memprocfs": fake_module}):
                with MemProcFSRunner(Path("sample.raw")) as runner:
                    manifest = runner.extract_forensic_artifacts(
                        out,
                        include_csv=False,
                        include_eventlogs=False,
                    )

            self.assertEqual(manifest["artifacts"], [])
            self.assertFalse((out / "forensic" / "csv" / "timeline_all.csv").exists())
            self.assertFalse((out / "eventlog" / "Security.evtx").exists())
            self.assertIn("disabled", (out / "manifest.json").read_text(encoding="utf-8"))

    def test_vfs_pid_entries_feed_psscan_candidates(self) -> None:
        class PidVfs:
            def list(self, path):
                if path == "/pid":
                    return {"123": {"size": 0}, "456": {"size": 0}}
                return {}

            def read(self, path, length, offset):
                files = {
                    "/pid/456/name.txt": b"hidden.exe\n",
                    "/pid/456/cmdline.txt": b"C:\\Temp\\hidden.exe -x\n",
                    "/pid/456/ppid.txt": b"4\n",
                }
                return files[path][offset:offset + length]

        class PidVmm(FakeVmm):
            def __init__(self, args):
                super().__init__(args)
                self.vfs = PidVfs()

        fake_module = types.SimpleNamespace(Vmm=PidVmm)
        with patch.dict(sys.modules, {"memprocfs": fake_module}):
            with MemProcFSRunner(Path("sample.raw")) as runner:
                results = runner.collect()

        self.assertEqual(results["psscan"][0]["PID"], 456)
        self.assertEqual(results["psscan"][0]["ImageFileName"], "hidden.exe")


class MemProcFSFailureTests(unittest.TestCase):
    def test_constructor_failure_releases_lock_and_next_session_opens(self):
        lock = Lock()
        runner = MemProcFSRunner(Path("synthetic.raw"))
        for error in (RuntimeError("invalid synthetic dump"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                with (
                    patch.object(memprocfs_runner, "_VMM_LOCK", lock),
                    patch.dict(sys.modules, {"memprocfs": types.SimpleNamespace(Vmm=lambda *_args: None)}),
                    patch.object(sys.modules["memprocfs"], "Vmm", side_effect=error),
                ):
                    with self.assertRaises(type(error)):
                        with runner:
                            self.fail("failed initialization must not enter the body")
                self.assertFalse(runner._lock_acquired)
                self.assertTrue(lock.acquire(blocking=False))
                lock.release()
        with (
            patch.object(memprocfs_runner, "_VMM_LOCK", lock),
            patch.dict(sys.modules, {"memprocfs": types.SimpleNamespace(Vmm=FakeVmm)}),
        ):
            with MemProcFSRunner(Path("synthetic.raw")):
                self.assertTrue(lock.locked())
        self.assertFalse(lock.locked())

    def test_known_size_incomplete_copy_fails_and_removes_partial_file(self):
        runner = MemProcFSRunner(Path("synthetic.raw"))
        runner._vmm = types.SimpleNamespace(vfs=types.SimpleNamespace(
            read=lambda _path, length, offset: b"abc"[offset:offset + length],
        ))
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "artifact.csv"
            result = runner._copy_vfs_file("/synthetic.csv", target, {"size": 5})
            self.assertEqual(result["status"], "failed")
            self.assertIn("Incomplete VFS read", result["error"])
            self.assertIsNone(result["sha256"])
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
