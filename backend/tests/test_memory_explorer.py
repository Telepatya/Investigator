from __future__ import annotations

# ruff: noqa: E402

import json
import sys
import tempfile
import types
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from importlib.util import find_spec
from pathlib import Path
from unittest.mock import patch


class _BaseModel:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    @classmethod
    def model_validate(cls, data):
        return cls(**data)

    def model_dump_json(self, indent=None):
        return "{}"


if "keyring" not in sys.modules and find_spec("keyring") is None:
    sys.modules.setdefault("keyring", types.SimpleNamespace(
        get_password=lambda *_args, **_kwargs: None,
        set_password=lambda *_args, **_kwargs: None,
        delete_password=lambda *_args, **_kwargs: None,
        errors=types.SimpleNamespace(PasswordDeleteError=Exception),
    ))
if "pydantic" not in sys.modules and find_spec("pydantic") is None:
    sys.modules.setdefault("pydantic", types.SimpleNamespace(
        BaseModel=_BaseModel,
        Field=lambda default=None, default_factory=None, **_kwargs: default_factory() if default_factory else default,
    ))

import app.config as config
from app.detect.entity_graph import entity_dossier
from app.memory import explorer, forensics
from app.store import cases, database
from app.store.database import Event, MemoryResult, Process


class _FakeMemory:
    def __init__(self, blobs: dict[int, bytes]):
        self.blobs = blobs

    def read(self, address: int, length: int):
        for base, data in self.blobs.items():
            if base <= address < base + len(data):
                offset = address - base
                return data[offset:offset + length]
        return b""


class _FakeModule:
    def __init__(self, name: str, base: int, data: bytes):
        self.name = name
        self.fullname = rf"C:\Temp\{name}"
        self.base = base
        self.image_size = len(data)
        self.file_size = len(data)


class _FakeMaps:
    def vad(self, _include_extra=True):
        return [{
            "start": 0x2000,
            "size": 4,
            "file": r"C:\Temp\dynamic.dll",
            "protection": "PAGE_EXECUTE_READ",
            "private": False,
        }]

    def handle(self):
        return [{
            "handle": 8,
            "type": "File",
            "name": r"C:\Temp\from-memory.txt",
            "access": "0x120089",
        }]


class _FakeProcess:
    pid = 123
    ppid = 4
    name = "evil.exe"
    fullname = "evil.exe"
    pathuser = r"C:\Temp\evil.exe"
    pathkernel = r"\Device\HarddiskVolume1\Temp\evil.exe"
    cmdline = r"C:\Temp\evil.exe -arg"
    username = "user"
    sid = "S-1-5-21"
    session = 1
    integrity = 2
    time_create = "2026-01-01 00:00:00 UTC"

    def __init__(self):
        self._main = b"MZMAIN"
        self.memory = _FakeMemory({0x1000: self._main, 0x2000: b"DLL!"})
        self.maps = _FakeMaps()

    def module_list(self):
        return [_FakeModule("evil.exe", 0x1000, self._main)]


class _FakeVfs:
    def __init__(self):
        self.files = {
            "/sys/version.txt": b"build",
            "/one/report.txt": b"first",
            "/two/report.txt": b"second",
            "/pid/123/minidump/minidump.dmp": b"MDMPFULLPROCESS",
        }

    def list(self, path: str):
        if path == "/":
            return {
                "sys": {"name": "sys", "f_isdir": True, "size": 0},
                "pid": {"name": "pid", "f_isdir": True, "size": 0},
            }
        if path == "/pid/123":
            return {
                "minidump": {"name": "minidump", "f_isdir": True, "size": 0},
            }
        if path == "/pid/123/minidump":
            return {
                "minidump.dmp": {
                    "name": "minidump.dmp", "f_isdir": False,
                    "size": len(self.files["/pid/123/minidump/minidump.dmp"]),
                },
            }
        if path == "/sys":
            return {"version.txt": {"name": "version.txt", "f_isdir": False, "size": 5}}
        if path in {"/one", "/two"}:
            source = f"{path}/report.txt"
            return {
                "report.txt": {
                    "name": "report.txt",
                    "f_isdir": False,
                    "size": len(self.files[source]),
                }
            }
        return {}

    def read(self, path: str, length: int, offset: int = 0):
        return self.files[path][offset:offset + length]


class _FakeVmm:
    last = None

    def __init__(self, args):
        self.args = args
        self.closed = False
        self.vfs = _FakeVfs()
        _FakeVmm.last = self

    def close(self):
        self.closed = True

    def process(self, pid: int):
        if pid != 123:
            raise RuntimeError("missing process")
        return _FakeProcess()


class MemoryExplorerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.uploads = self.root / "deadbeef" / "uploads"
        self.uploads.mkdir(parents=True)
        (self.uploads / "dump.raw").write_bytes(b"raw")
        self.patches = [
            patch.object(explorer, "case_uploads_path", return_value=self.uploads),
            patch.object(explorer, "get_cases_dir", return_value=self.root),
            patch.object(config, "get_cases_dir", return_value=self.root),
            patch.object(cases, "get_cases_dir", return_value=self.root),
            patch.object(cases, "case_db_path", side_effect=lambda case_id: self.root / case_id / "case.db"),
            patch.dict(sys.modules, {"memprocfs": types.SimpleNamespace(Vmm=_FakeVmm)}),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self) -> None:
        database.dispose_all_db_engines()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_entity_dossier_includes_memory_process_candidates(self) -> None:
        case = cases.create_case("memory entity")
        session = cases.get_session(case["id"])
        try:
            session.add(Process(
                pid=123,
                ppid=4,
                name="evil.exe",
                path=r"C:\Temp\evil.exe",
                cmdline=r"C:\Temp\evil.exe -arg",
                session_id="mem-dump",
                flags=["injected"],
                severity="high",
                extra={"user": "user"},
            ))
            session.commit()
        finally:
            session.close()

        dossier = entity_dossier(case["id"], "process::evil.exe")

        self.assertEqual(dossier["memory_processes"][0]["pid"], 123)
        self.assertEqual(dossier["memory_processes"][0]["session_id"], "mem-dump")

    def test_entity_dossier_defers_process_handles_until_requested(self) -> None:
        case = cases.create_case("memory handles")
        session = cases.get_session(case["id"])
        try:
            session.add(Process(
                pid=123,
                ppid=4,
                name="evil.exe",
                path=r"C:\Temp\evil.exe",
                cmdline=None,
                session_id="mem-dump",
                flags=["cross-process"],
                severity="high",
                extra={},
            ))
            session.add(Event(
                timestamp=None,
                host=None,
                source="memory:handles",
                category="handle",
                entity="evil.exe",
                severity="high",
                summary="evil.exe handle Process -> lsass.exe",
                raw={
                    "session_id": "mem-dump",
                    "PID": 123,
                    "Process": "evil.exe",
                    "Type": "Process",
                    "Name": "lsass.exe",
                    "TargetPID": 500,
                    "TargetProcess": "lsass.exe",
                    "Access": "0x143a",
                    "risk": "critical",
                    "risk_reasons": ["target appears sensitive"],
                },
            ))
            session.commit()
        finally:
            session.close()

        dossier = entity_dossier(case["id"], "process::evil.exe")
        proc = dossier["memory_processes"][0]
        handles = explorer.list_process_handles(case["id"], "mem-dump", 123)

        self.assertEqual(proc["handle_counts"], {})
        self.assertEqual(proc["handles"], [])
        self.assertEqual(proc["cross_process_activity"], [])
        self.assertTrue(proc["handles_on_demand"])
        self.assertEqual(handles["total"], 1)
        self.assertEqual(handles["handles"][0]["target_process"], "lsass.exe")

    def test_all_handle_types_are_on_demand_not_in_default_dossier(self) -> None:
        case = cases.create_case("memory file handles")
        session = cases.get_session(case["id"])
        try:
            session.add(Process(
                pid=123,
                ppid=4,
                name="evil.exe",
                path=r"C:\Temp\evil.exe",
                cmdline=None,
                session_id="mem-dump",
                flags=[],
                severity="info",
                extra={},
            ))
            session.add_all([
                Event(
                    timestamp=None,
                    host=None,
                    source="memory:handles",
                    category="handle",
                    entity="evil.exe",
                    severity="info",
                    summary="evil.exe handle File -> C:\\Temp\\a.txt",
                    raw={
                        "session_id": "mem-dump",
                        "PID": 123,
                        "Process": "evil.exe",
                        "Type": "File",
                        "Name": r"C:\Temp\a.txt",
                        "risk": "none",
                        "risk_reasons": [],
                    },
                ),
                Event(
                    timestamp=None,
                    host=None,
                    source="memory:handles",
                    category="handle",
                    entity="evil.exe",
                    severity="low",
                    summary="evil.exe handle Key -> Run",
                    raw={
                        "session_id": "mem-dump",
                        "PID": 123,
                        "Process": "evil.exe",
                        "Type": "Key",
                        "Name": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        "risk": "low",
                        "risk_reasons": ["registry path"],
                    },
                ),
            ])
            session.commit()
        finally:
            session.close()

        dossier = entity_dossier(case["id"], "process::evil.exe")
        proc = dossier["memory_processes"][0]
        all_handles = explorer.list_process_handles(case["id"], "mem-dump", 123)
        files = explorer.list_process_handles(case["id"], "mem-dump", 123, handle_type="File")

        self.assertEqual(proc["handle_counts"], {})
        self.assertEqual(proc["handles"], [])
        self.assertEqual(all_handles["total"], 2)
        self.assertEqual({h["type"] for h in all_handles["handles"]}, {"File", "Key"})
        self.assertEqual(files["total"], 1)
        self.assertEqual(files["handles"][0]["name"], r"C:\Temp\a.txt")

    def test_on_demand_handles_collect_from_dump_and_cache(self) -> None:
        case = cases.create_case("memory live handles")
        session = cases.get_session(case["id"])
        try:
            session.add(Process(
                pid=123,
                ppid=4,
                name="evil.exe",
                path=r"C:\Temp\evil.exe",
                cmdline=None,
                session_id="mem-dump",
                flags=[],
                severity="info",
                extra={},
            ))
            session.commit()
        finally:
            session.close()

        result = explorer.list_process_handles(case["id"], "mem-dump", 123)
        session = cases.get_session(case["id"])
        try:
            cached = session.query(Event).filter(Event.category == "handle").all()
        finally:
            session.close()

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["handles"][0]["name"], r"C:\Temp\from-memory.txt")
        self.assertEqual(len(cached), 1)
        self.assertTrue((cached[0].raw or {}).get("on_demand"))

    def test_entity_dossier_keeps_pid_memory_results_with_their_dump(self) -> None:
        case = cases.create_case("two dumps")
        session = cases.get_session(case["id"])
        try:
            session.add_all([
                Process(
                    pid=123,
                    ppid=4,
                    name="evil.exe",
                    path=r"C:\Temp\evil.exe",
                    cmdline=None,
                    session_id="mem-dump",
                    flags=[],
                    severity="info",
                    extra={},
                ),
                Process(
                    pid=123,
                    ppid=4,
                    name="evil.exe",
                    path=r"C:\Temp\evil.exe",
                    cmdline=None,
                    session_id="mem-other",
                    flags=[],
                    severity="info",
                    extra={},
                ),
                MemoryResult(
                    plugin="memprocfs_findevil",
                    pid=123,
                    process_name="evil.exe",
                    summary="dump hit",
                    data={"source": "mem-dump:forensic/csv/findevil.csv"},
                    severity="high",
                ),
                MemoryResult(
                    plugin="memprocfs_findevil",
                    pid=123,
                    process_name="evil.exe",
                    summary="other hit",
                    data={"source": "mem-other:forensic/csv/findevil.csv"},
                    severity="high",
                ),
            ])
            session.commit()
        finally:
            session.close()

        dossier = entity_dossier(case["id"], "process::evil.exe")
        by_session = {p["session_id"]: p for p in dossier["memory_processes"]}

        self.assertEqual([m["summary"] for m in by_session["mem-dump"]["memory_results"]], ["dump hit"])
        self.assertEqual([m["summary"] for m in by_session["mem-other"]["memory_results"]], ["other hit"])

    def test_process_image_extraction_caches_extracted_file_and_closes_vmm(self) -> None:
        output = explorer.extract_process_image("deadbeef", "mem-dump", 123)

        self.assertTrue(output.name.endswith(".extracted"))
        self.assertEqual(output.read_bytes(), b"MZMAIN")
        self.assertTrue(_FakeVmm.last.closed)
        manifest_path = (
            self.root / "deadbeef" / "derived" / "memprocfs" / "dump"
            / "extracted" / "manifest.json"
        )
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest["artifacts"][0]["sha256"], explorer._hash_file(output))

    def test_sparse_vmem_process_download_is_not_supported(self) -> None:
        with self.assertRaises(explorer.MemoryExplorerError) as cm:
            explorer.extract_process_image("deadbeef", "mem-dump", 123, kind="vmem")

        self.assertEqual(cm.exception.status_code, 400)
        self.assertIn("Unsupported process download kind", str(cm.exception))

    def test_full_process_minidump_uses_memprocfs_minidump_artifact(self) -> None:
        output = explorer.extract_process_image(
            "deadbeef", "mem-dump", 123, kind="minidump"
        )

        self.assertEqual(output.name, "evil.exe_123.minidump.dmp")
        self.assertEqual(output.read_bytes(), b"MDMPFULLPROCESS")
        manifest_path = (
            self.root / "deadbeef" / "derived" / "memprocfs" / "dump"
            / "extracted" / "manifest.json"
        )
        artifact = json.loads(manifest_path.read_text())["artifacts"][0]
        self.assertEqual(artifact["kind"], "process_minidump")
        self.assertEqual(artifact["source"], "/pid/123/minidump/minidump.dmp")
        self.assertEqual(artifact["pid"], 123)

    def test_vfs_listing_and_download_reject_unsafe_paths(self) -> None:
        listing = explorer.list_vfs("deadbeef", "mem-dump", "/")
        self.assertEqual({e["name"] for e in listing["entries"]}, {"pid", "sys"})

        output = explorer.extract_vfs_file("deadbeef", "mem-dump", "/sys/version.txt")
        self.assertEqual(output.read_bytes(), b"build")
        with self.assertRaises(explorer.MemoryExplorerError):
            explorer.list_vfs("deadbeef", "mem-dump", "/sys/../secret")
        with self.assertRaises(explorer.MemoryExplorerError) as cm:
            explorer.extract_vfs_file("deadbeef", "mem-dump", "/sys/missing.txt")
        self.assertEqual(cm.exception.status_code, 404)

    def test_vfs_downloads_with_same_basename_have_source_specific_cache_paths(self) -> None:
        first = explorer.extract_vfs_file(
            "deadbeef", "mem-dump", "/one/report.txt"
        )
        second = explorer.extract_vfs_file(
            "deadbeef", "mem-dump", "/two/report.txt"
        )

        self.assertNotEqual(first, second)
        self.assertEqual(first.read_bytes(), b"first")
        self.assertEqual(second.read_bytes(), b"second")
        self.assertIn(explorer._source_key("/one/report.txt"), first.name)
        self.assertIn(explorer._source_key("/two/report.txt"), second.name)

    def test_extensionless_physicalmemory_upload_resolves_as_dump(self) -> None:
        (self.uploads / "PhysicalMemory").write_bytes(b"raw")

        dump = explorer.resolve_memory_dump("deadbeef", "mem-PhysicalMemory")
        dumps = explorer.list_memory_dumps("deadbeef")

        self.assertEqual(dump.filename, "PhysicalMemory")
        row = next(row for row in dumps if row["filename"] == "PhysicalMemory")
        self.assertEqual(explorer.resolve_memory_dump("deadbeef", row["session_id"]).filename, "PhysicalMemory")

    def test_dd_memory_upload_resolves_as_dump(self) -> None:
        (self.uploads / "memory.dd").write_bytes(b"raw")

        dump = explorer.resolve_memory_dump("deadbeef", "mem-memory")
        dumps = explorer.list_memory_dumps("deadbeef")

        self.assertEqual(dump.filename, "memory.dd")
        row = next(row for row in dumps if row["filename"] == "memory.dd")
        self.assertEqual(explorer.resolve_memory_dump("deadbeef", row["session_id"]).filename, "memory.dd")

    def test_vfs_folder_archive_includes_manifest_and_file(self) -> None:
        archive = explorer.archive_vfs_selection("deadbeef", "mem-dump", ["/sys"])

        with zipfile.ZipFile(archive) as zf:
            self.assertEqual(zf.read("sys/version.txt"), b"build")
            manifest = json.loads(zf.read("manifest.json"))
        self.assertEqual(manifest[0]["source"], "/sys/version.txt")
        self.assertEqual(manifest[0]["status"], "ok")

    def test_same_second_archive_requests_publish_distinct_complete_files(self) -> None:
        with (
            patch.object(explorer.time, "time", return_value=1_700_000_000),
            patch.object(
                explorer.secrets,
                "token_hex",
                side_effect=["a" * 32, "b" * 32],
            ),
        ):
            first = explorer.archive_vfs_selection(
                "deadbeef", "mem-dump", ["/sys"]
            )
            second = explorer.archive_vfs_selection(
                "deadbeef", "mem-dump", ["/sys"]
            )

        self.assertNotEqual(first, second)
        self.assertTrue(first.is_file())
        self.assertTrue(second.is_file())
        for archive in (first, second):
            with zipfile.ZipFile(archive) as zf:
                self.assertEqual(zf.read("sys/version.txt"), b"build")
        self.assertEqual(list(first.parent.glob(".*.partial-*.zip")), [])

    def test_archive_failure_does_not_publish_partial_zip(self) -> None:
        with patch.object(
            zipfile.ZipFile,
            "writestr",
            side_effect=OSError("simulated archive failure"),
        ):
            with self.assertRaisesRegex(
                explorer.MemoryExplorerError, "Could not create VFS archive"
            ):
                explorer.archive_vfs_selection("deadbeef", "mem-dump", ["/sys"])

        output_dir = (
            self.root / "deadbeef" / "derived" / "memprocfs" / "dump"
            / "extracted" / "vfs"
        )
        self.assertEqual(list(output_dir.glob("*.zip")), [])
        self.assertEqual(list(output_dir.glob(".*.partial-*.zip")), [])

    def test_manifest_rejects_extracted_directory_symlink_escape(self) -> None:
        artifact_root = self.root / "deadbeef" / "derived" / "memprocfs" / "dump"
        artifact_root.mkdir(parents=True)
        outside = self.root / "outside"
        outside.mkdir()
        try:
            (artifact_root / "extracted").symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"Symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(explorer.MemoryExplorerError, "Unsafe extraction path"):
            explorer._record_manifest("deadbeef", "dump", {"kind": "test"})
        self.assertEqual(list(outside.iterdir()), [])

    def test_manifest_rejects_alias_to_another_case_dump(self) -> None:
        artifact_root = self.root / "deadbeef" / "derived" / "memprocfs"
        artifact_root.mkdir(parents=True)
        target = artifact_root / "target"
        target.mkdir()
        alias = artifact_root / "dump"
        try:
            alias.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"Symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(ValueError, "Invalid MemProcFS artifact path"):
            forensics.remove_memprocfs_artifacts("deadbeef", "dump")
        self.assertTrue(target.is_dir())

    def test_remove_memprocfs_artifacts_rejects_derived_alias(self) -> None:
        target = self.root / "aaaaaaaa" / "derived"
        target.mkdir(parents=True)
        alias = self.root / "deadbeef" / "derived"
        try:
            alias.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"Symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(ValueError, "Invalid MemProcFS derived directory"):
            forensics.remove_memprocfs_artifacts("deadbeef", "dump")
        self.assertTrue(target.is_dir())

    def test_remove_memprocfs_artifacts_rejects_memprocfs_alias(self) -> None:
        derived = self.root / "deadbeef" / "derived"
        derived.mkdir(parents=True)
        target = self.root / "aaaaaaaa" / "memprocfs"
        target.mkdir(parents=True)
        alias = derived / "memprocfs"
        try:
            alias.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"Symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(ValueError, "Invalid MemProcFS artifact root"):
            forensics.remove_memprocfs_artifacts("deadbeef", "dump")
        self.assertTrue(target.is_dir())

    def test_manifest_rejects_manifest_file_symlink_escape(self) -> None:
        artifact_root = self.root / "deadbeef" / "derived" / "memprocfs" / "dump"
        extracted = artifact_root / "extracted"
        extracted.mkdir(parents=True)
        outside = self.root / "outside-manifest.json"
        outside.write_text('{"artifacts": []}', encoding="utf-8")
        try:
            (extracted / "manifest.json").symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"Symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(explorer.MemoryExplorerError, "Unsafe extraction"):
            explorer._record_manifest("deadbeef", "dump", {"kind": "test"})
        self.assertEqual(json.loads(outside.read_text(encoding="utf-8")), {"artifacts": []})

    def test_manifest_updates_are_atomic_and_keep_concurrent_entries(self) -> None:
        extracted_dir = (
            self.root / "deadbeef" / "derived" / "memprocfs" / "dump" / "extracted"
        )
        extracted_dir.mkdir(parents=True)

        def record(index: int) -> None:
            explorer._record_manifest(
                "deadbeef", "dump", {"kind": "test", "index": index}
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(record, range(40)))

        manifest_path = (
            self.root / "deadbeef" / "derived" / "memprocfs" / "dump"
            / "extracted" / "manifest.json"
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual({row["index"] for row in manifest["artifacts"]}, set(range(40)))
        self.assertEqual(list(manifest_path.parent.glob(".manifest.json.partial-*")), [])

    def test_manifest_publication_failure_preserves_previous_manifest(self) -> None:
        explorer._record_manifest("deadbeef", "dump", {"kind": "first"})
        manifest_path = (
            self.root / "deadbeef" / "derived" / "memprocfs" / "dump"
            / "extracted" / "manifest.json"
        )
        original = manifest_path.read_bytes()
        with patch.object(explorer.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                explorer._record_manifest("deadbeef", "dump", {"kind": "second"})

        self.assertEqual(manifest_path.read_bytes(), original)
        self.assertEqual(list(manifest_path.parent.glob(".manifest.json.partial-*")), [])

    def test_manifest_parse_failure_preserves_corrupt_forensic_record(self) -> None:
        manifest_path = (
            self.root / "deadbeef" / "derived" / "memprocfs" / "dump"
            / "extracted" / "manifest.json"
        )
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text("{truncated", encoding="utf-8")
        original = manifest_path.read_bytes()

        with self.assertRaisesRegex(explorer.MemoryExplorerError, "manifest is invalid"):
            explorer._record_manifest("deadbeef", "dump", {"kind": "new"})

        self.assertEqual(manifest_path.read_bytes(), original)
        self.assertEqual(list(manifest_path.parent.glob(".manifest.json.partial-*")), [])


class MemoryExtractionCompletenessTests(unittest.TestCase):
    def test_incomplete_module_range_has_no_complete_image_hash(self):
        process = types.SimpleNamespace(memory=_FakeMemory({0x1000: b"MZ"}))
        self.assertIsNone(explorer._hash_process_range(process, 0x1000, 8))
        self.assertIsNotNone(explorer._hash_process_range(process, 0x1000, 2))

    def test_short_process_range_preserves_previous_complete_output(self):
        process = types.SimpleNamespace(memory=_FakeMemory({0x1000: b"MZ"}))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "image.extracted"
            output.write_bytes(b"previous")
            with self.assertRaisesRegex(explorer.MemoryExplorerError, "Incomplete memory read"):
                explorer._copy_process_range(
                    process, 0x1000, 8, output, {}, allowed_root=root
                )
            self.assertEqual(output.read_bytes(), b"previous")
            self.assertEqual(list(root.glob(".*.partial-*")), [])

    def test_known_size_short_vfs_file_preserves_previous_complete_output(self):
        vmm = types.SimpleNamespace(vfs=_FakeVfs())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "version.extracted"
            output.write_bytes(b"previous")
            with self.assertRaisesRegex(explorer.MemoryExplorerError, "Incomplete VFS read"):
                explorer._copy_vfs_file(
                    vmm,
                    "/sys/version.txt",
                    output,
                    {"size": 10},
                    allowed_root=root,
                )
            self.assertEqual(output.read_bytes(), b"previous")
            self.assertEqual(list(root.glob(".*.partial-*")), [])

    def test_unknown_size_vfs_file_still_completes_at_eof(self):
        vmm = types.SimpleNamespace(vfs=_FakeVfs())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "version.extracted"
            result = explorer._copy_vfs_file(
                vmm, "/sys/version.txt", output, None, allowed_root=root
            )
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["size"], 5)
            self.assertEqual(output.read_bytes(), b"build")

    def test_copy_helpers_reject_targets_outside_authorized_root(self):
        process = types.SimpleNamespace(memory=_FakeMemory({0x1000: b"MZ"}))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            allowed = base / "allowed"
            allowed.mkdir()
            outside = base / "outside.bin"
            outside.write_bytes(b"sentinel")
            with self.assertRaisesRegex(explorer.MemoryExplorerError, "Unsafe extraction path"):
                explorer._copy_process_range(
                    process, 0x1000, 2, outside, {}, allowed_root=allowed
                )
            self.assertEqual(outside.read_bytes(), b"sentinel")

    def test_short_archive_member_reports_failure(self):
        vmm = types.SimpleNamespace(vfs=_FakeVfs())
        with tempfile.TemporaryDirectory() as directory:
            with zipfile.ZipFile(Path(directory) / "selection.zip", "w") as archive:
                with self.assertRaisesRegex(ValueError, "Incomplete VFS read"):
                    explorer._write_vfs_to_zip(
                        vmm, archive, "/sys/version.txt", {"size": 10}, "sys/version.txt"
                    )


if __name__ == "__main__":
    unittest.main()
