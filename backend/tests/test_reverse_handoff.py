from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import app.config as config
from app.reverse.database import ReverseArtifact, ReverseProject, dispose_reverse_db, get_reverse_session
from app.reverse.handoff import ProcessHandoffError, handoff_process_to_reverse
from app.reverse.store import (
    contained_project_path,
    create_project,
    import_artifact,
    list_projects,
)
from app.store import cases
from app.store.database import Event, Finding, MemoryResult, Process, dispose_all_db_engines


class ReverseProcessHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old_config_dir = config.DEFAULT_CONFIG_DIR
        self.old_cases_dir = config.DEFAULT_CASES_DIR
        self.old_config_file = config.CONFIG_FILE
        self.old_cases_default = config.AppConfig.model_fields["cases_dir"].default
        config.DEFAULT_CONFIG_DIR = self.root
        config.DEFAULT_CASES_DIR = self.root / "cases"
        config.CONFIG_FILE = self.root / "config.json"
        config.AppConfig.model_fields["cases_dir"].default = str(config.DEFAULT_CASES_DIR)
        self.cfg = config.AppConfig(cases_dir=str(config.DEFAULT_CASES_DIR))
        self.config_patch = patch.object(config, "load_config", return_value=self.cfg)
        self.config_patch.start()
        dispose_reverse_db()
        self.case_id = cases.create_case("memory handoff")["id"]
        session = cases.get_session(self.case_id)
        try:
            session.add_all([
                Process(pid=4, ppid=0, name="System", session_id="mem-a", flags=[], severity="info"),
                Process(pid=2244, ppid=4, name="calc.exe", path=r"C:\Windows\SysWOW64\calc.exe",
                        cmdline="calc.exe", session_id="mem-a", flags=["hollowing-suspect"],
                        severity="high"),
                Process(pid=3000, ppid=2244, name="child.exe", session_id="mem-a", flags=[],
                        severity="medium"),
                Process(pid=2244, ppid=10, name="other.exe", session_id="mem-b", flags=[],
                        severity="info"),
            ])
            session.add_all([
                MemoryResult(plugin="dlllist", pid=2244, process_name="calc.exe",
                             summary="first module mismatch", severity="high",
                             data={"session_id": "mem-a", "module": "oleacc.dll"}),
                MemoryResult(plugin="dlllist", pid=2244, process_name="other.exe",
                             summary="wrong session", severity="critical",
                             data={"session_id": "mem-b"}),
                Event(source="memory:malfind", category="process", entity="calc.exe", severity="high",
                      summary="selected action", raw={"session_id": "mem-a", "PID": 2244}),
                Event(source="memory:process", category="process", entity="child.exe", severity="medium",
                      summary="one hop action", raw={"session_id": "mem-a", "PID": 3000}),
                Event(source="memory:process", category="process", entity="other.exe", severity="critical",
                      summary="unrelated action", raw={"session_id": "mem-b", "PID": 2244}),
                Finding(title="Possible hollowing", description="Detector hypothesis", severity="high",
                        mitre_techniques=["T1055.012"], evidence={"session_id": "mem-a", "pid": 2244},
                        source="memory"),
            ])
            session.commit()
        finally:
            session.close()
        self.dump = config.case_uploads_path(self.case_id) / "calc.exe_2244.minidump.dmp"
        self.dump.write_bytes(b"MDMP-process-bytes")
        self.modules = [{"name": "calc.exe", "base_hex": "0x400000", "size": 4096}]
        self.handles = [{"type": "Process", "target_pid": 3000, "target_process": "child.exe",
                         "access": "0x1fffff", "risk": "high", "event_id": 9}]

    def tearDown(self) -> None:
        dispose_reverse_db()
        dispose_all_db_engines()
        self.config_patch.stop()
        config.DEFAULT_CONFIG_DIR = self.old_config_dir
        config.DEFAULT_CASES_DIR = self.old_cases_dir
        config.CONFIG_FILE = self.old_config_file
        config.AppConfig.model_fields["cases_dir"].default = self.old_cases_default
        self.temp.cleanup()

    def _patch_sources(self):
        return (
            patch("app.reverse.handoff.extract_process_image", return_value=self.dump),
            patch("app.reverse.handoff.list_process_modules", return_value={"modules": self.modules}),
            patch("app.reverse.handoff.export_process_handles", return_value=self.handles),
            patch("app.reverse.handoff.resolve_memory_dump", return_value=SimpleNamespace(filename="memory.raw")),
        )

    def test_handoff_is_ready_exact_pid_scoped_and_does_not_start_analysis(self) -> None:
        patches = self._patch_sources()
        with patches[0] as extract, patches[1], patches[2], patches[3]:
            result = handoff_process_to_reverse(self.case_id, "mem-a", 2244)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(len(result["artifact_ids"]), 4)
        extract.assert_called_once_with(
            self.case_id, "mem-a", 2244, kind="minidump", exact_vfs_path=True
        )
        with get_reverse_session() as db:
            project = db.get(ReverseProject, result["project_id"])
            self.assertEqual(project.status, "ready")
            self.assertIsNone(project.active_run_id)
            self.assertIn("Prove or disprove process hollowing", project.analysis_note)
            artifacts = list(db.query(ReverseArtifact).filter_by(project_id=project.id))
        self.assertEqual({item.artifact_type for item in artifacts}, {"upload", "context"})
        context_row = next(item for item in artifacts if item.name == "process-context.json")
        context = json.loads(contained_project_path(
            result["project_id"], context_row.relative_path, must_exist=True
        ).read_text(encoding="utf-8"))
        self.assertEqual(context["process"]["pid"], 2244)
        self.assertEqual(context["evidence_counts"]["handles"], 1)
        self.assertLessEqual(len(context["context_digest"].encode("utf-8")), 16 * 1024)
        self.assertEqual([row["summary"] for row in context["memory_results"]], ["first module mismatch"])
        action_row = next(item for item in artifacts if item.name == "process-actions.jsonl")
        actions_text = contained_project_path(
            result["project_id"], action_row.relative_path, must_exist=True
        ).read_text(encoding="utf-8")
        self.assertIn("selected action", actions_text)
        self.assertIn("one hop action", actions_text)
        self.assertNotIn("unrelated action", actions_text)

    def test_import_failure_rolls_back_workspace_and_artifacts(self) -> None:
        patches = self._patch_sources()
        calls = 0

        def fail_second(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("disk full")
            return import_artifact(*args, **kwargs)

        with patches[0], patches[1], patches[2], patches[3], patch(
            "app.reverse.handoff.import_artifact", side_effect=fail_second
        ):
            with self.assertRaisesRegex(ProcessHandoffError, "disk full"):
                handoff_process_to_reverse(self.case_id, "mem-a", 2244)
        self.assertEqual(list_projects(self.case_id), [])

    def test_import_rejects_sources_outside_authorized_root(self) -> None:
        project = create_project("contained import", linked_case_id=self.case_id)
        allowed = self.root / "allowed"
        allowed.mkdir()
        outside = self.root / "outside.bin"
        outside.write_bytes(b"outside")

        with self.assertRaisesRegex(ValueError, "authorized directory"):
            import_artifact(
                project.id,
                outside,
                source_root=allowed,
                name="outside.bin",
                artifact_type="upload",
                content_type="application/octet-stream",
            )
        with get_reverse_session() as db:
            self.assertEqual(
                db.query(ReverseArtifact).filter_by(project_id=project.id).count(), 0
            )

    def test_import_rejects_symlink_escape(self) -> None:
        project = create_project("symlink import", linked_case_id=self.case_id)
        allowed = self.root / "allowed"
        allowed.mkdir()
        outside = self.root / "outside.bin"
        outside.write_bytes(b"outside")
        link = allowed / "link.bin"
        try:
            link.symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"Symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(ValueError, "authorized directory"):
            import_artifact(
                project.id,
                link,
                source_root=allowed,
                name="link.bin",
                artifact_type="upload",
                content_type="application/octet-stream",
            )

    def test_handoff_rejects_extractor_output_outside_case_root(self) -> None:
        outside = self.root / "outside.minidump"
        outside.write_bytes(b"outside")
        patches = self._patch_sources()
        with (
            patch("app.reverse.handoff.extract_process_image", return_value=outside),
            patches[1],
            patches[2],
            patches[3],
        ):
            with self.assertRaisesRegex(ProcessHandoffError, "authorized directory"):
                handoff_process_to_reverse(self.case_id, "mem-a", 2244)
        self.assertEqual(list_projects(self.case_id), [])


if __name__ == "__main__":
    unittest.main()
