from __future__ import annotations

import base64
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app.config as config
from app.reverse.database import (
    ReverseProject,
    ReverseRun,
    dispose_reverse_db,
    get_reverse_session,
    init_reverse_db,
    reverse_db_path,
)
from app.reverse.store import (
    append_provenance,
    contained_project_path,
    create_project,
    list_projects,
    recover_interrupted_chats,
    recover_interrupted_runs,
    repair_case_links,
    safe_filename,
    unlink_deleted_case,
)
from app.reverse.tools import parse_tool_call, parse_tool_rejection
from app.store import cases
from app.store.database import dispose_all_db_engines


class ReverseStoreTests(unittest.TestCase):
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
        self.config_patch = patch.object(
            config,
            "load_config",
            side_effect=lambda: config.AppConfig(cases_dir=str(config.DEFAULT_CASES_DIR)),
        )
        self.config_patch.start()
        dispose_reverse_db()
        init_reverse_db()

    def tearDown(self) -> None:
        dispose_reverse_db()
        dispose_all_db_engines()
        self.config_patch.stop()
        config.DEFAULT_CONFIG_DIR = self.old_config_dir
        config.DEFAULT_CASES_DIR = self.old_cases_dir
        config.CONFIG_FILE = self.old_config_file
        config.AppConfig.model_fields["cases_dir"].default = self.old_cases_default
        self.temp.cleanup()

    def test_standalone_and_linked_projects_and_unlink_on_case_delete(self) -> None:
        case_id = cases.create_case("linked")["id"]
        standalone = create_project("standalone")
        linked = create_project("linked reverse", linked_case_id=case_id)
        self.assertIsNone(standalone.linked_case_id)
        self.assertEqual(linked.linked_case_id, case_id)
        self.assertEqual([row["id"] for row in list_projects(case_id)], [linked.id])

        self.assertTrue(cases.delete_case(case_id))
        self.assertEqual(unlink_deleted_case(case_id), 1)
        with get_reverse_session() as db:
            self.assertIsNone(db.get(ReverseProject, linked.id).linked_case_id)

    def test_invalid_case_link_is_rejected_and_stale_link_is_repaired(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not exist"):
            create_project("bad", linked_case_id="deadbeef")
        project = create_project("repair")
        with get_reverse_session() as db:
            row = db.get(ReverseProject, project.id)
            row.linked_case_id = "deadbeef"
            db.commit()
        self.assertEqual(repair_case_links(), [project.id])

    def test_paths_are_uuid_scoped_and_cannot_escape(self) -> None:
        project = create_project("paths")
        path = contained_project_path(project.id, "uploads/example")
        self.assertEqual(path.parent.name, "uploads")
        with self.assertRaisesRegex(ValueError, "escapes"):
            contained_project_path(project.id, "../../outside")
        self.assertEqual(safe_filename("..\\evil.exe"), "evil.exe")
        with self.assertRaises(ValueError):
            safe_filename("bad:name.exe")

    def test_interrupted_run_is_recovered_as_stopped(self) -> None:
        project = create_project("recovery")
        run = ReverseRun(
            id="11111111-1111-4111-8111-111111111111",
            project_id=project.id,
            status="running",
            provider="ollama",
            model="test",
        )
        with get_reverse_session() as db:
            db.add(run)
            row = db.get(ReverseProject, project.id)
            row.status = "running"
            row.active_run_id = run.id
            db.commit()
        self.assertEqual(recover_interrupted_runs(), [run.id])
        with get_reverse_session() as db:
            self.assertEqual(db.get(ReverseRun, run.id).status, "stopped")

    def test_interrupted_chat_status_is_recovered(self) -> None:
        project = create_project("chat-recovery")
        with get_reverse_session() as db:
            row = db.get(ReverseProject, project.id)
            row.status = "chatting"
            db.commit()
        self.assertEqual(recover_interrupted_chats(), [project.id])
        with get_reverse_session() as db:
            self.assertEqual(db.get(ReverseProject, project.id).status, "completed")
        self.assertEqual(recover_interrupted_chats(), [])

    def test_denied_tool_calls_surface_a_policy_reason(self) -> None:
        denied = json.dumps([{"tool": "run_cmd", "cmd": ["curl", "http://evil.example"]}])
        self.assertIsNone(parse_tool_call(denied))
        self.assertEqual(parse_tool_rejection(denied), "NOT_IN_ALLOWLIST:curl")
        malformed = json.dumps([{"tool": "run_cmd"}])
        self.assertIsNone(parse_tool_call(malformed))
        self.assertIn("schema validation", parse_tool_rejection(malformed))
        self.assertIsNone(parse_tool_rejection("No tool call here."))

    def test_provenance_chain_links_canonical_hashes(self) -> None:
        project = create_project("provenance")
        first = append_provenance(project.id, "one", {"value": 1})
        second = append_provenance(project.id, "two", {"value": 2})
        self.assertEqual(first.sequence, 1)
        self.assertEqual(second.sequence, 2)
        self.assertEqual(second.previous_hash, first.entry_hash)
        self.assertEqual(len(second.entry_hash), 64)

    def test_reverse_tool_parser_accepts_one_array_operation_and_rejects_escape(self) -> None:
        artifact = "/workspace/inputs/11111111-1111-4111-8111-111111111111"
        call = parse_tool_call(json.dumps([{
            "tool": "run_cmd", "cmd": ["strings", "-n", "6", artifact],
        }]))
        self.assertIsNotNone(call)
        self.assertEqual(call.tool, "run_cmd")
        source = base64.b64encode(b"print('static parser')").decode()
        write_call = parse_tool_call(json.dumps([{
            "tool": "write_file",
            "path": "/workspace/tools/inspect_header.py",
            "content_base64": source,
        }]))
        self.assertEqual(write_call.tool, "write_file")
        self.assertEqual(parse_tool_call(json.dumps([{
            "tool": "run_command",
            "command": ["python3", "/workspace/tools/inspect_header.py", artifact],
        }])).tool, "run_cmd")
        self.assertIsNone(parse_tool_call(json.dumps([{
            "tool": "write_file", "path": "/workspace/inputs/replace", "content_base64": source,
        }])))
        self.assertIsNone(parse_tool_call(json.dumps([{
            "tool": "run_cmd", "cmd": ["sh", "-c", "id"],
        }])))
        self.assertIsNone(parse_tool_call(json.dumps([{
            "tool": "run_cmd", "cmd": ["python3", artifact],
        }])))
        self.assertIsNone(parse_tool_call(json.dumps([{
            "tool": "read_file", "path": "/workspace/../etc/passwd",
        }])))
        self.assertIsNone(parse_tool_call(json.dumps({
            "tool": "run_cmd", "cmd": ["file", artifact],
        })))

    def test_tool_parser_normalizes_common_shorthand_shapes(self) -> None:
        artifact = "/workspace/inputs/11111111-1111-4111-8111-111111111111"
        # Tool name as the object key with a whole command line as one string.
        shorthand = parse_tool_call(json.dumps([{"run_cmd": f"strings {artifact}"}]))
        self.assertIsNotNone(shorthand)
        self.assertEqual(shorthand.cmd, ["strings", artifact])
        # cmd given as a single string instead of an argv array.
        string_cmd = parse_tool_call(json.dumps([{
            "tool": "run_cmd", "cmd": f"strings -n 6 {artifact}",
        }]))
        self.assertEqual(string_cmd.cmd, ["strings", "-n", "6", artifact])
        # One-element argv containing the whole command line.
        packed = parse_tool_call(json.dumps([{
            "tool": "run_cmd", "cmd": [f"file {artifact}"],
        }]))
        self.assertEqual(packed.cmd, ["file", artifact])
        # Shorthand with a nested argument object.
        nested = parse_tool_call(json.dumps([{
            "read_file": {"path": "/workspace/output/carved.bin", "max_bytes": 512},
        }]))
        self.assertEqual(nested.tool, "read_file")
        self.assertEqual(nested.max_bytes, 512)
        # Normalization never bypasses the command policy.
        self.assertIsNone(parse_tool_call(json.dumps([{"run_cmd": "curl http://evil.example"}])))
        self.assertEqual(
            parse_tool_rejection(json.dumps([{"run_cmd": "curl http://evil.example"}])),
            "NOT_IN_ALLOWLIST:curl",
        )
        self.assertIsNone(parse_tool_call(json.dumps([{"run_cmd": "sh -c id"}])))

    def test_v1_store_migrates_report_signature_and_verification_state(self) -> None:
        dispose_reverse_db()
        path = reverse_db_path()
        for suffix in ("", "-wal", "-shm"):
            Path(str(path) + suffix).unlink(missing_ok=True)
        connection = sqlite3.connect(path)
        connection.execute(
            "CREATE TABLE reverse_runs (id VARCHAR(36) PRIMARY KEY, project_id VARCHAR(36))"
        )
        connection.execute("CREATE TABLE reverse_schema_version (version INTEGER NOT NULL)")
        connection.execute("INSERT INTO reverse_schema_version(version) VALUES (1)")
        connection.commit()
        connection.close()
        init_reverse_db()
        connection = sqlite3.connect(path)
        columns = {row[1] for row in connection.execute("PRAGMA table_info(reverse_runs)")}
        version = connection.execute("SELECT version FROM reverse_schema_version").fetchone()[0]
        connection.close()
        self.assertEqual(version, 6)
        self.assertIn("report_signature_status", columns)
        self.assertIn("report_signature_error", columns)
        self.assertIn("report_verification_status", columns)
        self.assertIn("report_verification_details", columns)

    def test_v5_store_removes_retired_tool_approvals(self) -> None:
        project = create_project("legacy tools")
        dispose_reverse_db()
        connection = sqlite3.connect(reverse_db_path())
        connection.execute("UPDATE reverse_schema_version SET version = 5")
        connection.execute(
            "INSERT INTO reverse_tool_approvals "
            "(project_id, tool_id, approved, created_at) VALUES (?, ?, 1, CURRENT_TIMESTAMP)",
            (project.id, "strings_scan"),
        )
        connection.commit()
        connection.close()
        init_reverse_db()
        connection = sqlite3.connect(reverse_db_path())
        version = connection.execute("SELECT version FROM reverse_schema_version").fetchone()[0]
        retired = connection.execute(
            "SELECT COUNT(*) FROM reverse_tool_approvals WHERE tool_id = 'strings_scan'"
        ).fetchone()[0]
        connection.close()
        self.assertEqual(version, 6)
        self.assertEqual(retired, 0)


if __name__ == "__main__":
    unittest.main()
