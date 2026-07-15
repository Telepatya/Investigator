from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import app.config as config
from app.reverse.database import (
    ReverseArtifact,
    dispose_reverse_db,
    get_reverse_session,
    init_reverse_db,
)
from app.reverse.sandbox import ReverseSandboxManager, _bounded_tool_output
from app.reverse.store import contained_project_path, create_project
from app.reverse.tools import parse_tool_call


class _Image:
    id = "sha256:image"
    attrs = {"RepoDigests": ["investigator-reverse@sha256:verified"]}


class _Container:
    id = "container-id"
    status = "created"

    class _Result:
        exit_code = 0

    def exec_run(self, *_args, **_kwargs):
        return self._Result()

    def start(self):
        self.status = "running"

    def reload(self):
        return None

    def put_archive(self, _path, _data):
        return True


class _Images:
    def get(self, _name):
        return _Image()


class _Containers:
    def __init__(self):
        self.kwargs = None

    def get(self, _name):
        raise RuntimeError("not found")

    def create(self, _image, **kwargs):
        self.kwargs = kwargs
        return _Container()


class _Docker:
    def __init__(self):
        self.images = _Images()
        self.containers = _Containers()


class ReverseSandboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old_dir = config.DEFAULT_CONFIG_DIR
        self.old_file = config.CONFIG_FILE
        config.DEFAULT_CONFIG_DIR = self.root
        config.CONFIG_FILE = self.root / "config.json"
        dispose_reverse_db()
        init_reverse_db()

    def tearDown(self) -> None:
        dispose_reverse_db()
        config.DEFAULT_CONFIG_DIR = self.old_dir
        config.CONFIG_FILE = self.old_file
        self.temp.cleanup()

    def test_container_is_created_with_exact_hardening_boundary(self) -> None:
        project = create_project("sandbox")
        fake = _Docker()
        manager = ReverseSandboxManager()
        with patch.object(manager, "_docker", return_value=fake):
            active = manager.ensure(project.id)
        self.assertEqual(active.image_digest, "investigator-reverse@sha256:verified")
        args = fake.containers.kwargs
        self.assertEqual(args["network_mode"], "none")
        self.assertTrue(args["read_only"])
        self.assertEqual(args["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", args["security_opt"])
        self.assertNotIn("volumes", args)
        self.assertNotIn("ports", args)
        self.assertIn("/workspace", args["tmpfs"])
        self.assertIn("noexec", args["tmpfs"]["/workspace"])
        self.assertIn("uid=10001", args["tmpfs"]["/workspace"])
        self.assertGreater(args["pids_limit"], 0)

    def test_truncated_disassembly_keeps_entrypoint_header_and_tail(self) -> None:
        value = "ENTRYPOINT\n" + ("instruction\n" * 1000) + "FINAL-BLOCK"
        bounded, truncated = _bounded_tool_output(value, 1000)
        self.assertTrue(truncated)
        self.assertLessEqual(len(bounded), 1000)
        self.assertTrue(bounded.startswith("ENTRYPOINT"))
        self.assertTrue(bounded.endswith("FINAL-BLOCK"))
        self.assertIn("middle omitted", bounded)

    def test_indirect_command_execution_bypasses_are_rejected_on_the_host(self) -> None:
        denied = [
            ["find", "/workspace", "-exec", "sh", "-c", "id", ";"],
            ["awk", "BEGIN{system(\"id\")}", "/workspace/inputs/sample"],
            ["sed", "s/a/b/e", "/workspace/inputs/sample"],
            ["rm", "inputs/sample"],
            ["python3", "/workspace/inputs/sample.py"],
            ["unzip", "/workspace/inputs/sample.zip", "-d", "/workspace/inputs/extracted"],
            ["7z", "a", "/workspace/inputs/sample.7z", "/workspace/output/data"],
            ["upx", "/workspace/inputs/sample"],
        ]
        for cmd in denied:
            with self.subTest(cmd=cmd):
                self.assertIsNone(parse_tool_call(json.dumps([{"tool": "run_cmd", "cmd": cmd}])))
        self.assertIsNone(parse_tool_call(json.dumps([{
            "tool": "run_cmd",
            "cmd": ["binwalk", "sample"],
            "cwd": "/workspace/inputs",
        }])))

    @unittest.skipUnless(
        os.environ.get("INVESTIGATOR_DOCKER_TESTS") == "1",
        "set INVESTIGATOR_DOCKER_TESTS=1 to exercise the local sandbox image",
    )
    def test_real_image_executes_only_the_semantic_broker(self) -> None:
        project = create_project("docker integration")
        artifact_id = str(uuid.uuid4())
        payload = b"MZ static integration fixture"
        relative = f"uploads/{artifact_id}"
        contained_project_path(project.id, relative).write_bytes(payload)
        with get_reverse_session() as db:
            db.add(ReverseArtifact(
                id=artifact_id,
                project_id=project.id,
                name="fixture.bin",
                relative_path=relative,
                artifact_type="upload",
                content_type="application/octet-stream",
                file_size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            ))
            db.commit()
        sample = f"/workspace/inputs/{artifact_id}"
        call = parse_tool_call(json.dumps([{"tool": "run_cmd", "cmd": ["file", sample]}]))
        self.assertIsNotNone(call)
        manager = ReverseSandboxManager()
        try:
            result = manager.execute(project.id, call)
            self.assertTrue(result["success"], result)
            self.assertIn("text", result["stdout"].lower())

            listing = parse_tool_call(json.dumps([{
                "tool": "list_dir",
                "path": "/workspace/inputs",
            }]))
            list_result = manager.execute(project.id, listing)
            self.assertTrue(list_result["success"], list_result)
            self.assertIn(artifact_id, [item["name"] for item in list_result["items"]])

            reading = parse_tool_call(json.dumps([{
                "tool": "read_file",
                "path": sample,
                "max_bytes": 32,
            }]))
            read_result = manager.execute(project.id, reading)
            self.assertTrue(read_result["success"], read_result)
            self.assertEqual(base64.b64decode(read_result["content_base64"]), payload)

            permissions = parse_tool_call(json.dumps([{
                "tool": "run_cmd",
                "cmd": ["stat", "-c", "%a", "/workspace/inputs"],
            }]))
            permission_result = manager.execute(project.id, permissions)
            self.assertTrue(permission_result["success"], permission_result)
            self.assertEqual(permission_result["stdout"].strip(), "500")

            source = (
                "import hashlib, sys\n"
                "from pathlib import Path\n"
                "data = Path(sys.argv[1]).read_bytes()\n"
                "print(hashlib.sha256(data).hexdigest(), len(data))\n"
            )
            write = parse_tool_call(json.dumps([{
                "tool": "write_file",
                "path": "/workspace/tools/hash_sample.py",
                "content_base64": base64.b64encode(source.encode()).decode(),
            }]))
            self.assertTrue(manager.execute(project.id, write)["success"])
            run = parse_tool_call(json.dumps([{
                "tool": "run_cmd",
                "cmd": ["python3", "/workspace/tools/hash_sample.py", sample],
            }]))
            python_result = manager.execute(project.id, run)
            self.assertTrue(python_result["success"], python_result)
            self.assertIn(hashlib.sha256(payload).hexdigest(), python_result["stdout"])

            blocked_source = "import subprocess\nsubprocess.run(['/usr/bin/file', 'fixture'])\n"
            blocked = parse_tool_call(json.dumps([{
                "tool": "write_file",
                "path": "/workspace/tools/blocked_process.py",
                "content_base64": base64.b64encode(blocked_source.encode()).decode(),
            }]))
            self.assertTrue(manager.execute(project.id, blocked)["success"])
            blocked_run = parse_tool_call(json.dumps([{
                "tool": "run_cmd",
                "cmd": ["python3", "/workspace/tools/blocked_process.py", sample],
            }]))
            blocked_result = manager.execute(project.id, blocked_run)
            self.assertFalse(blocked_result["success"])
            self.assertIn("blocked audit event", blocked_result["stderr"])
        finally:
            manager.shutdown()


if __name__ == "__main__":
    unittest.main()
