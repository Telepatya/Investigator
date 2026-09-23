from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
import zlib
from pathlib import Path
from unittest.mock import patch

import app.config as config
from app.reverse.database import (
    ReverseArtifact,
    dispose_reverse_db,
    get_reverse_session,
    init_reverse_db,
)
from app.reverse.command_policy import _is_symbolic_chmod_mode
from app.reverse.sandbox import ReverseSandboxManager, _bounded_tool_output
from app.reverse.store import contained_project_path, create_project
from app.reverse.tools import parse_tool_call


class _Image:
    id = "sha256:image"
    attrs = {"RepoDigests": ["investigator-reverse@sha256:verified"]}


class _Container:
    id = "container-id"

    class _Result:
        exit_code = 0
        output = b"3\n"

    def __init__(self):
        self.status = "created"
        self.calls = []

    def exec_run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self._Result()

    def start(self):
        self.status = "running"

    def reload(self):
        return None

    def remove(self, **_kwargs):
        self.status = "removed"

    def put_archive(self, _path, _data):
        return True


class _Images:
    def get(self, _name):
        return _Image()


class _Containers:
    def __init__(self):
        self.kwargs = None
        self.container = None
        self.error = None

    def get(self, _name):
        if self.error:
            raise self.error
        from docker.errors import NotFound

        raise NotFound("not found")

    def create(self, _image, **kwargs):
        self.kwargs = kwargs
        self.container = _Container()
        return self.container


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
        self.assertIn("uid=0,gid=10001,mode=0750", args["tmpfs"]["/workspace"])
        commands = fake.containers.container.calls
        prepare = next(call for call in commands if call[0][0] == ["reverse-stage", "prepare"])
        self.assertEqual(prepare[1]["user"], "0:10001")
        self.assertGreater(args["pids_limit"], 0)

    def test_stale_container_lookup_errors_are_not_silently_ignored(self) -> None:
        project = create_project("sandbox lookup failure")
        fake = _Docker()
        fake.containers.error = RuntimeError("Docker API permission denied")
        manager = ReverseSandboxManager()
        with patch.object(manager, "_docker", return_value=fake):
            with self.assertRaisesRegex(RuntimeError, "permission denied"):
                manager.ensure(project.id)
        self.assertIsNone(fake.containers.kwargs)

    def test_truncated_disassembly_keeps_entrypoint_header_and_tail(self) -> None:
        value = "ENTRYPOINT\n" + ("instruction\n" * 1000) + "FINAL-BLOCK"
        bounded, truncated = _bounded_tool_output(value, 1000)
        self.assertTrue(truncated)
        self.assertLessEqual(len(bounded), 1000)
        self.assertTrue(bounded.startswith("ENTRYPOINT"))
        self.assertTrue(bounded.endswith("FINAL-BLOCK"))
        self.assertIn("middle omitted", bounded)

    def test_context_sidecar_is_staged_by_safe_name_and_sealed(self) -> None:
        project = create_project("context sandbox")
        artifact_id = str(uuid.uuid4())
        payload = b'{"context_digest":"lead"}'
        relative = f"context/{artifact_id}"
        contained_project_path(project.id, relative).write_bytes(payload)
        with get_reverse_session() as db:
            db.add(ReverseArtifact(
                id=artifact_id, project_id=project.id, name="process-context.json",
                relative_path=relative, artifact_type="context", content_type="application/json",
                file_size=len(payload), sha256=hashlib.sha256(payload).hexdigest(),
            ))
            db.commit()
        fake = _Docker()
        manager = ReverseSandboxManager()
        with patch.object(manager, "_docker", return_value=fake):
            manager.ensure(project.id)
        for args, kwargs in fake.containers.container.calls:
            if args[0][:2] in (["reverse-stage", "write"], ["reverse-stage", "seal"]):
                self.assertEqual(kwargs["user"], "0:10001")
        commands = [call[0][0] for call in fake.containers.container.calls]
        self.assertTrue(any(command[:4] == [
            "reverse-stage", "write", "context", "process-context.json"
        ] for command in commands))
        self.assertTrue(any(command[:4] == [
            "reverse-stage", "seal", "context", "process-context.json"
        ] for command in commands))

    def test_outdated_staging_protocol_is_rejected_before_artifact_copy(self) -> None:
        project = create_project("outdated sandbox")
        fake = _Docker()
        manager = ReverseSandboxManager()

        class _OldResult:
            exit_code = 2
            output = b"Invalid staging request\n"

        fake.containers.create(_Image()).exec_run = lambda *_args, **_kwargs: _OldResult()
        container = fake.containers.container
        fake.containers.create = lambda *_args, **_kwargs: container
        with patch.object(manager, "_docker", return_value=fake):
            with self.assertRaisesRegex(
                Exception, "sandbox image is outdated or incompatible"
            ):
                manager.ensure(project.id)
        self.assertEqual(container.status, "removed")

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

    def test_symbolic_chmod_mode_parser_matches_supported_single_clause_syntax(self) -> None:
        for mode in ("u+x", "go-r", "a=rw", "ugoa+Xst"):
            with self.subTest(mode=mode):
                self.assertTrue(_is_symbolic_chmod_mode(mode))
        for mode in ("+x", "u+", "u+x,go-r", "u+x;id", "u+xyz"):
            with self.subTest(mode=mode):
                self.assertFalse(_is_symbolic_chmod_mode(mode))

    def test_pyinstaller_inspector_command_has_bounded_output_mutation(self) -> None:
        allowed = parse_tool_call(json.dumps([{
            "tool": "run_cmd",
            "cmd": [
                "pyinstaller-inspect", "/workspace/inputs/sample", "--extract", "loki",
                "--output", "/workspace/output/loki.bin",
            ],
        }]))
        denied = parse_tool_call(json.dumps([{
            "tool": "run_cmd",
            "cmd": [
                "pyinstaller-inspect", "/workspace/inputs/sample", "--extract", "loki",
                "--output", "/workspace/inputs/loki.bin",
            ],
        }]))
        denied_equals = parse_tool_call(json.dumps([{
            "tool": "run_cmd",
            "cmd": [
                "pyinstaller-inspect", "/workspace/inputs/sample", "--extract", "loki",
                "--output=/workspace/context/loki.bin",
            ],
        }]))
        self.assertIsNotNone(allowed)
        self.assertIsNone(denied)
        self.assertIsNone(denied_equals)

    def test_pyinstaller_inspector_uses_cookie_end_for_package_base(self) -> None:
        payload = b"synthetic Python 3.7 marshalled payload"
        packed = zlib.compress(payload, 9)
        name = b"loki\0"
        entry_size = 18 + len(name)
        toc = struct.pack("!iIIIBc", entry_size, 0, len(packed), len(payload), 1, b"s") + name
        cookie = struct.pack(
            "!8sIIII64s", b"MEI\x0c\x0b\x0a\x0b\x0e",
            len(packed) + len(toc) + 88, len(packed), len(toc), 307, b"python37.dll\0",
        )
        prefix = b"MZ" + (b"\0" * 86)
        archive = prefix + packed + toc + cookie
        sample = self.root / "synthetic-pyinstaller.exe"
        sample.write_bytes(archive)
        script = Path(__file__).parents[1] / "reverse_sandbox" / "pyinstaller_inspect.py"
        completed = subprocess.run(
            [sys.executable, str(script), str(sample)], capture_output=True, text=True,
            check=False, timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        result = json.loads(completed.stdout)
        self.assertEqual(result["package_base"], len(prefix))
        self.assertEqual(result["cookie_size"], 88)
        self.assertEqual(result["python_version"], "3.7")
        self.assertFalse(result["bytecode_runtime_compatible"])
        self.assertTrue(result["entries"][0]["zlib_header_plausible"])

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
            self.assertEqual(permission_result["stdout"].strip(), "550")

            active = manager.ensure(project.id)
            container = manager._docker().containers.get(active.container_id)
            permission_check = container.exec_run(
                ["python3", "-c", (
                    "import os, pathlib, sys\n"
                    "assert os.geteuid() == 10001\n"
                    "sample = pathlib.Path(sys.argv[1])\n"
                    "assert sample.read_bytes() == b'MZ static integration fixture'\n"
                    "for path in (sample, sample.parent, pathlib.Path('/workspace/context'), pathlib.Path('/workspace')):\n"
                    " assert path.stat().st_uid == 0\n"
                    " try: path.chmod(0o777)\n"
                    " except PermissionError: pass\n"
                    " else: raise AssertionError('analyst could chmod evidence boundary')\n"
                    "try: sample.unlink()\n"
                    "except PermissionError: pass\n"
                    "else: raise AssertionError('analyst could unlink evidence')\n"
                    "try: sample.parent.rename('/workspace/renamed-inputs')\n"
                    "except PermissionError: pass\n"
                    "else: raise AssertionError('analyst could replace input directory')\n"
                    "for name in ('output', 'tools'):\n"
                    " path = pathlib.Path('/workspace') / name / 'permission-probe'\n"
                    " path.write_text('synthetic')\n"
                    " path.unlink()\n"
                ), sample],
                user="reverse", workdir="/workspace",
            )
            self.assertEqual(permission_check.exit_code, 0, permission_check.output)

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
