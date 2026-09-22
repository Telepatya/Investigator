"""Synthetic command-output tests; Linux resource limits belong to Docker tests."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from app.reverse import command_policy


def _load_broker():
    spec = importlib.util.spec_from_file_location(
        "output_test_broker", Path(__file__).parents[1] / "reverse_sandbox" / "broker.py"
    )
    module = importlib.util.module_from_spec(spec)
    aliases = {"reverse_policy": command_policy}
    if os.name == "nt":
        aliases["resource"] = types.SimpleNamespace()
    with patch.dict(sys.modules, aliases), patch.object(sys, "path", list(sys.path)):
        spec.loader.exec_module(module)
    return module


class ReverseBrokerOutputTests(unittest.TestCase):
    def setUp(self):
        self.broker = _load_broker()
        native_run = subprocess.run

        def run(*args, **kwargs):
            if os.name == "nt":
                # Exercise actual file-backed output collection on Windows;
                # preexec_fn/resource is available only in the Linux image.
                self.assertIs(kwargs.pop("preexec_fn"), self.broker.limits)
            return native_run(*args, **kwargs)

        self.runner_patch = patch.object(self.broker.subprocess, "run", side_effect=run)
        self.runner_patch.start()
        self.addCleanup(self.runner_patch.stop)

    def test_both_output_streams_are_bounded_during_collection(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(self.broker, "MAX_BROKER_OUTPUT", 64):
            result = self.broker.bounded_command(
                [sys.executable, "-c", "import sys; sys.stdout.write('a'*4096); sys.stderr.write('b'*4096)"],
                cwd=directory, input=None, timeout=10,
            )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"a" * 65)
        self.assertEqual(result.stderr, b"b" * 65)

    def test_small_output_stdin_and_failure_status_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.broker.bounded_command(
                [sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.stderr.write('error'); sys.exit(7)"],
                cwd=directory, input=b"synthetic input", timeout=10,
            )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b"synthetic input")
        self.assertEqual(result.stderr, b"error")

    def test_command_timeout_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.broker.bounded_command(
                    [sys.executable, "-c", "import time; time.sleep(2)"],
                    cwd=directory, input=None, timeout=0.05,
                )


if __name__ == "__main__":
    unittest.main()
