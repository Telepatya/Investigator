from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("generate_sbom", ROOT / "scripts" / "generate_sbom.py")
assert SPEC and SPEC.loader
generate_sbom = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generate_sbom)

RUN_SPEC = importlib.util.spec_from_file_location("investigator_launcher", ROOT / "run.py")
assert RUN_SPEC and RUN_SPEC.loader
investigator_launcher = importlib.util.module_from_spec(RUN_SPEC)
RUN_SPEC.loader.exec_module(investigator_launcher)

BUILD_SPEC = importlib.util.spec_from_file_location("build_release", ROOT / "scripts" / "build_release.py")
assert BUILD_SPEC and BUILD_SPEC.loader
build_release = importlib.util.module_from_spec(BUILD_SPEC)
with patch.dict(sys.modules, {"generate_sbom": generate_sbom}):
    BUILD_SPEC.loader.exec_module(build_release)


class ReleaseToolingTests(unittest.TestCase):
    def test_release_includes_referenced_requirement_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (*build_release.ROOT_FILES, *build_release.BACKEND_FILES):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            for tree in build_release.TREES:
                (root / tree).mkdir(parents=True, exist_ok=True)
            with patch.object(build_release, "ROOT", root):
                included = {path.relative_to(root) for path in build_release.release_files()}
            for name in included:
                if name.suffix in {".txt", ".in"}:
                    for line in (root / name).read_text(encoding="utf-8").splitlines():
                        if line.startswith("-r "):
                            self.assertIn(name.parent / line[3:].strip(), included)

    def test_frontend_digest_tracks_public_and_build_config_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "public").mkdir()
            with patch.object(investigator_launcher, "FRONTEND", root):
                previous = investigator_launcher.frontend_source_digest()
                for name in ("public/shield.svg", "tailwind.config.js", "postcss.config.js"):
                    path = root / name
                    path.write_text("first")
                    current = investigator_launcher.frontend_source_digest()
                    self.assertNotEqual(previous, current)
                    path.write_text("second")
                    self.assertNotEqual(current, investigator_launcher.frontend_source_digest())
                    previous = investigator_launcher.frontend_source_digest()
    def test_locked_install_uses_hashes_without_dependency_resolution(self) -> None:
        command = investigator_launcher.locked_pip_install_command(
            Path("python.exe"), Path("requirements-memory.lock")
        )
        self.assertIn("--require-hashes", command)
        self.assertIn("--no-deps", command)
        self.assertEqual(command[-2:], ["-r", "requirements-memory.lock"])

    def test_sbom_is_deterministic_and_contains_both_ecosystems(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            generate_sbom.write_sbom("v0.1.0", first)
            generate_sbom.write_sbom("v0.1.0", second)
            self.assertEqual(first.read_bytes(), second.read_bytes())

            data = json.loads(first.read_text(encoding="utf-8"))
            self.assertEqual(data["bomFormat"], "CycloneDX")
            purls = {component["purl"] for component in data["components"]}
            self.assertEqual(len(purls), len(data["components"]))
            self.assertTrue(any(purl.startswith("pkg:pypi/fastapi@") for purl in purls))
            self.assertTrue(any(purl.startswith("pkg:pypi/lief@") for purl in purls))
            self.assertTrue(any(purl.startswith("pkg:npm/react@") for purl in purls))
            self.assertTrue(any(purl.startswith("pkg:docker/ubuntu@22.04") for purl in purls))
            self.assertTrue(any(
                purl.startswith("pkg:deb/ubuntu/yara@4.1.3-1build1") for purl in purls
            ))


if __name__ == "__main__":
    unittest.main()
