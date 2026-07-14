from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("generate_sbom", ROOT / "scripts" / "generate_sbom.py")
assert SPEC and SPEC.loader
generate_sbom = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generate_sbom)


class ReleaseToolingTests(unittest.TestCase):
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
            self.assertTrue(any(purl.startswith("pkg:pypi/fastapi@") for purl in purls))
            self.assertTrue(any(purl.startswith("pkg:npm/react@") for purl in purls))


if __name__ == "__main__":
    unittest.main()
