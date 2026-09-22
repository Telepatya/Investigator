"""Keep pySigma's optional disk cache outside supported rule operations.

This is reachability evidence, not a suppression of the unpatched diskcache
advisory. The dependency remains in the complete upstream package closure.
"""

import subprocess
import sys
import unittest
from pathlib import Path


class SigmaDependencyBoundaryTests(unittest.TestCase):
    def test_rule_compilation_does_not_load_optional_disk_cache(self):
        script = """
import sys
class BlockCache:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'diskcache' or fullname.startswith('sigma.data') or fullname.startswith('sigma.validators'):
            raise AssertionError('Unexpected optional cache/validator import: ' + fullname)
sys.meta_path.insert(0, BlockCache())
from app.rules.sigma_compile import compile_source
rules = compile_source('''title: Synthetic dependency boundary
tags:
  - attack.execution
  - attack.t1059
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: example-marker
  condition: selection
level: medium
''')
assert len(rules) == 1
assert 'diskcache' not in sys.modules
"""
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[1],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
