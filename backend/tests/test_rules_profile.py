from __future__ import annotations

# ruff: noqa: E402
#
# The RuleProfile carries two promises that are easy to break by accident:
#   * an installation that never touched the Rules page pays nothing — the engine
#     iterates the very same table objects it always did, and no database is opened;
#   * disabling a rule *removes work* rather than suppressing a finding afterwards.
# Both are asserted structurally here, because a regression in either is invisible
# in ordinary detection output.

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.detect import rules as R
from app.rules import database as rules_database
from app.rules import profile as profile_module
from app.rules import store
from app.rules.profile import DEFAULT_PROFILE, load_profile


class _RulesDbTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [
            patch.object(rules_database, "get_rules_dir", return_value=self.root),
        ]
        for item in self.patches:
            item.start()
        rules_database.dispose_rules_db()
        profile_module.invalidate_cache()

    def tearDown(self) -> None:
        rules_database.dispose_rules_db()
        profile_module.invalidate_cache()
        for item in reversed(self.patches):
            item.stop()
        self.tmp.cleanup()


class DefaultProfileTests(_RulesDbTestBase):
    def test_no_database_yields_the_default_profile(self) -> None:
        self.assertIs(load_profile(), DEFAULT_PROFILE)

    def test_default_profile_holds_the_module_tables_themselves(self) -> None:
        """Identity, not equality.

        The corpus tests compare the engine's prefiltered output against a reference
        loop over the module tables. If the default profile handed out copies, those
        comparisons would silently stop testing the same objects.
        """
        self.assertIs(DEFAULT_PROFILE.win_cmdline, R.SUSPICIOUS_CMDLINE_PATTERNS)
        self.assertIs(DEFAULT_PROFILE.linux_cmdline, R.LINUX_SUSPICIOUS_CMDLINE_PATTERNS)
        self.assertIs(DEFAULT_PROFILE.lolbins, R.LOLBINS)
        self.assertIs(DEFAULT_PROFILE.parent_child, R.SUSPICIOUS_PARENT_CHILD_MAP)
        self.assertIs(DEFAULT_PROFILE.system_process_paths, R.SYSTEM_PROCESS_PATHS)
        self.assertIs(DEFAULT_PROFILE.exec_dirs, R.SUSPICIOUS_EXECUTION_DIRS)
        self.assertIs(DEFAULT_PROFILE.registry_persistence, R.PERSISTENCE_REGISTRY_PATHS)
        self.assertIs(DEFAULT_PROFILE.linux_persistence, R.LINUX_PERSISTENCE_PATHS)
        self.assertIs(DEFAULT_PROFILE.web_attacks, R.WEB_ATTACK_PATTERNS)
        self.assertIs(DEFAULT_PROFILE.web_user_agents, R.WEB_USER_AGENT_PATTERNS)

    def test_no_database_opens_no_session(self) -> None:
        with patch.object(rules_database, "init_rules_db") as opened:
            self.assertIs(load_profile(), DEFAULT_PROFILE)
        opened.assert_not_called()

    def test_default_profile_has_no_custom_rules(self) -> None:
        self.assertTrue(DEFAULT_PROFILE.custom.empty)
        self.assertTrue(DEFAULT_PROFILE.is_default)


class FilteringTests(_RulesDbTestBase):
    def test_disabling_a_member_removes_only_that_entry(self) -> None:
        store.set_builtin_state("lolbin.certutil", enabled=False)
        profile_module.invalidate_cache()
        active = load_profile()

        self.assertNotIn("certutil.exe", active.lolbins)
        self.assertEqual(len(active.lolbins), len(R.LOLBINS) - 1)
        # Untouched tables must still be the originals, so nothing else got copied.
        self.assertIs(active.win_cmdline, R.SUSPICIOUS_CMDLINE_PATTERNS)

    def test_disabling_a_family_removes_every_member(self) -> None:
        store.set_builtin_state("lolbin", enabled=False)
        profile_module.invalidate_cache()
        self.assertEqual(len(load_profile().lolbins), 0)

    def test_disabling_a_grouped_rule_drops_all_of_its_patterns(self) -> None:
        """Descriptions shared by several patterns are one rule and go together."""
        spec_indices = 2  # "PowerShell encoded command" owns two patterns
        store.set_builtin_state("cmdline.win.powershell-encoded-command", enabled=False)
        profile_module.invalidate_cache()
        active = load_profile()
        self.assertEqual(
            len(active.win_cmdline), len(R.SUSPICIOUS_CMDLINE_PATTERNS) - spec_indices
        )
        self.assertNotIn(
            "PowerShell encoded command", [row[2] for row in active.win_cmdline]
        )

    def test_severity_override_rewrites_only_its_target(self) -> None:
        store.set_builtin_state("cmdline.win.powershell-no-profile-execution", severity_override="critical")
        profile_module.invalidate_cache()
        active = load_profile()
        severities = {
            row[2]: row[3] for row in active.win_cmdline
        }
        self.assertEqual(severities["PowerShell no-profile execution"], "critical")
        self.assertEqual(severities["PowerShell encoded command"], "high")

    def test_family_disable_is_applied_centrally_too(self) -> None:
        """A fully disabled legacy id is dropped in _add_finding as a backstop.

        Table filtering handles the hot path; this covers detections whose logic is
        imperative engine code rather than a table row.
        """
        store.set_builtin_state("lolbin", enabled=False)
        for spec_id in [
            spec.id for spec in __import__("app.rules.registry", fromlist=["x"]).BUILTIN_RULES
            if spec.family == "lolbin"
        ]:
            store.set_builtin_state(spec_id, enabled=False)
        profile_module.invalidate_cache()
        self.assertIn("lolbin-activity", load_profile().disabled_legacy_ids)

    def test_partial_family_disable_is_not_applied_centrally(self) -> None:
        """One disabled LOLBin must not suppress the other 32 via the shared id."""
        store.set_builtin_state("lolbin.certutil", enabled=False)
        profile_module.invalidate_cache()
        self.assertNotIn("lolbin-activity", load_profile().disabled_legacy_ids)


class CacheTests(_RulesDbTestBase):
    def test_profile_is_cached_until_the_revision_changes(self) -> None:
        store.set_builtin_state("lolbin.certutil", enabled=False)
        profile_module.invalidate_cache()
        first = load_profile()
        self.assertIs(load_profile(), first)

        store.set_builtin_state("lolbin.mshta", enabled=False)
        second = load_profile()
        self.assertIsNot(second, first)
        self.assertGreater(second.revision, first.revision)

    def test_re_enabling_everything_returns_to_the_default_profile(self) -> None:
        store.set_builtin_state("lolbin.certutil", enabled=False)
        profile_module.invalidate_cache()
        self.assertIsNot(load_profile(), DEFAULT_PROFILE)

        store.set_builtin_state("lolbin.certutil", enabled=True)
        self.assertIs(load_profile(), DEFAULT_PROFILE)


if __name__ == "__main__":
    unittest.main()
