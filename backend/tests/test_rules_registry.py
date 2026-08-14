from __future__ import annotations

# ruff: noqa: E402
#
# The registry is the bridge between two identifier spaces: the new fine-grained
# registry ids, and the legacy ids that ``overrides.rule_id_for()`` derives from a
# finding title and that are already persisted in every existing case's
# ``case_meta["disabled_rules"]``. If those drift apart, analysts silently lose
# suppressions they set up, so the relationship is pinned here rather than trusted.

import unittest

from app.detect import rules as R
from app.detect.overrides import rule_id_for
from app.rules.registry import (
    BUILTIN_RULES,
    LEGACY_TO_REGISTRY,
    RULES_BY_ID,
    members_of,
    registry_fingerprint,
)


class CatalogShapeTests(unittest.TestCase):
    def test_ids_are_unique(self) -> None:
        ids = [spec.id for spec in BUILTIN_RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_catalog_is_not_empty_and_is_indexed(self) -> None:
        self.assertGreater(len(BUILTIN_RULES), 250)
        self.assertEqual(len(RULES_BY_ID), len(BUILTIN_RULES))

    def test_fingerprint_is_stable_across_calls(self) -> None:
        self.assertEqual(registry_fingerprint(), registry_fingerprint())

    def test_every_table_row_is_owned_by_exactly_one_rule(self) -> None:
        """No pattern may be orphaned: an unowned row could never be disabled."""
        for table_name, table in (
            ("SUSPICIOUS_CMDLINE_PATTERNS", R.SUSPICIOUS_CMDLINE_PATTERNS),
            ("LINUX_SUSPICIOUS_CMDLINE_PATTERNS", R.LINUX_SUSPICIOUS_CMDLINE_PATTERNS),
            ("WEB_ATTACK_PATTERNS", R.WEB_ATTACK_PATTERNS),
            ("WEB_USER_AGENT_PATTERNS", R.WEB_USER_AGENT_PATTERNS),
            ("PERSISTENCE_REGISTRY_PATHS", R.PERSISTENCE_REGISTRY_PATHS),
            ("LINUX_PERSISTENCE_PATHS", R.LINUX_PERSISTENCE_PATHS),
        ):
            with self.subTest(table=table_name):
                owned: list[int] = []
                for spec in BUILTIN_RULES:
                    if spec.source_table == table_name:
                        owned.extend(spec.source_indices)
                self.assertEqual(
                    sorted(owned), list(range(len(table))),
                    f"{table_name} rows are not covered exactly once",
                )

    def test_mapping_tables_are_fully_covered(self) -> None:
        for table_name, table in (
            ("LOLBINS", R.LOLBINS),
            ("SYSTEM_PROCESS_PATHS", R.SYSTEM_PROCESS_PATHS),
        ):
            with self.subTest(table=table_name):
                keys = {
                    spec.source_key
                    for spec in BUILTIN_RULES
                    if spec.source_table == table_name and spec.source_key
                }
                self.assertEqual(keys, set(table))


class LegacyCompatibilityTests(unittest.TestCase):
    """The contract with already-persisted per-case ``disabled_rules``."""

    def test_command_line_rules_keep_their_persisted_legacy_id(self) -> None:
        # The engine emits these findings with title=description, so the legacy id
        # an existing case stored is exactly rule_id_for(description).
        for spec in BUILTIN_RULES:
            if spec.source_table != "SUSPICIOUS_CMDLINE_PATTERNS":
                continue
            with self.subTest(rule=spec.id):
                self.assertIn(rule_id_for(spec.title), spec.legacy_rule_ids)

    def test_lolbin_family_collapses_to_the_persisted_family_id(self) -> None:
        members = members_of("lolbin")
        self.assertGreater(len(members), 20)
        for spec in members:
            self.assertEqual(spec.legacy_rule_ids, ("lolbin-activity",))
        # The family switch itself carries the same legacy id, which is what makes an
        # existing per-case disable of "lolbin-activity" keep working untouched.
        self.assertEqual(RULES_BY_ID["lolbin"].legacy_rule_ids, ("lolbin-activity",))

    def test_variable_title_families_are_all_claimed(self) -> None:
        """Every collapsing prefix in overrides.py maps onto some registry rule.

        A prefix with no owner would mean a rule an analyst can suppress per-case but
        cannot find on the Rules page.
        """
        from app.detect.overrides import _VARIABLE_TITLE_RULES

        unclaimed = [
            legacy
            for _prefix, legacy in _VARIABLE_TITLE_RULES
            if legacy not in LEGACY_TO_REGISTRY
        ]
        self.assertEqual(unclaimed, [])

    def test_web_rules_use_the_web_prefixed_legacy_id(self) -> None:
        for spec in BUILTIN_RULES:
            if spec.kind not in ("web-request", "web-ua"):
                continue
            with self.subTest(rule=spec.id):
                for legacy in spec.legacy_rule_ids:
                    self.assertTrue(legacy.startswith("web-"), legacy)

    def test_duplicate_descriptions_collapse_into_one_rule(self) -> None:
        """Rows sharing a description are one rule, because findings dedupe by title.

        SUSPICIOUS_CMDLINE_PATTERNS carries 98 patterns under 94 descriptions; the
        four repeats must not become four separately-togglable rules that both claim
        the same legacy id.
        """
        spec = RULES_BY_ID["cmdline.win.powershell-encoded-command"]
        self.assertGreater(len(spec.source_indices), 1)
        for index in spec.source_indices:
            self.assertEqual(
                R.SUSPICIOUS_CMDLINE_PATTERNS[index][2], "PowerShell encoded command"
            )


class EditabilityTests(unittest.TestCase):
    def test_titles_are_never_editable(self) -> None:
        """Renaming a rule would orphan every persisted override that keys on it."""
        for spec in BUILTIN_RULES:
            self.assertNotIn("title", spec.editable)
            self.assertNotIn("description", spec.editable)

    def test_stateful_engine_rules_are_not_forkable(self) -> None:
        for spec in BUILTIN_RULES:
            if spec.kind == "engine":
                self.assertFalse(spec.forkable, spec.id)


if __name__ == "__main__":
    unittest.main()
