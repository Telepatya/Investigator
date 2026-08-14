"""The rule set a detection run executes against.

A ``RuleProfile`` is an immutable snapshot combining the built-in rule tables (minus
anything the analyst disabled, plus any severity overrides) with the compiled custom
Sigma rules. ``run_detections_sync`` takes one snapshot at the start of a run and
threads it down, so a rule change mid-run can never make a case's findings
internally inconsistent.

Three properties are deliberate and each is pinned by a test:

* **The default profile holds the module tables themselves**, not copies. With no
  global rule state, the engine iterates the exact same list objects it always did,
  so behavior and memory are unchanged and the existing corpus tests keep comparing
  like with like.
* **A default installation costs one ``stat``.** ``load_profile`` checks whether the
  rules database file exists before opening anything.
* **Disabling a rule removes work.** A disabled rule is filtered out of its table
  before the run, so it costs one fewer regex search per subject rather than being
  demoted after the fact. That is the opposite of the per-case ``disabled_rules``
  mechanism, which stays exactly as it was.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Mapping, Sequence

from app.detect import rules as R
from app.rules import limits
from app.rules.registry import BUILTIN_RULES, RULES_BY_ID, RuleSpec
from app.rules.sigma_compile import CompiledRule

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CustomRuleSet:
    """Compiled custom rules, split by whether a literal gate could be derived."""

    gated: tuple[CompiledRule, ...] = ()
    ungated: tuple[CompiledRule, ...] = ()
    prefilter: re.Pattern[str] | None = None

    @property
    def empty(self) -> bool:
        return not self.gated and not self.ungated

    def candidates(self, blob: str) -> tuple[CompiledRule, ...]:
        """Rules worth evaluating for a subject whose searchable text is ``blob``.

        The gate mirrors ``_check_cmdline_impl``: one cheap alternation search
        decides whether any gated rule can possibly match, and rules with no
        derivable literal are always considered.
        """
        if self.prefilter is None or not self.prefilter.search(blob):
            return self.ungated
        matched = tuple(
            rule for rule in self.gated if any(literal in blob for literal in rule.literals)
        )
        return self.ungated + matched


EMPTY_CUSTOM_RULES = CustomRuleSet()


@dataclass(frozen=True, slots=True)
class RuleProfile:
    """Everything a detection run needs to know about which rules are active."""

    revision: int
    win_cmdline: Sequence[tuple[Any, str, str, str]]
    linux_cmdline: Sequence[tuple[Any, str, str, str]]
    lolbins: Mapping[str, tuple[str, str]]
    parent_child: Mapping[tuple[str, str], tuple[str, str]]
    system_process_paths: Mapping[str, str]
    exec_dirs: Sequence[str]
    registry_persistence: Sequence[tuple[str, str, str]]
    linux_persistence: Sequence[tuple[str, str, str, str]]
    web_attacks: Sequence[tuple[Any, str, str, str]]
    web_user_agents: Sequence[tuple[str, str, str, str]]
    # Legacy rule ids that are fully disabled, applied centrally in ``_add_finding``
    # — the one place that sees every finding's title, and therefore the only place
    # that can cover detections implemented as imperative engine code rather than as
    # table rows. Table filtering above is the performance path; this is the
    # correctness backstop, and the two agree by construction.
    disabled_legacy_ids: frozenset[str] = frozenset()
    severity_overrides: Mapping[str, str] = field(default_factory=dict)
    custom: CustomRuleSet = EMPTY_CUSTOM_RULES
    is_default: bool = False


DEFAULT_PROFILE = RuleProfile(
    revision=0,
    # Identity, not copies: with no overrides the engine must touch the very same
    # objects it does today.
    win_cmdline=R.SUSPICIOUS_CMDLINE_PATTERNS,
    linux_cmdline=R.LINUX_SUSPICIOUS_CMDLINE_PATTERNS,
    lolbins=R.LOLBINS,
    parent_child=R.SUSPICIOUS_PARENT_CHILD_MAP,
    system_process_paths=R.SYSTEM_PROCESS_PATHS,
    exec_dirs=R.SUSPICIOUS_EXECUTION_DIRS,
    registry_persistence=R.PERSISTENCE_REGISTRY_PATHS,
    linux_persistence=R.LINUX_PERSISTENCE_PATHS,
    web_attacks=R.WEB_ATTACK_PATTERNS,
    web_user_agents=R.WEB_USER_AGENT_PATTERNS,
    custom=EMPTY_CUSTOM_RULES,
    is_default=True,
)

_cache_lock = RLock()
_cached_profile: RuleProfile | None = None


def _effective_disabled(states: Mapping[str, bool]) -> set[str]:
    """Registry ids that are inactive, resolving the family/member relationship.

    A member rule is only active when its family is active, so disabling the
    ``lolbin`` family switches off all 33 members without needing 33 rows.
    """
    disabled: set[str] = {
        rule_id for rule_id, enabled in states.items() if not enabled and rule_id in RULES_BY_ID
    }
    disabled_families = {rule_id for rule_id in disabled if RULES_BY_ID[rule_id].family is None}
    for spec in BUILTIN_RULES:
        if spec.family and spec.family in disabled_families:
            disabled.add(spec.id)
    return disabled


def _filter_sequence(
    table: Sequence[Any],
    specs: list[RuleSpec],
    disabled: set[str],
    severity_index: int | None,
    severity_overrides: Mapping[str, str],
) -> Sequence[Any]:
    """Drop disabled rows and apply severity overrides, or return the table as-is."""
    drop: set[int] = set()
    retint: dict[int, str] = {}
    for spec in specs:
        if spec.id in disabled:
            drop.update(spec.source_indices)
        elif spec.id in severity_overrides and severity_index is not None:
            for index in spec.source_indices:
                retint[index] = severity_overrides[spec.id]
    if not drop and not retint:
        return table
    rebuilt = []
    for index, row in enumerate(table):
        if index in drop:
            continue
        if index in retint:
            row = tuple(row)
            row = row[:severity_index] + (retint[index],) + row[severity_index + 1 :]
        rebuilt.append(row)
    return tuple(rebuilt)


def _specs_for(table_name: str) -> list[RuleSpec]:
    return [spec for spec in BUILTIN_RULES if spec.source_table == table_name]


def _filter_mapping(
    table: Mapping[Any, Any], table_name: str, disabled: set[str]
) -> Mapping[Any, Any]:
    drop = {
        spec.source_key
        for spec in _specs_for(table_name)
        if spec.source_key and spec.id in disabled
    }
    if not drop:
        return table
    return {key: value for key, value in table.items() if key not in drop}


def _filter_parent_child(disabled: set[str]) -> Mapping[tuple[str, str], tuple[str, str]]:
    drop: set[int] = set()
    for spec in _specs_for("SUSPICIOUS_PARENT_CHILD"):
        if spec.id in disabled:
            drop.update(spec.source_indices)
    if not drop:
        return R.SUSPICIOUS_PARENT_CHILD_MAP
    return {
        (parent, child): (technique, description)
        for index, (parent, child, technique, description) in enumerate(R.SUSPICIOUS_PARENT_CHILD)
        if index not in drop
    }


def _filter_exec_dirs(disabled: set[str]) -> Sequence[str]:
    drop: set[int] = set()
    for spec in _specs_for("SUSPICIOUS_EXECUTION_DIRS"):
        if spec.id in disabled:
            drop.update(spec.source_indices)
    if not drop:
        return R.SUSPICIOUS_EXECUTION_DIRS
    return tuple(
        directory
        for index, directory in enumerate(R.SUSPICIOUS_EXECUTION_DIRS)
        if index not in drop
    )


def build_profile(
    revision: int,
    states: Mapping[str, bool],
    severity_overrides: Mapping[str, str],
    custom: CustomRuleSet,
) -> RuleProfile:
    """Assemble a profile from global rule state. Pure; does no I/O."""
    disabled = _effective_disabled(states)
    if not disabled and not severity_overrides and custom.empty:
        return DEFAULT_PROFILE

    # A legacy id may be shared by a whole family (all 33 LOLBins report as
    # "lolbin-activity"). Suppressing centrally on that id would switch off every
    # member, so an id only qualifies once *every* rule that can emit it is
    # disabled. Disabling a single member is handled by table filtering instead.
    owners: dict[str, list[str]] = {}
    for spec in BUILTIN_RULES:
        for legacy in spec.legacy_rule_ids:
            owners.setdefault(legacy, []).append(spec.id)
    disabled_legacy = frozenset(
        legacy
        for legacy, rule_ids in owners.items()
        if all(rule_id in disabled for rule_id in rule_ids)
    )

    legacy_severity: dict[str, str] = {}
    for spec in BUILTIN_RULES:
        if spec.id not in severity_overrides:
            continue
        for legacy in spec.legacy_rule_ids:
            # Only apply centrally where the legacy id is unambiguous; a shared id
            # would otherwise re-severitise sibling rules that were not touched.
            if len(owners.get(legacy, ())) == 1:
                legacy_severity[legacy] = severity_overrides[spec.id]

    return RuleProfile(
        revision=revision,
        win_cmdline=_filter_sequence(
            R.SUSPICIOUS_CMDLINE_PATTERNS,
            _specs_for("SUSPICIOUS_CMDLINE_PATTERNS"),
            disabled,
            3,
            severity_overrides,
        ),
        linux_cmdline=_filter_sequence(
            R.LINUX_SUSPICIOUS_CMDLINE_PATTERNS,
            _specs_for("LINUX_SUSPICIOUS_CMDLINE_PATTERNS"),
            disabled,
            3,
            severity_overrides,
        ),
        lolbins=_filter_mapping(R.LOLBINS, "LOLBINS", disabled),
        parent_child=_filter_parent_child(disabled),
        system_process_paths=_filter_mapping(
            R.SYSTEM_PROCESS_PATHS, "SYSTEM_PROCESS_PATHS", disabled
        ),
        exec_dirs=_filter_exec_dirs(disabled),
        registry_persistence=_filter_sequence(
            R.PERSISTENCE_REGISTRY_PATHS,
            _specs_for("PERSISTENCE_REGISTRY_PATHS"),
            disabled,
            None,
            severity_overrides,
        ),
        linux_persistence=_filter_sequence(
            R.LINUX_PERSISTENCE_PATHS,
            _specs_for("LINUX_PERSISTENCE_PATHS"),
            disabled,
            3,
            severity_overrides,
        ),
        web_attacks=_filter_sequence(
            R.WEB_ATTACK_PATTERNS, _specs_for("WEB_ATTACK_PATTERNS"), disabled, 3, severity_overrides
        ),
        web_user_agents=_filter_sequence(
            R.WEB_USER_AGENT_PATTERNS,
            _specs_for("WEB_USER_AGENT_PATTERNS"),
            disabled,
            3,
            severity_overrides,
        ),
        disabled_legacy_ids=disabled_legacy,
        severity_overrides=legacy_severity,
        custom=custom,
        is_default=False,
    )


def build_custom_rule_set(compiled: Sequence[CompiledRule]) -> CustomRuleSet:
    """Split compiled rules into gated and ungated buckets and build the prefilter."""
    gated: list[CompiledRule] = []
    ungated: list[CompiledRule] = []
    literals: set[str] = set()
    for rule in compiled:
        if rule.literals:
            gated.append(rule)
            literals |= set(rule.literals)
        else:
            ungated.append(rule)
    prefilter = (
        re.compile("|".join(re.escape(literal) for literal in sorted(literals)))
        if literals
        else None
    )
    return CustomRuleSet(gated=tuple(gated), ungated=tuple(ungated), prefilter=prefilter)


def load_profile() -> RuleProfile:
    """Current rule profile, cached until the global revision changes."""
    from app.rules.database import rules_db_exists

    if not rules_db_exists():
        # Nothing has ever been customized: skip the database entirely.
        return DEFAULT_PROFILE

    from app.rules import store

    try:
        revision = store.current_revision()
    except Exception:  # pragma: no cover - a broken store must not stop detections
        logger.exception("Could not read the rules revision; using built-in rules")
        return DEFAULT_PROFILE

    global _cached_profile
    with _cache_lock:
        cached = _cached_profile
        if cached is not None and cached.revision == revision:
            return cached
    try:
        states, severities, compiled = store.load_active_state()
    except Exception:  # pragma: no cover - as above
        logger.exception("Could not load global rule state; using built-in rules")
        return DEFAULT_PROFILE

    if len(compiled) > limits.MAX_ENABLED_CUSTOM_RULES:
        logger.warning(
            "Ignoring %d custom rules beyond the %d limit",
            len(compiled) - limits.MAX_ENABLED_CUSTOM_RULES,
            limits.MAX_ENABLED_CUSTOM_RULES,
        )
        compiled = compiled[: limits.MAX_ENABLED_CUSTOM_RULES]

    profile = build_profile(revision, states, severities, build_custom_rule_set(compiled))
    with _cache_lock:
        _cached_profile = profile
    return profile


def invalidate_cache() -> None:
    """Drop the cached profile so the next run rebuilds it."""
    global _cached_profile
    with _cache_lock:
        _cached_profile = None
