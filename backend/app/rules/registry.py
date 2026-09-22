"""Catalog of the built-in detection rules.

The detection engine's rules live as Python literals in ``app.detect.rules`` and as
imperative blocks in ``app.detect.engine``. This module reads those tables and
presents them as one uniform, addressable catalog so the Rules page can list, filter
and toggle them. It deliberately does **not** re-express any rule: it holds
references to the already-compiled ``re.Pattern`` objects, so building the catalog
allocates a few hundred frozen dataclasses and compiles nothing.

Two identifier spaces meet here, and keeping them straight is the whole job:

* **Registry id** (``RuleSpec.id``) is new, fine-grained and stable — one id per
  individually togglable rule, e.g. ``lolbin.certutil``.
* **Legacy rule id** is what ``overrides.rule_id_for()`` already derives from a
  finding's *title*, and what is already persisted in every existing case's
  ``case_meta["disabled_rules"]``. Several registry rules can share one legacy id
  (all 33 LOLBins collapse to ``lolbin-activity``), which is exactly why the
  registry needs its own space.

``legacy_rule_ids`` is always *computed* by calling ``overrides.rule_id_for()`` with
the title the engine actually emits — never written by hand — so the two can not
drift apart silently.

Where a table's members all collapse to a single legacy id, the catalog emits a
**family** rule plus one **member** rule per entry. A member is only active when its
family is also active, so an existing per-case disable of the family id keeps
suppressing the whole group while the Rules page still offers per-member control.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable

from app.detect import rules as R
from app.detect.overrides import _slug, rule_id_for

# Rule kinds. These drive the family grouping in the UI and the fork templates.
KIND_CMDLINE = "cmdline"
KIND_LOLBIN = "lolbin"
KIND_PARENT_CHILD = "parent-child"
KIND_MASQUERADE = "masquerade"
KIND_EXEC_DIR = "exec-dir"
KIND_REGISTRY_PERSISTENCE = "registry-persistence"
KIND_LINUX_PERSISTENCE = "linux-persistence"
KIND_WEB_REQUEST = "web-request"
KIND_WEB_UA = "web-ua"
KIND_ENGINE = "engine"

# Metadata an analyst may change on a built-in. Title and description are absent on
# purpose: the description *is* the finding title, and the finding title is what
# every existing case's persisted overrides key on. Renaming one would orphan them.
_METADATA_EDITABLE = frozenset({"enabled", "severity", "techniques", "note"})
_ENABLE_ONLY = frozenset({"enabled", "note"})


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """One individually togglable built-in detection rule."""

    id: str
    title: str
    kind: str
    platform: str  # windows | linux | web | any
    severity: str
    techniques: tuple[str, ...]
    logic: str  # human-readable source: regex text, path fragment, or process pair
    source_table: str
    # Indices into ``source_table`` this rule owns. Several tables carry more than
    # one pattern under the same description (98 command-line patterns share 94
    # descriptions); those are one *rule* with several *patterns*, because findings
    # dedupe by title and the legacy id is a slug of the description.
    source_indices: tuple[int, ...] = ()
    # For tables that are mappings rather than sequences (``LOLBINS``,
    # ``SYSTEM_PROCESS_PATHS``), the key this rule owns.
    source_key: str = ""
    legacy_rule_ids: tuple[str, ...] = ()
    family: str | None = None
    editable: frozenset[str] = field(default=_METADATA_EDITABLE)
    forkable: bool = True
    description: str = ""


def _slug_tail(text: str) -> str:
    """Namespace-safe slug for the trailing component of a registry id.

    Uses ``overrides._slug`` rather than ``rule_id_for``: the latter also folds the
    ``_VARIABLE_TITLE_RULES`` prefixes, which is correct for a *finding title* but
    would silently collapse unrelated rule descriptions into one id here.
    """
    return _slug(text)


def _stem(name: str) -> str:
    """``certutil.exe`` -> ``certutil``; used to keep member ids readable."""
    base = (name or "").rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    return _slug_tail(base.removesuffix(".exe"))


@dataclass(frozen=True, slots=True)
class _Group:
    """Rows of one table that constitute a single togglable rule."""

    slug: str
    title: str  # representative description
    descriptions: tuple[str, ...]  # every distinct description in the group
    indices: tuple[int, ...]


def _group_rows(table: Iterable[tuple[Any, ...]], desc_index: int) -> list[_Group]:
    """Group a table's rows into rules, keyed by the slug of their description.

    Grouping on the *slug* rather than the raw description is deliberate. Several
    tables carry more than one pattern under the same description (98 command-line
    patterns share 94 descriptions), and ``WEB_ATTACK_PATTERNS`` carries two
    descriptions that differ only in a character the slug drops
    (``Path traversal (encoded ../)`` and ``...(encoded ..\\)``). Both cases are
    already a single rule as far as the persisted per-case overrides are concerned,
    because those key on the slug — so the registry must agree.
    """
    order: list[str] = []
    rows_by_slug: dict[str, list[int]] = {}
    descs_by_slug: dict[str, list[str]] = {}
    for index, row in enumerate(table):
        description = str(row[desc_index])
        slug = _slug(description)
        if slug not in rows_by_slug:
            rows_by_slug[slug] = []
            descs_by_slug[slug] = []
            order.append(slug)
        rows_by_slug[slug].append(index)
        if description not in descs_by_slug[slug]:
            descs_by_slug[slug].append(description)
    return [
        _Group(
            slug=slug,
            title=descs_by_slug[slug][0],
            descriptions=tuple(descs_by_slug[slug]),
            indices=tuple(rows_by_slug[slug]),
        )
        for slug in order
    ]


def _pattern_text(value: Any) -> str:
    """Readable logic for a row whose matcher may be a regex or a plain substring."""
    return getattr(value, "pattern", None) or str(value)


# --- per-table builders ------------------------------------------------------


def _legacy_ids(descriptions: Iterable[str], template: str = "{}") -> tuple[str, ...]:
    """Legacy ids for a group, derived from the titles the engine actually emits."""
    seen: list[str] = []
    for description in descriptions:
        legacy = rule_id_for(template.format(description))
        if legacy not in seen:
            seen.append(legacy)
    return tuple(seen)


def _build_cmdline(table, table_name: str, platform: str, prefix: str) -> list[RuleSpec]:
    specs: list[RuleSpec] = []
    for group in _group_rows(table, 2):
        rows = [table[i] for i in group.indices]
        # Rows in a group share technique and severity; take the first and keep
        # every pattern in the logic text so the analyst sees what actually fires.
        _, technique, _, severity = rows[0]
        specs.append(
            RuleSpec(
                id=f"{prefix}.{group.slug}",
                title=group.title,
                kind=KIND_CMDLINE,
                platform=platform,
                severity=severity,
                techniques=(technique,),
                logic="\n".join(_pattern_text(row[0]) for row in rows),
                source_table=table_name,
                source_indices=group.indices,
                # The engine passes title=description for these rules.
                legacy_rule_ids=_legacy_ids(group.descriptions),
                description=f"Command-line pattern ({platform}).",
            )
        )
    return specs


def _build_lolbins() -> list[RuleSpec]:
    family_legacy = (rule_id_for("LOLBin activity: example.exe"),)
    specs = [
        RuleSpec(
            id="lolbin",
            title="LOLBin activity",
            kind=KIND_LOLBIN,
            platform="windows",
            severity="medium",
            techniques=(),
            logic=f"{len(R.LOLBINS)} living-off-the-land binaries",
            source_table="LOLBINS",
            legacy_rule_ids=family_legacy,
            editable=_ENABLE_ONLY,
            forkable=False,
            description="Parent switch for every living-off-the-land binary rule.",
        )
    ]
    for name, (technique, desc) in R.LOLBINS.items():
        specs.append(
            RuleSpec(
                id=f"lolbin.{_stem(name)}",
                title=f"LOLBin: {name}",
                kind=KIND_LOLBIN,
                platform="windows",
                severity="low" if name in R.LOW_SIGNAL_LOLBINS else "medium",
                techniques=(technique,),
                logic=f"{name} invoked with arguments — {desc}",
                source_table="LOLBINS",
                source_key=name,
                legacy_rule_ids=family_legacy,
                family="lolbin",
                description=desc,
            )
        )
    return specs


def _build_parent_child() -> list[RuleSpec]:
    family_legacy = (rule_id_for("Suspicious process chain: a.exe -> b.exe"),)
    specs = [
        RuleSpec(
            id="parent-child",
            title="Suspicious process chain",
            kind=KIND_PARENT_CHILD,
            platform="windows",
            severity="high",
            techniques=(),
            logic=f"{len(R.SUSPICIOUS_PARENT_CHILD)} parent/child pairs",
            source_table="SUSPICIOUS_PARENT_CHILD",
            legacy_rule_ids=family_legacy,
            editable=_ENABLE_ONLY,
            forkable=False,
            description="Parent switch for every suspicious parent/child process pair.",
        )
    ]
    for index, (parent, child, technique, desc) in enumerate(R.SUSPICIOUS_PARENT_CHILD):
        specs.append(
            RuleSpec(
                id=f"parent-child.{_stem(parent)}--{_stem(child)}",
                title=f"Process chain: {parent} -> {child}",
                kind=KIND_PARENT_CHILD,
                platform="windows",
                severity="high",
                techniques=(technique,),
                logic=f"{parent} spawning {child}",
                source_table="SUSPICIOUS_PARENT_CHILD",
                source_indices=(index,),
                legacy_rule_ids=family_legacy,
                family="parent-child",
                description=desc,
            )
        )
    return specs


def _build_masquerade() -> list[RuleSpec]:
    family_legacy = (rule_id_for("System process masquerade: svchost.exe"),)
    specs = [
        RuleSpec(
            id="masquerade",
            title="System process masquerade",
            kind=KIND_MASQUERADE,
            platform="windows",
            severity="high",
            techniques=("T1036",),
            logic=f"{len(R.SYSTEM_PROCESS_PATHS)} system processes with an expected image path",
            source_table="SYSTEM_PROCESS_PATHS",
            legacy_rule_ids=family_legacy,
            editable=_ENABLE_ONLY,
            forkable=False,
            description="Parent switch for system-process path masquerade checks.",
        )
    ]
    for name, expected in R.SYSTEM_PROCESS_PATHS.items():
        specs.append(
            RuleSpec(
                id=f"masquerade.{_stem(name)}",
                title=f"Masquerade: {name}",
                kind=KIND_MASQUERADE,
                platform="windows",
                severity="high",
                techniques=("T1036",),
                logic=f"{name} running from a path not containing '{expected}'",
                source_table="SYSTEM_PROCESS_PATHS",
                source_key=name,
                legacy_rule_ids=family_legacy,
                family="masquerade",
                description=f"{name} is expected under '{expected}'.",
            )
        )
    return specs


def _build_exec_dirs() -> list[RuleSpec]:
    family_legacy = (rule_id_for("Execution from suspicious directory: a.exe"),)
    specs = [
        RuleSpec(
            id="exec-dir",
            title="Execution from suspicious directory",
            kind=KIND_EXEC_DIR,
            platform="windows",
            severity="medium",
            techniques=("T1036",),
            logic=f"{len(R.SUSPICIOUS_EXECUTION_DIRS)} user-writable directories",
            source_table="SUSPICIOUS_EXECUTION_DIRS",
            legacy_rule_ids=family_legacy,
            editable=_ENABLE_ONLY,
            forkable=False,
            description="Parent switch for execution-from-suspicious-directory checks.",
        )
    ]
    for index, directory in enumerate(R.SUSPICIOUS_EXECUTION_DIRS):
        specs.append(
            RuleSpec(
                id=f"exec-dir.{_slug_tail(directory)}",
                title=f"Execution from {directory}",
                kind=KIND_EXEC_DIR,
                platform="windows",
                severity="medium",
                techniques=("T1036",),
                logic=directory,
                source_table="SUSPICIOUS_EXECUTION_DIRS",
                source_indices=(index,),
                legacy_rule_ids=family_legacy,
                family="exec-dir",
                description=f"Image path contains '{directory}'.",
            )
        )
    return specs


def _build_registry_persistence() -> list[RuleSpec]:
    specs: list[RuleSpec] = []
    for group in _group_rows(R.PERSISTENCE_REGISTRY_PATHS, 2):
        rows = [R.PERSISTENCE_REGISTRY_PATHS[i] for i in group.indices]
        specs.append(
            RuleSpec(
                id=f"registry-persistence.{group.slug}",
                title=group.title,
                kind=KIND_REGISTRY_PERSISTENCE,
                platform="windows",
                # This table carries no severity column; the engine hardcodes "high".
                severity="high",
                techniques=(rows[0][1],),
                logic="\n".join(str(row[0]) for row in rows),
                source_table="PERSISTENCE_REGISTRY_PATHS",
                source_indices=group.indices,
                # Emitted both as a bare description and via the MemProcFS timeline path.
                legacy_rule_ids=(
                    _legacy_ids(group.descriptions)
                    + _legacy_ids(group.descriptions, "MemProcFS timeline: {}")
                ),
                description="Registry persistence location touched.",
            )
        )
    return specs


def _build_linux_persistence() -> list[RuleSpec]:
    specs: list[RuleSpec] = []
    for group in _group_rows(R.LINUX_PERSISTENCE_PATHS, 2):
        rows = [R.LINUX_PERSISTENCE_PATHS[i] for i in group.indices]
        specs.append(
            RuleSpec(
                id=f"linux-persistence.{group.slug}",
                title=group.title,
                kind=KIND_LINUX_PERSISTENCE,
                platform="linux",
                severity=rows[0][3],
                techniques=(rows[0][1],),
                logic="\n".join(str(row[0]) for row in rows),
                source_table="LINUX_PERSISTENCE_PATHS",
                source_indices=group.indices,
                legacy_rule_ids=_legacy_ids(group.descriptions),
                description="Linux persistence location written.",
            )
        )
    return specs


def _build_web(table, table_name: str, kind: str, prefix: str) -> list[RuleSpec]:
    specs: list[RuleSpec] = []
    for group in _group_rows(table, 2):
        rows = [table[i] for i in group.indices]
        specs.append(
            RuleSpec(
                id=f"{prefix}.{group.slug}",
                title=group.title,
                kind=kind,
                platform="web",
                severity=rows[0][3],
                techniques=(rows[0][1],),
                logic="\n".join(_pattern_text(row[0]) for row in rows),
                source_table=table_name,
                source_indices=group.indices,
                # Both web tables report through the same "Web attack: ..." title.
                legacy_rule_ids=_legacy_ids(group.descriptions, "Web attack: {}"),
                description="Web request signature.",
            )
        )
    return specs


# Detections implemented as imperative blocks in ``engine.py`` rather than as table
# rows. They can be enabled/disabled and re-severitied centrally in ``_add_finding``
# (which sees every finding's title), but they have no pattern to fork.
_ENGINE_RULES: tuple[tuple[str, str, str, str, tuple[str, ...]], ...] = (
    # (title template as emitted, kind label, platform, severity, techniques)
    ("Security event log cleared", "Defense evasion", "windows", "high", ("T1070.001",)),
    ("New user account created", "Persistence", "windows", "medium", ("T1136.001",)),
    ("New service installed", "Persistence", "windows", "high", ("T1543.003",)),
    ("Boot config weakens driver signing (Event 4826)", "Defense evasion", "windows", "high", ("T1553.006",)),
    ("Remote thread creation", "Process injection", "windows", "high", ("T1055",)),
    ("Suspicious process access", "Credential access", "windows", "high", ("T1003",)),
    ("Suspicious cross-process handle", "Process injection", "windows", "high", ("T1055",)),
    ("USN Journal: file renamed to executable/script extension", "Masquerading", "windows", "medium", ("T1036.003",)),
    ("Cron job modified", "Persistence", "linux", "medium", ("T1053.003",)),
    ("Suspicious domain indicator: example.com", "Network", "any", "medium", ()),
    ("Random-looking executable in Windows root: a.exe", "Masquerading", "windows", "high", ("T1036",)),
    ("Service-hosted executable in Windows root: a.exe", "Masquerading", "windows", "high", ("T1036",)),
    ("Unresolved parentage for a.exe", "Process anomaly", "windows", "low", ()),
    ("Anomalous parent for a.exe", "Process anomaly", "windows", "medium", ()),
    ("Correlated indicators on a.exe (pid 1)", "Correlation", "any", "high", ()),
    ("File artifact later executed: a.exe", "Correlation", "windows", "high", ()),
    ("Persistence artifact executed: a.exe", "Correlation", "windows", "high", ()),
    ("Service provenance traced: svc", "Correlation", "windows", "medium", ()),
    ("RemCom named-pipe activity by a.exe (pid 1)", "Lateral movement", "windows", "high", ("T1570",)),
    ("Web scanning / enumeration from 1.2.3.4", "Reconnaissance", "web", "medium", ()),
    ("Brute force followed by successful logon: combo", "Credential access", "any", "high", ("T1110",)),
    ("Authentication brute force attempts: combo", "Credential access", "any", "medium", ("T1110",)),
    ("RDP logon by account referenced in other findings: x", "Lateral movement", "windows", "medium", ()),
    ("Special-privilege logon by account referenced in other findings: x", "Privilege escalation", "windows", "medium", ()),
    ("Root login: combo", "Privilege escalation", "linux", "medium", ()),
    ("Risky Entra sign-in: user", "Cloud identity", "any", "medium", ()),
    ("Linux user account created: name", "Persistence", "linux", "medium", ("T1136",)),
    ("User added to privileged group: name -> group", "Privilege escalation", "linux", "high", ("T1098",)),
)


def _build_engine_rules() -> list[RuleSpec]:
    specs: list[RuleSpec] = []
    for title_sample, label, platform, severity, techniques in _ENGINE_RULES:
        legacy = rule_id_for(title_sample)
        specs.append(
            RuleSpec(
                id=f"engine.{legacy}",
                title=title_sample.split(":")[0].strip(),
                kind=KIND_ENGINE,
                platform=platform,
                severity=severity,
                techniques=techniques,
                logic="Implemented in the detection engine (stateful or multi-signal).",
                source_table="engine",
                legacy_rule_ids=(legacy,),
                # Correlation and threshold logic has no single-event Sigma equivalent.
                forkable=False,
                description=label,
            )
        )
    return specs


# --- catalog assembly --------------------------------------------------------


def _build_catalog() -> tuple[RuleSpec, ...]:
    specs: list[RuleSpec] = []
    specs += _build_cmdline(
        R.SUSPICIOUS_CMDLINE_PATTERNS, "SUSPICIOUS_CMDLINE_PATTERNS", "windows", "cmdline.win"
    )
    specs += _build_cmdline(
        R.LINUX_SUSPICIOUS_CMDLINE_PATTERNS,
        "LINUX_SUSPICIOUS_CMDLINE_PATTERNS",
        "linux",
        "cmdline.linux",
    )
    specs += _build_lolbins()
    specs += _build_parent_child()
    specs += _build_masquerade()
    specs += _build_exec_dirs()
    specs += _build_registry_persistence()
    specs += _build_linux_persistence()
    specs += _build_web(R.WEB_ATTACK_PATTERNS, "WEB_ATTACK_PATTERNS", KIND_WEB_REQUEST, "web.request")
    specs += _build_web(R.WEB_USER_AGENT_PATTERNS, "WEB_USER_AGENT_PATTERNS", KIND_WEB_UA, "web.ua")
    specs += _build_engine_rules()

    seen: dict[str, RuleSpec] = {}
    for spec in specs:
        if spec.id in seen:
            raise RuntimeError(f"Duplicate built-in rule id: {spec.id}")
        seen[spec.id] = spec
    return tuple(specs)


BUILTIN_RULES: tuple[RuleSpec, ...] = _build_catalog()
RULES_BY_ID: dict[str, RuleSpec] = {spec.id: spec for spec in BUILTIN_RULES}

# Legacy id -> the registry rules that can emit it. Lets the Rules page show that a
# rule is also suppressed inside a particular case, and lets the engine translate a
# global disable of a family into the table filtering it implies.
LEGACY_TO_REGISTRY: dict[str, tuple[str, ...]] = {}
for _spec in BUILTIN_RULES:
    for _legacy in _spec.legacy_rule_ids:
        LEGACY_TO_REGISTRY[_legacy] = LEGACY_TO_REGISTRY.get(_legacy, ()) + (_spec.id,)


def members_of(family_id: str) -> tuple[RuleSpec, ...]:
    return tuple(spec for spec in BUILTIN_RULES if spec.family == family_id)


def registry_fingerprint() -> str:
    """Digest over every rule id, so a catalog change invalidates cached state."""
    digest = hashlib.sha256()
    for spec in sorted(BUILTIN_RULES, key=lambda item: item.id):
        digest.update(spec.id.encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()
