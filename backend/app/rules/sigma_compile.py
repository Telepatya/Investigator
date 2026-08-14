"""Compile Sigma rules into in-memory matchers.

Parsing is delegated to pySigma, the reference implementation of the Sigma
specification, so a rule pasted from a public feed is interpreted exactly as its
author intended. pySigma also resolves every value modifier down to a small set of
value types before we ever see it — ``|contains`` becomes a wildcarded string,
``|base64offset`` and ``|windash`` become an expansion of alternatives, ``|all``
becomes a conjunction — which leaves this module a genuinely small job: turn the
parsed condition tree into a Python closure.

Two properties are load-bearing:

* **No code generation.** The condition tree is compiled into nested closures. There
  is no ``eval``, no ``exec``, and no string is ever assembled into Python source.
  The only dynamic compilation is ``re.compile`` for an explicit ``|re`` value, and
  that goes through ``safe_regex`` first.
* **Unsupported means refused, not ignored.** A construct this build cannot execute
  raises with the construct named, at save time. A rule that silently never matches
  is the failure mode this design exists to avoid.

Alongside the predicate, compilation derives the set of literal strings a subject
must contain for the rule to have any chance of matching. That set becomes a cheap
prefilter gate, mirroring the ``_CMDLINE_PREFILTER_RE`` optimization the built-in
engine already relies on.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Callable

import yaml
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaError as PySigmaError
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaQueryExpression,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from app.rules import limits
from app.rules.fieldmap import MatchCtx, is_known_field, logsource_predicate
from app.rules.safe_regex import UnsafeRegexError, bounded_search, compile_bounded

_SEVERITY_BY_LEVEL = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}
_ATTACK_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_ANCHOR_RE = re.compile(r"(?m)(?:^|\s)[&*][A-Za-z0-9_-]+")

Predicate = Callable[[MatchCtx], bool]
# A literal set of ``None`` means "no sound literal constraint could be derived":
# the rule may match a subject containing none of any particular string, so it can
# not be placed behind the prefilter gate.
Literals = frozenset[str] | None


class SigmaRuleError(ValueError):
    """Base class for every rejection an analyst should see verbatim."""


class SigmaSyntaxError(SigmaRuleError):
    """The document is not a well-formed Sigma rule."""


class SigmaUnsupportedError(SigmaRuleError):
    """A valid Sigma construct this build cannot execute."""


class SigmaLimitError(SigmaRuleError):
    """A cap from ``app.rules.limits`` was exceeded."""


@dataclass(frozen=True, slots=True)
class CompiledRule:
    """A Sigma rule ready to be evaluated against processes and events."""

    rule_id: str
    slug: str
    title: str
    severity: str
    techniques: tuple[str, ...]
    description: str
    predicate: Predicate
    logsource_gate: Predicate
    logsource_label: str
    literals: frozenset[str]
    warnings: tuple[str, ...]
    unmapped_fields: tuple[str, ...]
    yaml_source: str
    content_sha256: str

    @property
    def gated(self) -> bool:
        """Whether a literal prefilter could be derived for this rule."""
        return bool(self.literals)


# --- source-level guards -----------------------------------------------------


def _check_source(text: str) -> None:
    encoded = text.encode("utf-8", errors="ignore")
    if len(encoded) > limits.MAX_YAML_BYTES:
        raise SigmaLimitError(
            f"Rule is {len(encoded)} bytes; the limit is {limits.MAX_YAML_BYTES}"
        )
    # PyYAML's safe loader still expands anchors and aliases, so a small document can
    # inflate to an enormous object graph. Sigma rules never need anchors, so the
    # whole class is refused at the source level rather than measured afterwards.
    if _ANCHOR_RE.search(text):
        raise SigmaLimitError(
            "YAML anchors and aliases are not accepted in rule sources"
        )


def _check_shape(text: str) -> None:
    """Walk the loaded document to bound its depth and node count."""
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise SigmaSyntaxError(f"Invalid YAML: {exc}") from exc

    nodes = 0

    def walk(node: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > limits.MAX_YAML_DEPTH:
            raise SigmaLimitError(f"Rule nests deeper than {limits.MAX_YAML_DEPTH} levels")
        if nodes > limits.MAX_YAML_NODES:
            raise SigmaLimitError(f"Rule has more than {limits.MAX_YAML_NODES} nodes")
        if isinstance(node, dict):
            for key, value in node.items():
                walk(key, depth + 1)
                walk(value, depth + 1)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item, depth + 1)

    for document in documents:
        if document is not None:
            walk(document, 0)


# --- value compilation -------------------------------------------------------


def _literal_runs(parts: tuple[Any, ...]) -> list[str]:
    """Wildcard-free runs of a parsed Sigma string, lowercased."""
    return [str(part).lower() for part in parts if isinstance(part, str) and part]


def _longest_literal(parts: tuple[Any, ...]) -> Literals:
    runs = [run for run in _literal_runs(parts) if len(run) >= limits.MIN_PREFILTER_LITERAL_LENGTH]
    if not runs:
        return None
    return frozenset({max(runs, key=len)})


def _compile_string(value: SigmaString, field_name: str) -> tuple[Callable[[str], bool], Literals]:
    """Build a matcher for a parsed Sigma string.

    pySigma has already folded ``contains``/``startswith``/``endswith`` into leading
    and trailing wildcards, so the shape of the parts tuple tells us which cheap
    string operation applies. Only genuinely interior wildcards need a regex.
    """
    cased = isinstance(value, SigmaCasedString)
    parts = tuple(value.s)

    if not parts:
        return (lambda subject: subject == ""), None

    literals = _longest_literal(parts)
    plain = [part for part in parts if isinstance(part, str)]
    wildcards = [part for part in parts if not isinstance(part, str)]

    if any(part is SpecialChars.WILDCARD_SINGLE for part in wildcards):
        # '?' means exactly one character; only a regex expresses that faithfully.
        return _compile_regex_text(str(value.to_regex().regexp), field_name, cased), literals

    if not wildcards:
        needle = plain[0] if plain else ""
        if cased:
            return (lambda subject: subject == needle), literals
        lowered = needle.lower()
        return (lambda subject: subject.lower() == lowered), literals

    leading = parts[0] is SpecialChars.WILDCARD_MULTI
    trailing = parts[-1] is SpecialChars.WILDCARD_MULTI
    interior = [part for part in parts[1:-1] if not isinstance(part, str)]

    if not interior and len(plain) == 1:
        needle = plain[0]
        if not cased:
            needle = needle.lower()

            def _fold(subject: str) -> str:
                return subject.lower()
        else:

            def _fold(subject: str) -> str:
                return subject

        if leading and trailing:
            return (lambda subject: needle in _fold(subject)), literals
        if leading:
            return (lambda subject: _fold(subject).endswith(needle)), literals
        if trailing:
            return (lambda subject: _fold(subject).startswith(needle)), literals

    return _compile_regex_text(str(value.to_regex().regexp), field_name, cased), literals


def _compile_regex_text(
    pattern: str, field_name: str, cased: bool = False
) -> Callable[[str], bool]:
    flags = 0 if cased else re.IGNORECASE
    try:
        compiled = compile_bounded(pattern, flags)
    except UnsafeRegexError as exc:
        raise SigmaUnsupportedError(f"Field '{field_name}': {exc}") from exc
    return lambda subject: bounded_search(compiled, subject)


def _compile_regex_value(
    value: SigmaRegularExpression, field_name: str
) -> tuple[Callable[[str], bool], Literals]:
    pattern = str(value.regexp)
    flags = 0
    for flag in getattr(value, "flags", ()) or ():
        name = getattr(flag, "name", "").upper()
        if name == "IGNORECASE":
            flags |= re.IGNORECASE
        elif name == "MULTILINE":
            flags |= re.MULTILINE
        elif name == "DOTALL":
            flags |= re.DOTALL
    try:
        compiled = compile_bounded(pattern, flags)
    except UnsafeRegexError as exc:
        raise SigmaUnsupportedError(f"Field '{field_name}': {exc}") from exc
    # A literal run inside the pattern still gates soundly, provided it is not
    # optional. Only unconditional prefixes/suffixes of alternation-free patterns
    # qualify, so this stays conservative: anything with '|', '?' or a group is
    # treated as ungateable.
    literals: Literals = None
    if not re.search(r"[|?*+{\[(]", pattern):
        cleaned = re.sub(r"\\([\\.^$])", r"\1", pattern).strip("^$")
        if len(cleaned) >= limits.MIN_PREFILTER_LITERAL_LENGTH and cleaned.isprintable():
            literals = frozenset({cleaned.lower()})
    return (lambda subject: bounded_search(compiled, subject)), literals


def _compile_cidr(value: SigmaCIDRExpression) -> Callable[[str], bool]:
    network = value.network

    def _match(subject: str) -> bool:
        try:
            return ipaddress.ip_address(subject.strip()) in network
        except ValueError:
            return False

    return _match


def _compile_compare(value: SigmaCompareExpression) -> Callable[[str], bool]:
    threshold = float(value.number.number)
    operator = value.op.name.upper()
    comparisons: dict[str, Callable[[float], bool]] = {
        "LT": lambda number: number < threshold,
        "LTE": lambda number: number <= threshold,
        "GT": lambda number: number > threshold,
        "GTE": lambda number: number >= threshold,
    }
    compare = comparisons.get(operator)
    if compare is None:
        raise SigmaUnsupportedError(f"Comparison operator '{operator}' is not supported")

    def _match(subject: str) -> bool:
        try:
            return compare(float(str(subject).strip()))
        except (TypeError, ValueError):
            return False

    return _match


def _compile_value(value: Any, field_name: str) -> tuple[Callable[[str], bool], Literals]:
    """Compile one Sigma value into a predicate over a single string."""
    if isinstance(value, SigmaString):
        return _compile_string(value, field_name)
    if isinstance(value, SigmaRegularExpression):
        return _compile_regex_value(value, field_name)
    if isinstance(value, SigmaCIDRExpression):
        return _compile_cidr(value), None
    if isinstance(value, SigmaCompareExpression):
        return _compile_compare(value), None
    if isinstance(value, SigmaNumber):
        text = str(value.number)
        return (lambda subject: subject.strip() == text), None
    if isinstance(value, SigmaBool):
        text = "true" if value.boolean else "false"
        return (lambda subject: subject.strip().lower() == text), None
    if isinstance(value, SigmaFieldReference):
        raise SigmaUnsupportedError(
            f"Field '{field_name}': the 'fieldref' modifier is not supported"
        )
    if isinstance(value, SigmaQueryExpression):
        raise SigmaUnsupportedError(
            f"Field '{field_name}': backend query expressions are not supported"
        )
    raise SigmaUnsupportedError(
        f"Field '{field_name}': value type {type(value).__name__} is not supported"
    )


# --- condition compilation ---------------------------------------------------


def _and_literals(children: list[Literals]) -> Literals:
    """Necessary literals for a conjunction.

    Any single conjunct's necessary literals are necessary for the whole, so the
    most selective child wins. Picking the smallest set keeps the prefilter tight.
    """
    usable = [child for child in children if child]
    if not usable:
        return None
    return min(usable, key=len)


def _or_literals(children: list[Literals]) -> Literals:
    """Necessary literals for a disjunction.

    Every branch must contribute, otherwise a subject could satisfy the ungateable
    branch while containing none of the collected literals — which would make the
    prefilter drop a real match.
    """
    collected: set[str] = set()
    for child in children:
        if not child:
            return None
        collected |= child
    return frozenset(collected) or None


def _compile_field_expression(
    node: ConditionFieldEqualsValueExpression, state: "_CompileState"
) -> tuple[Predicate, Literals]:
    field_name = str(node.field)
    if not is_known_field(field_name):
        state.unmapped_fields.add(field_name)

    value = node.value
    if isinstance(value, SigmaNull):
        return (lambda ctx: not ctx.values(field_name)), None
    if isinstance(value, SigmaExists):
        expected = bool(getattr(value, "exists", True))
        return (lambda ctx: bool(ctx.values(field_name)) is expected), None
    if isinstance(value, SigmaExpansion):
        # windash / base64offset expand to a set of alternatives: any one matching
        # satisfies the field, so this is an OR whose literals are the union.
        matchers: list[Callable[[str], bool]] = []
        literal_sets: list[Literals] = []
        for item in value.values:
            matcher, literals = _compile_value(item, field_name)
            matchers.append(matcher)
            literal_sets.append(literals)
        frozen = tuple(matchers)

        def _expansion(ctx: MatchCtx) -> bool:
            subjects = ctx.values(field_name)
            return any(matcher(subject) for subject in subjects for matcher in frozen)

        return _expansion, _or_literals(literal_sets)

    matcher, literals = _compile_value(value, field_name)

    def _match(ctx: MatchCtx) -> bool:
        return any(matcher(subject) for subject in ctx.values(field_name))

    return _match, literals


def _compile_keyword(node: ConditionValueExpression) -> tuple[Predicate, Literals]:
    """A fieldless search term, matched against the whole subject."""
    value = node.value
    if not isinstance(value, SigmaString):
        raise SigmaUnsupportedError(
            f"Keyword searches support strings only, got {type(value).__name__}"
        )
    parts = tuple(value.s)
    literals = _longest_literal(parts)
    plain = [part for part in parts if isinstance(part, str)]
    if len(plain) == 1 and not any(not isinstance(part, str) for part in parts):
        needle = plain[0].lower()
        return (lambda ctx: needle in ctx.blob()), literals
    matcher = _compile_regex_text(str(value.to_regex().regexp), "keyword")
    return (lambda ctx: matcher(ctx.blob())), literals


@dataclass
class _CompileState:
    unmapped_fields: set[str] = field(default_factory=set)
    negated_fields: set[str] = field(default_factory=set)


def _compile_condition(node: Any, state: _CompileState) -> tuple[Predicate, Literals]:
    if isinstance(node, ConditionAND):
        compiled = [_compile_condition(child, state) for child in node.args]
        predicates = tuple(item[0] for item in compiled)
        if len(predicates) == 1:
            return predicates[0], compiled[0][1]
        return (
            lambda ctx: all(predicate(ctx) for predicate in predicates),
            _and_literals([item[1] for item in compiled]),
        )
    if isinstance(node, ConditionOR):
        compiled = [_compile_condition(child, state) for child in node.args]
        predicates = tuple(item[0] for item in compiled)
        if len(predicates) == 1:
            return predicates[0], compiled[0][1]
        return (
            lambda ctx: any(predicate(ctx) for predicate in predicates),
            _or_literals([item[1] for item in compiled]),
        )
    if isinstance(node, ConditionNOT):
        inner, _ = _compile_condition(node.args[0], state)
        # A negated branch imposes no positive literal on the subject.
        return (lambda ctx: not inner(ctx)), None
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _compile_field_expression(node, state)
    if isinstance(node, ConditionValueExpression):
        return _compile_keyword(node)
    raise SigmaUnsupportedError(f"Condition node {type(node).__name__} is not supported")


# --- entry point -------------------------------------------------------------


def _severity_for(rule: SigmaRule) -> str:
    level = getattr(rule.level, "name", "") or ""
    return _SEVERITY_BY_LEVEL.get(level.lower(), "medium")


def _techniques_for(rule: SigmaRule) -> tuple[str, ...]:
    found: list[str] = []
    for tag in rule.tags or ():
        match = _ATTACK_TAG_RE.match(str(tag))
        if match:
            technique = match.group(1).upper()
            if technique not in found:
                found.append(technique)
    return tuple(found[: limits.MAX_TECHNIQUES])


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").strip().lower()).strip("-") or "rule"


def parse_rules(yaml_source: str) -> list[SigmaRule]:
    """Parse a Sigma document, rejecting anything this build cannot execute."""
    text = str(yaml_source or "")
    if not text.strip():
        raise SigmaSyntaxError("Rule source is empty")
    _check_source(text)
    _check_shape(text)
    try:
        collection = SigmaCollection.from_yaml(text)
    except PySigmaError as exc:
        raise SigmaSyntaxError(str(exc)) from exc
    except yaml.YAMLError as exc:
        raise SigmaSyntaxError(f"Invalid YAML: {exc}") from exc

    parsed: list[SigmaRule] = []
    for rule in collection.rules:
        if not isinstance(rule, SigmaRule):
            raise SigmaUnsupportedError(
                f"{type(rule).__name__} documents (Sigma correlations) are not supported"
            )
        parsed.append(rule)
    if not parsed:
        raise SigmaSyntaxError("No Sigma rules found in the document")
    return parsed


def compile_rule(rule: SigmaRule, yaml_source: str) -> CompiledRule:
    """Compile one parsed Sigma rule into a matcher."""
    detections = rule.detection.detections or {}
    if len(detections) > limits.MAX_SELECTIONS:
        raise SigmaLimitError(
            f"Rule declares {len(detections)} selections; the limit is {limits.MAX_SELECTIONS}"
        )

    conditions = rule.detection.parsed_condition or []
    if len(conditions) != 1:
        raise SigmaUnsupportedError(
            "Exactly one condition is supported; this rule declares "
            f"{len(conditions)}"
        )

    try:
        tree = conditions[0].parse()
    except PySigmaError as exc:
        raise SigmaSyntaxError(f"Invalid condition: {exc}") from exc

    state = _CompileState()
    predicate, literals = _compile_condition(tree, state)

    logsource = rule.logsource
    gate, label, known_logsource = logsource_predicate(
        logsource.category or "", logsource.product or "", logsource.service or ""
    )

    warnings: list[str] = []
    if state.unmapped_fields:
        names = ", ".join(sorted(state.unmapped_fields))
        warnings.append(
            f"Fields not mapped to stored evidence: {names}. "
            "They resolve only if the raw event carries a matching key."
        )
    if not known_logsource and label != "any":
        warnings.append(
            f"Log source '{label}' is not mapped; the rule is evaluated against every "
            "process and event."
        )
    if not literals:
        warnings.append(
            "No literal prefilter could be derived, so this rule is evaluated against "
            "every process and event."
        )

    title = str(rule.title or "Untitled rule")[: limits.MAX_TITLE_LENGTH]
    source_text = str(yaml_source)
    return CompiledRule(
        rule_id=str(rule.id or ""),
        slug=_slugify(title),
        title=title,
        severity=_severity_for(rule),
        techniques=_techniques_for(rule),
        description=str(rule.description or "")[:2000],
        predicate=predicate,
        logsource_gate=gate,
        logsource_label=label,
        literals=frozenset(literals or ()),
        warnings=tuple(warnings),
        unmapped_fields=tuple(sorted(state.unmapped_fields)),
        yaml_source=source_text,
        content_sha256=hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
    )


def compile_source(yaml_source: str) -> list[CompiledRule]:
    """Parse and compile every rule in a Sigma document."""
    return [compile_rule(rule, yaml_source) for rule in parse_rules(yaml_source)]


def matches(compiled: CompiledRule, ctx: MatchCtx) -> bool:
    """Evaluate a compiled rule against one subject."""
    return compiled.logsource_gate(ctx) and compiled.predicate(ctx)
