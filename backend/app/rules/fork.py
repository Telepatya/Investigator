"""Generate an editable Sigma rule from a built-in detection.

Built-in rules are Python: regex lookaheads, parent/child pairs, normalized path
comparisons. Their metadata is directly editable, but their logic is not — so
"editing" one means forking it into a custom Sigma rule that approximates it, and
disabling the original.

Every generated rule is compiled before it is stored. An approximation that does not
run is worse than no fork at all, so a template that produces something uncompilable
is a bug here, reported as such, rather than a broken rule saved to the analyst's
rule set.
"""

from __future__ import annotations

import re
import uuid

from app.rules import registry
from app.rules.registry import RuleSpec

# `(?=.*token)` — the shape rules.py uses to require several tokens in one command
# line. Expressed in Sigma this is `CommandLine|contains|all`, which is both exactly
# equivalent and far friendlier to the literal prefilter than a regex would be.
_LOOKAHEAD_RE = re.compile(r"\(\?=\.\*(?P<body>(?:[^()\\]|\\.)+)\)")
_REGEX_METACHARACTERS = re.compile(r"[.^$*+?{}\[\]|()]")


def _yaml_quote(value: str) -> str:
    """Single-quoted YAML scalar.

    Backslashes are deliberately left alone: inside single quotes YAML performs no
    escape processing, so doubling them would push literal backslashes into the
    pattern — which turns ``\\bfoo`` into an unterminated regex and Windows paths
    into nonsense.
    """
    return "'" + str(value).replace("'", "''") + "'"


def decompose_lookaheads(pattern: str) -> list[str] | None:
    """Turn ``(?=.*a)(?=.*b)`` into ``["a", "b"]``.

    Returns ``None`` unless the pattern is *entirely* lookaheads over literal text,
    so a partial match never silently drops a constraint.
    """
    matches = list(_LOOKAHEAD_RE.finditer(pattern))
    if not matches:
        return None
    consumed = "".join(match.group(0) for match in matches)
    if consumed != pattern:
        return None
    tokens: list[str] = []
    for match in matches:
        body = match.group("body")
        # Only literal alternatives can be expressed as `contains`; a nested
        # alternation or class means the fork must stay a regex.
        if _REGEX_METACHARACTERS.search(body.replace("\\b", "")):
            return None
        token = body.replace("\\b", "").replace("\\", "")
        if not token:
            return None
        tokens.append(token)
    return tokens


def _literal_from_pattern(pattern: str) -> str | None:
    """The pattern's literal text, if it carries no regex syntax at all."""
    cleaned = pattern.replace("\\b", "").strip("^$")
    if _REGEX_METACHARACTERS.search(cleaned):
        return None
    unescaped = re.sub(r"\\(.)", r"\1", cleaned)
    return unescaped or None


def _split_literals_and_regexes(patterns: list[str]) -> tuple[list[str], list[str]]:
    """Partition patterns into plain substrings and genuine regexes.

    Some tables (notably ``WEB_ATTACK_PATTERNS``) mix compiled regexes with plain
    substrings in one list. A substring like ``sleep(`` is not a valid regex, so
    emitting it under ``|re`` would produce a rule that refuses to compile.
    """
    literals: list[str] = []
    regexes: list[str] = []
    for pattern in patterns:
        literal = _literal_from_pattern(pattern)
        if literal is not None:
            literals.append(literal)
            continue
        try:
            re.compile(pattern)
        except re.error:
            # Not valid regex syntax, so it was only ever meant as a substring.
            literals.append(pattern)
        else:
            regexes.append(pattern)
    return literals, regexes


def _field_selections(field: str, patterns: list[str]) -> list[str]:
    """Detection body matching ``field`` against a mix of substrings and regexes."""
    literals, regexes = _split_literals_and_regexes(patterns)
    lines = ["detection:"]
    names: list[str] = []
    if literals:
        names.append("selection_text")
        lines.append("    selection_text:")
        lines.append(f"        {field}|contains:")
        lines += [f"            - {_yaml_quote(literal)}" for literal in literals]
    if regexes:
        names.append("selection_regex")
        lines.append("    selection_regex:")
        lines.append(f"        {field}|re:")
        lines += [f"            - {_yaml_quote(pattern)}" for pattern in regexes]
    lines.append("    condition: " + " or ".join(names))
    return lines


def _header(spec: RuleSpec, title: str, logsource: str) -> list[str]:
    # Titles routinely contain a colon ("LOLBin: certutil.exe"), so both free-text
    # fields are quoted rather than emitted bare.
    lines = [
        f"title: {_yaml_quote(title)}",
        f"id: {uuid.uuid4()}",
        "status: experimental",
        "description: "
        + _yaml_quote(
            f"Fork of the built-in rule '{spec.id}'. "
            "Review and adjust before relying on it."
        ),
        "logsource:",
    ]
    lines += [f"    {entry}" for entry in logsource.splitlines()]
    return lines


def _footer(spec: RuleSpec) -> list[str]:
    lines: list[str] = []
    if spec.techniques:
        lines.append("tags:")
        lines += [f"    - attack.{technique.lower()}" for technique in spec.techniques]
    level = "informational" if spec.severity == "info" else spec.severity
    lines.append(f"level: {level}")
    return lines


def _cmdline_detection(spec: RuleSpec) -> list[str]:
    patterns = [line for line in spec.logic.splitlines() if line.strip()]
    if len(patterns) == 1:
        # `(?=.*a)(?=.*b)` is how rules.py demands several tokens in one command
        # line. Sigma says the same thing with `contains|all`, which is equivalent,
        # prefilter-friendly, and sidesteps the regex guard entirely.
        tokens = decompose_lookaheads(patterns[0])
        if tokens:
            return [
                "detection:",
                "    selection:",
                "        CommandLine|contains|all:",
                *[f"            - {_yaml_quote(token)}" for token in tokens],
                "    condition: selection",
            ]
    return _field_selections("CommandLine", patterns)


def build_fork_yaml(spec: RuleSpec) -> str:
    """Render a built-in rule as an approximate Sigma rule."""
    if not spec.forkable:
        raise ValueError(
            f"Rule '{spec.id}' is stateful or multi-signal and has no Sigma equivalent"
        )

    title = f"{spec.title} (fork)"

    if spec.kind == registry.KIND_CMDLINE:
        product = "linux" if spec.platform == "linux" else "windows"
        body = _cmdline_detection(spec)
        lines = _header(spec, title, f"product: {product}\ncategory: process_creation")
        lines += body
    elif spec.kind == registry.KIND_LOLBIN:
        lines = _header(spec, title, "product: windows\ncategory: process_creation")
        lines += [
            "detection:",
            "    selection:",
            f"        Image|endswith: {_yaml_quote(chr(92) + spec.source_key)}",
            "    condition: selection",
        ]
    elif spec.kind == registry.KIND_PARENT_CHILD:
        parent, child = spec.title.removeprefix("Process chain: ").split(" -> ")
        lines = _header(spec, title, "product: windows\ncategory: process_creation")
        lines += [
            "detection:",
            "    selection:",
            f"        ParentImage|endswith: {_yaml_quote(chr(92) + parent.strip())}",
            f"        Image|endswith: {_yaml_quote(chr(92) + child.strip())}",
            "    condition: selection",
        ]
    elif spec.kind == registry.KIND_MASQUERADE:
        expected = spec.logic.split("not containing ")[-1].strip().strip("'")
        lines = _header(spec, title, "product: windows\ncategory: process_creation")
        lines += [
            "detection:",
            "    selection:",
            f"        Image|endswith: {_yaml_quote(chr(92) + spec.source_key)}",
            "    filter:",
            f"        Image|contains: {_yaml_quote(expected)}",
            "    condition: selection and not filter",
        ]
    elif spec.kind == registry.KIND_EXEC_DIR:
        lines = _header(spec, title, "product: windows\ncategory: process_creation")
        lines += [
            "detection:",
            "    selection:",
            f"        Image|contains: {_yaml_quote(spec.logic)}",
            "    condition: selection",
        ]
    elif spec.kind == registry.KIND_REGISTRY_PERSISTENCE:
        fragments = [line for line in spec.logic.splitlines() if line.strip()]
        lines = _header(spec, title, "product: windows\ncategory: registry_set")
        lines += ["detection:", "    selection:", "        TargetObject|contains:"]
        lines += [f"            - {_yaml_quote(fragment)}" for fragment in fragments]
        lines.append("    condition: selection")
    elif spec.kind == registry.KIND_LINUX_PERSISTENCE:
        fragments = [line for line in spec.logic.splitlines() if line.strip()]
        lines = _header(spec, title, "product: linux\ncategory: file_event")
        lines += ["detection:", "    selection:", "        TargetFilename|contains:"]
        lines += [f"            - {_yaml_quote(fragment)}" for fragment in fragments]
        lines.append("    condition: selection")
    elif spec.kind in (registry.KIND_WEB_REQUEST, registry.KIND_WEB_UA):
        field = "c-uri" if spec.kind == registry.KIND_WEB_REQUEST else "cs-user-agent"
        patterns = [line for line in spec.logic.splitlines() if line.strip()]
        lines = _header(spec, title, "category: webserver")
        lines += _field_selections(field, patterns)
    else:
        raise ValueError(f"Rule kind '{spec.kind}' cannot be forked")

    lines += _footer(spec)
    return "\n".join(lines) + "\n"
