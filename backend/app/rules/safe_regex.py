"""Bounded regular-expression compilation for analyst-supplied rule patterns.

``ROADMAP.md`` lists unbounded regular-expression matching as out of scope: a rule
author is trusted, but a pasted public Sigma rule is not, and a catastrophically
backtracking pattern would stall a detection run with no way to interrupt it.

The guard is deliberately static and conservative. It rejects the shapes that
actually produce exponential backtracking (a quantified group whose body is itself
quantified) rather than attempting to measure a pattern's real complexity, and it
caps the subject length so even a linear-but-slow pattern cannot be fed a
multi-megabyte command line.
"""

from __future__ import annotations

import re
import time

MAX_PATTERN_LENGTH = 512
MAX_SUBJECT_LENGTH = 8192

# Budget for a single match against the adversarial corpus below. A well-behaved
# pattern finishes these in microseconds; a backtracking one blows straight past it.
BACKTRACK_BUDGET_SECONDS = 0.02

# Deliberately short subjects. Catastrophic backtracking is exponential in the
# subject length, so 24 characters is long enough for a bad pattern to exceed the
# budget by orders of magnitude while still terminating quickly enough to measure.
# Longer subjects would make the check itself hang on the very patterns it exists to
# catch. The trailing mismatch character is what forces full backtracking.
_ADVERSARIAL_SUBJECTS = (
    "a" * 24 + "!",
    "ab" * 12 + "!",
    "a b" * 8 + "!",
    "0" * 24 + "!",
    "/" * 12 + "a" * 12 + "!",
    "\\" * 12 + "a" * 12 + "!",
)

# Only unbounded quantifiers compound. `{1,3}` and `{3}` repeat a bounded number of
# times, so a group carrying them cannot blow up exponentially.
_UNBOUNDED_QUANTIFIERS = "*+"


class UnsafeRegexError(ValueError):
    """A pattern was rejected before it was ever compiled."""


def _strip_escapes(pattern: str) -> str:
    """Blank out escaped characters so scanning never mistakes ``\\(`` for a group."""
    out: list[str] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "\\" and index + 1 < length:
            out.append("__")
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _has_backreference(pattern: str) -> bool:
    """True for \\1-style or (?P=name) backreferences, which are unbounded in cost."""
    index = 0
    length = len(pattern)
    while index < length:
        if pattern[index] == "\\" and index + 1 < length:
            nxt = pattern[index + 1]
            if nxt.isdigit() and nxt != "0":
                return True
            index += 2
            continue
        if pattern.startswith("(?P=", index):
            return True
        index += 1
    return False


def _next_is_quantifier(scanned: str, index: int) -> bool:
    """Whether an *unbounded* quantifier immediately follows position ``index``.

    ``{n}`` and ``{n,m}`` are excluded on purpose: bounded repetition cannot produce
    exponential backtracking, and treating it as dangerous would reject ordinary
    patterns such as an IPv4 match, ``\\d{1,3}(?:\\.\\d{1,3}){3}``.
    """
    if index >= len(scanned):
        return False
    if scanned[index] in _UNBOUNDED_QUANTIFIERS:
        return True
    # `{n,}` is unbounded above; `{n}` and `{n,m}` are not.
    if scanned[index] == "{":
        close = scanned.find("}", index)
        if close != -1:
            return scanned[index + 1 : close].endswith(",")
    return False


def _has_nested_quantifier(pattern: str) -> bool:
    """Detect a quantified group whose body can backtrack ambiguously.

    Two shapes matter. ``(a+)+`` and ``(a*)*`` multiply the inner quantifier's
    backtracking states by the outer one. ``(a|aa)+`` is the same problem written
    with an alternation: overlapping branches give the engine many ways to split
    the same input. Deciding whether branches genuinely overlap is not something a
    scanner can do, so any quantified group containing an alternation is refused.

    Walking the group structure once is enough — the scan pairs each ``(`` with its
    ``)``, notes whether the body held a quantifier or an alternation, and reports
    when such a group is itself quantified. Note that ``?`` is deliberately not an
    outer quantifier here: it repeats at most once and cannot compound.
    """
    scanned = _strip_escapes(pattern)
    # Stack entries track, per open group, whether its body held a quantifier or "|".
    stack: list[bool] = []
    in_class = False
    index = 0
    length = len(scanned)
    while index < length:
        char = scanned[index]
        if in_class:
            if char == "]":
                in_class = False
            index += 1
            continue
        if char == "[":
            in_class = True
            index += 1
            continue
        if char == "(":
            stack.append(False)
            index += 1
            continue
        if char == ")":
            body_is_ambiguous = stack.pop() if stack else False
            if body_is_ambiguous and _next_is_quantifier(scanned, index + 1):
                return True
            # A group that is quantified counts as ambiguous for its parent.
            if stack and (body_is_ambiguous or _next_is_quantifier(scanned, index + 1)):
                stack[-1] = True
            index += 1
            continue
        if char in _UNBOUNDED_QUANTIFIERS and stack:
            stack[-1] = True
        elif char == "|" and stack:
            stack[-1] = True
        index += 1
    return False


def _adversarial_subjects(pattern: str) -> tuple[str, ...]:
    """Adversarial subjects for one pattern.

    A fixed corpus only catches patterns built from characters it happens to
    contain, so the literal characters of the pattern itself are folded in: a
    pattern over ``x`` needs a subject of ``x`` to backtrack. Each subject ends in a
    character that forces the match to fail, which is what makes the engine explore
    every alternative before giving up.
    """
    literals: list[str] = []
    for char in _strip_escapes(pattern):
        if char.isalnum() and char not in literals:
            literals.append(char)
        if len(literals) >= 4:
            break
    derived = tuple(char * 24 + "!" for char in literals)
    return _ADVERSARIAL_SUBJECTS + derived


def _exceeds_backtrack_budget(compiled: re.Pattern[str]) -> bool:
    """Measure the pattern against short adversarial subjects.

    Whether a quantified group is genuinely ambiguous is not decidable by scanning:
    ``(?:-\\S+\\s+)*`` looks like the classic catastrophic shape but its branches
    match disjoint character classes, so it runs in linear time. Measuring settles
    it, and catches malicious shapes a scanner would miss.
    """
    for subject in _adversarial_subjects(compiled.pattern):
        started = time.perf_counter()
        try:
            compiled.search(subject)
        except (RuntimeError, MemoryError):
            return True
        if time.perf_counter() - started > BACKTRACK_BUDGET_SECONDS:
            return True
    return False


def compile_bounded(pattern: str, flags: int = 0) -> re.Pattern[str]:
    """Compile ``pattern`` after rejecting the constructs we refuse to run.

    Raises ``UnsafeRegexError`` with an analyst-readable reason; callers surface
    that text directly so a rejected rule explains itself.
    """
    text = str(pattern or "")
    if not text:
        raise UnsafeRegexError("Regular expression is empty")
    if len(text) > MAX_PATTERN_LENGTH:
        raise UnsafeRegexError(
            f"Regular expression is {len(text)} characters; the limit is {MAX_PATTERN_LENGTH}"
        )
    if _has_backreference(text):
        raise UnsafeRegexError(
            "Backreferences are not supported because their match cost is unbounded"
        )
    try:
        compiled = re.compile(text, flags)
    except re.error as exc:
        raise UnsafeRegexError(f"Invalid regular expression: {exc}") from exc

    # The verdict is measured, not guessed. The syntactic scan only sharpens the
    # message, because "it looks like (a+)+" is the explanation an analyst can act
    # on, whereas "it was slow" is not.
    if _exceeds_backtrack_budget(compiled):
        if _has_nested_quantifier(text):
            raise UnsafeRegexError(
                "Nested quantifiers such as (a+)+ make this pattern backtrack "
                "catastrophically; rewrite the repeated group so its branches cannot "
                "match the same text"
            )
        raise UnsafeRegexError(
            "This pattern backtracks far too slowly on adversarial input and is rejected"
        )
    return compiled


def bounded_search(compiled: re.Pattern[str], value: str) -> bool:
    """Search ``value`` truncated to a fixed ceiling.

    Detection subjects are command lines and file paths; anything past 8 KiB is
    payload, not signal, and matching it only buys worst-case runtime.
    """
    if not value:
        return False
    return compiled.search(value[:MAX_SUBJECT_LENGTH]) is not None
