"""Regular expressions with a deadline on every untrusted match.

Probe inputs help authors catch expensive rules early. They cannot prove a pattern
safe, so the same timeout also applies to every actual detection subject.
"""
from __future__ import annotations

import regex

MAX_PATTERN_LENGTH = 512
MAX_SUBJECT_LENGTH = 8192
BACKTRACK_BUDGET_SECONDS = 0.02


class UnsafeRegexError(ValueError):
    """A rule cannot be evaluated safely; abort rather than report a non-match."""


def _has_backreference(pattern: str) -> bool:
    index = 0
    while index < len(pattern):
        if pattern[index] == "\\" and index + 1 < len(pattern):
            if pattern[index + 1] in "123456789g":
                return True
            index += 2
            continue
        if pattern.startswith("(?P=", index):
            return True
        index += 1
    return False


def _search(compiled: regex.Pattern[str], subject: str) -> bool:
    try:
        return compiled.search(
            subject, timeout=BACKTRACK_BUDGET_SECONDS, concurrent=True
        ) is not None
    except TimeoutError as exc:
        raise UnsafeRegexError(
            "Regular expression exceeded its match deadline; simplify the rule "
            "before retrying analysis"
        ) from exc


def compile_bounded(pattern: str, flags: int = 0) -> regex.Pattern[str]:
    text = str(pattern or "")
    if not text:
        raise UnsafeRegexError("Regular expression is empty")
    if len(text) > MAX_PATTERN_LENGTH:
        raise UnsafeRegexError(
            f"Regular expression is {len(text)} characters; the limit is {MAX_PATTERN_LENGTH}"
        )
    if _has_backreference(text):
        raise UnsafeRegexError("Backreferences are not supported")
    try:
        # VERSION0 preserves Python re's simple case folding and inline-flag
        # behavior for existing analyst rules.
        compiled = regex.compile(text, flags | regex.VERSION0)
    except (regex.error, OverflowError, RecursionError) as exc:
        raise UnsafeRegexError(f"Invalid regular expression: {exc}") from exc
    literals = list(dict.fromkeys(char for char in text if char.isalnum()))[:4]
    for char in dict.fromkeys(["a", "0", *literals]):
        _search(compiled, char * 1024 + "!")
    return compiled


def bounded_search(compiled: regex.Pattern[str], value: str) -> bool:
    if not value:
        return False
    return _search(compiled, value[:MAX_SUBJECT_LENGTH])
