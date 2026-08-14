"""Mapping from Sigma taxonomy field names onto Investigator's stored evidence.

Sigma rules address fields by Windows/Sysmon event-schema names (``CommandLine``,
``ParentImage``, ``TargetFilename``). This project stores a normalized ``Event`` row
with a free-form ``raw`` JSON payload, plus a ``Process`` row with real columns. This
module bridges the two.

Resolution order for a field is: an explicit model binding (a real column, which is
both faster and better normalized than the raw payload), then a list of known raw-key
aliases, then a case/space/underscore-insensitive sweep of the raw payload. A field
that resolves nowhere yields no values, which makes every test over it false — and
that fact is reported at save time rather than left to be discovered when a rule
never fires.

The normalization deliberately mirrors ``app.detect.engine._field``. It is
reimplemented here rather than imported so that ``app.rules`` never imports the
engine (the engine imports this package, not the other way round); a test asserts the
two agree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

# Sigma ``logsource`` values this build knows how to gate on. Anything else still
# runs, against every subject, with a warning — refusing would break the promise
# that public Sigma rules import verbatim, since the corpus carries hundreds of
# logsource combinations.
MAPPED_LOGSOURCE_CATEGORIES = frozenset(
    {
        "process_creation",
        "registry_set",
        "registry_add",
        "registry_event",
        "file_event",
        "network_connection",
        "dns_query",
        "webserver",
        "proxy",
        "authentication",
    }
)
MAPPED_LOGSOURCE_PRODUCTS = frozenset({"windows", "linux"})


def _normalize_key(name: str) -> str:
    return name.lower().replace(" ", "").replace("_", "")


@dataclass(slots=True)
class MatchCtx:
    """One subject a Sigma rule is evaluated against: a process or an event."""

    kind: str  # "process" | "event"
    raw: dict[str, Any] = field(default_factory=dict)
    process: Any | None = None
    parent: Any | None = None
    event: Any | None = None
    _cache: dict[str, tuple[str, ...]] = field(default_factory=dict)
    _normalized_raw: dict[str, str] | None = None
    _blob: str | None = None

    def normalized_raw(self) -> dict[str, str]:
        """Raw payload keyed by normalized name, built at most once per subject."""
        if self._normalized_raw is None:
            table: dict[str, str] = {}
            for key, value in (self.raw or {}).items():
                if isinstance(key, str) and value not in (None, ""):
                    table.setdefault(_normalize_key(key), str(value))
            self._normalized_raw = table
        return self._normalized_raw

    def blob(self) -> str:
        """Lowercased haystack for keyword (fieldless) searches and the prefilter."""
        if self._blob is None:
            parts: list[str] = []
            if self.process is not None:
                parts += [
                    str(self.process.name or ""),
                    str(self.process.path or ""),
                    str(self.process.cmdline or ""),
                ]
            if self.event is not None:
                parts += [
                    str(self.event.summary or ""),
                    str(self.event.source or ""),
                    str(self.event.entity or ""),
                ]
            parts += [str(value) for value in (self.raw or {}).values() if value not in (None, "")]
            self._blob = " ".join(parts).lower()
        return self._blob

    def values(self, sigma_field: str) -> tuple[str, ...]:
        """Every value ``sigma_field`` resolves to for this subject."""
        cached = self._cache.get(sigma_field)
        if cached is not None:
            return cached
        resolved = _resolve(self, sigma_field)
        self._cache[sigma_field] = resolved
        return resolved


def _basename(path: str) -> str:
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1]


def _proc(ctx: MatchCtx, attribute: str) -> tuple[str, ...]:
    value = getattr(ctx.process, attribute, None) if ctx.process is not None else None
    return (str(value),) if value not in (None, "") else ()


def _parent(ctx: MatchCtx, attribute: str) -> tuple[str, ...]:
    value = getattr(ctx.parent, attribute, None) if ctx.parent is not None else None
    return (str(value),) if value not in (None, "") else ()


def _event_attr(ctx: MatchCtx, attribute: str) -> tuple[str, ...]:
    value = getattr(ctx.event, attribute, None) if ctx.event is not None else None
    return (str(value),) if value not in (None, "") else ()


# Explicit bindings to real columns. Each returns a tuple so a field can legitimately
# carry more than one candidate value (an image path and its basename, say).
MODEL_BINDINGS: dict[str, Callable[[MatchCtx], tuple[str, ...]]] = {
    "CommandLine": lambda ctx: _proc(ctx, "cmdline"),
    "ProcessCommandLine": lambda ctx: _proc(ctx, "cmdline"),
    "Image": lambda ctx: _proc(ctx, "path"),
    "NewProcessName": lambda ctx: _proc(ctx, "path"),
    "ProcessName": lambda ctx: _proc(ctx, "name"),
    "OriginalFileName": lambda ctx: _proc(ctx, "name"),
    "ProcessId": lambda ctx: _proc(ctx, "pid"),
    "ParentProcessId": lambda ctx: _proc(ctx, "ppid"),
    "ParentImage": lambda ctx: _parent(ctx, "path"),
    "ParentCommandLine": lambda ctx: _parent(ctx, "cmdline"),
    "ParentProcessName": lambda ctx: _parent(ctx, "name"),
    "Computer": lambda ctx: _event_attr(ctx, "host"),
    "ComputerName": lambda ctx: _event_attr(ctx, "host"),
}

# Raw-payload aliases, tried in order before the normalized sweep.
TAXONOMY_ALIASES: dict[str, tuple[str, ...]] = {
    "CommandLine": ("CommandLine", "Cmdline", "CmdLine", "ProcessCommandLine", "Args"),
    "Image": ("Image", "NewProcessName", "ImagePath", "ProcessPath"),
    "ProcessName": ("ProcessName", "Process", "NewProcessName"),
    "OriginalFileName": ("OriginalFileName",),
    "ParentImage": ("ParentImage", "ParentProcessName", "ParentImagePath"),
    "ParentCommandLine": ("ParentCommandLine", "ParentCmdline"),
    "EventID": ("EventID", "Event ID", "EventId", "Id"),
    "Channel": ("Channel", "LogName"),
    "Provider_Name": ("Provider_Name", "ProviderName", "SourceName"),
    "TargetFilename": ("TargetFilename", "FileName", "Path", "TargetFile"),
    "TargetObject": ("TargetObject", "KeyPath", "Key", "ObjectName"),
    "Details": ("Details", "NewValue", "Value"),
    "User": ("User", "SubjectUserName", "TargetUserName", "AccountName", "Account"),
    "SubjectUserName": ("SubjectUserName", "User", "AccountName"),
    "TargetUserName": ("TargetUserName", "TargetAccount", "AccountName"),
    "LogonType": ("LogonType",),
    "ServiceName": ("ServiceName", "Service"),
    "ServiceFileName": ("ServiceFileName", "ImagePath"),
    "DestinationIp": ("DestinationIp", "DestIp", "RemoteAddress", "dest_ip"),
    "SourceIp": ("SourceIp", "SrcIp", "IpAddress", "ClientIp", "src_ip"),
    "DestinationPort": ("DestinationPort", "DestPort", "RemotePort"),
    "DestinationHostname": ("DestinationHostname", "Host", "Hostname"),
    "QueryName": ("QueryName", "Query", "DnsName", "Domain"),
    "c-uri": ("c-uri", "request", "uri", "url", "cs-uri-stem"),
    "cs-user-agent": ("cs-user-agent", "user_agent", "UserAgent", "useragent"),
    "sc-status": ("sc-status", "status", "status_code"),
    "c-ip": ("c-ip", "SourceIp", "ClientIp", "src_ip"),
}


def _resolve(ctx: MatchCtx, sigma_field: str) -> tuple[str, ...]:
    values: list[str] = []
    binding = MODEL_BINDINGS.get(sigma_field)
    if binding is not None:
        values.extend(binding(ctx))
    for alias in TAXONOMY_ALIASES.get(sigma_field, (sigma_field,)):
        candidate = (ctx.raw or {}).get(alias)
        if candidate not in (None, ""):
            text = str(candidate)
            if text not in values:
                values.append(text)
    if not values:
        candidate = ctx.normalized_raw().get(_normalize_key(sigma_field))
        if candidate:
            values.append(candidate)
    # An image path is frequently matched by basename; offering both keeps
    # `Image|endswith: \powershell.exe` working against bare-name telemetry.
    if sigma_field in ("Image", "ParentImage", "NewProcessName"):
        for value in list(values):
            base = _basename(value)
            if base and base not in values:
                values.append(base)
    return tuple(values)


def is_known_field(sigma_field: str) -> bool:
    """Whether a field has an explicit binding or alias list.

    A field outside this set can still resolve through the normalized raw sweep at
    match time; the answer here drives the "unmapped field" warning shown to the
    analyst, not whether the rule is allowed to run.
    """
    return sigma_field in MODEL_BINDINGS or sigma_field in TAXONOMY_ALIASES


def logsource_predicate(
    category: str, product: str, service: str
) -> tuple[Callable[[MatchCtx], bool], str, bool]:
    """Build the subject gate for a rule's ``logsource``.

    Returns the predicate, a human-readable label, and whether the logsource was
    recognized. Unrecognized logsources get a permissive predicate so the rule still
    runs — the literal prefilter is what bounds its cost.
    """
    category = (category or "").lower()
    product = (product or "").lower()
    service = (service or "").lower()
    label = "/".join(part for part in (product, category, service) if part) or "any"
    known = category in MAPPED_LOGSOURCE_CATEGORIES or product in MAPPED_LOGSOURCE_PRODUCTS

    def _is_linux(ctx: MatchCtx) -> bool:
        return bool((ctx.raw or {}).get("linux_log"))

    predicates: list[Callable[[MatchCtx], bool]] = []

    if product == "windows":
        # Mirrors the engine's hard split so a Windows rule can never fire on Linux
        # syslog prose, and vice-versa.
        predicates.append(lambda ctx: not _is_linux(ctx))
    elif product == "linux":
        predicates.append(lambda ctx: ctx.kind == "process" or _is_linux(ctx))

    if category == "process_creation":
        predicates.append(
            lambda ctx: ctx.kind == "process"
            or str((ctx.raw or {}).get("EventID") or "") in ("1", "4688")
        )
    elif category in ("registry_set", "registry_add", "registry_event"):
        predicates.append(
            lambda ctx: ctx.kind == "event"
            and (
                getattr(ctx.event, "category", "") == "persistence"
                or "registry" in str(getattr(ctx.event, "source", "")).lower()
            )
        )
    elif category in ("webserver", "proxy"):
        predicates.append(
            lambda ctx: ctx.kind == "event" and getattr(ctx.event, "category", "") == "web"
        )
    elif category == "authentication":
        predicates.append(
            lambda ctx: ctx.kind == "event"
            and getattr(ctx.event, "category", "") in ("authentication", "logon")
        )

    if service:
        token = service.lower()
        predicates.append(
            lambda ctx: token in str(getattr(ctx.event, "source", "")).lower()
            or token in str((ctx.raw or {}).get("Channel") or "").lower()
            if ctx.kind == "event"
            else True
        )

    if not predicates:
        return (lambda ctx: True), label, known

    frozen = tuple(predicates)

    def _gate(ctx: MatchCtx) -> bool:
        return all(predicate(ctx) for predicate in frozen)

    return _gate, label, known


def iter_known_fields() -> Iterable[str]:
    return sorted(set(MODEL_BINDINGS) | set(TAXONOMY_ALIASES))
