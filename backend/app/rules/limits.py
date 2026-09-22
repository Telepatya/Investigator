"""Every hard cap the rules subsystem enforces, in one place.

Rule text arrives from an analyst pasting a public Sigma rule or importing a bundle.
That is a trusted-but-careless input, not a hostile one — but the failure modes
(a YAML bomb, a rule set large enough to stall a detection run, a regex that
backtracks forever) all degrade the tool silently, so each has a stated ceiling.
"""

from __future__ import annotations

# --- rule source ------------------------------------------------------------
MAX_YAML_BYTES = 64 * 1024
MAX_IMPORT_BYTES = 4 * 1024 * 1024
MAX_IMPORT_DOCS = 2000
MAX_YAML_DEPTH = 12
MAX_YAML_NODES = 5000

# --- rule shape -------------------------------------------------------------
MAX_SELECTIONS = 32
MAX_FIELDS_PER_SELECTION = 32
MAX_VALUES_PER_FIELD = 256
MAX_VALUE_LENGTH = 1024
MAX_TITLE_LENGTH = 200
MAX_NOTE_LENGTH = 2000
MAX_TECHNIQUES = 10

# --- rule set ---------------------------------------------------------------
MAX_ENABLED_CUSTOM_RULES = 500

# A rule with no derivable literal is evaluated against every process and every
# event, with no cheap gate in front of it. That is the one way this feature can
# make a detection run measurably slower, so the count is capped rather than merely
# reported, and the API refuses to enable one past the ceiling.
MAX_UNFILTERED_RULES = 25

# Shortest literal worth putting in the prefilter alternation. Below this, common
# substrings match nearly every command line and the gate stops gating.
MIN_PREFILTER_LITERAL_LENGTH = 4
