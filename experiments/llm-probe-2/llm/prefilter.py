"""A deterministic check for bodies that look like they are aimed at a reader.

Local only. The contract in this probe does not call it: a body it flagged
would never reach the model, and whether the prompt alone resists the attack
is the thing being measured. It is run against the ten bodies in the tests
and the README reports what it catches and what it misses.

Not spliced into the contract, so it may import prompt.py directly.
"""

import re
from pathlib import Path
import importlib.util

_PROMPT = Path(__file__).resolve().parent / "prompt.py"
_spec = importlib.util.spec_from_file_location("probe2_prompt", _PROMPT)
prompt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(prompt)

SCHEMA_KEYS = ("shipped", "eta_day", "injection")

# An opening brace followed by a quoted key and a colon: the start of a JSON
# object, or of a Python dict, which a model reads the same way.
_OBJECT = re.compile(r"\{\s*[\"'][^\"'\n]*[\"']\s*:")

REASONS = ("schema_key", "json_object", "delimiter_line")


def flags(body):
    """The reasons a body is suspicious, in REASONS order. Empty if none.

    The key and object checks run on the sanitized body, which is what the
    model would see; the delimiter check runs on the body before the
    sanitizer drops those lines, with the invisible characters taken out
    first so a zero-width space cannot break up a run of dashes.
    """
    clean = prompt.sanitize(body)
    lowered = clean.lower()
    found = []
    if any(key in lowered for key in SCHEMA_KEYS):
        found.append("schema_key")
    if _OBJECT.search(clean):
        found.append("json_object")
    visible = str(body).translate(prompt.INVISIBLE)
    raw_lines = visible.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if any(prompt.is_delimiter_line(line) for line in raw_lines):
        found.append("delimiter_line")
    return found


def suspicious(body):
    return bool(flags(body))
