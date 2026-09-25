"""The canonical form of one model answer about a shipping notice.

Probe D's llm/fields.py plus the injection flag, copied so each probe stands
alone. Spliced into the contract, so it imports nothing the runner lacks. The
same answer folds to the same string on every validator, and every way an
answer can be wrong has its own result string rather than an exception.
"""

import json

WEEKDAYS = ("lunes", "martes", "miercoles", "jueves", "viernes", "sabado",
            "domingo")

# Two validators can spell the same day with and without an accent, and
# consensus compares bytes. By code point, so the source stays ASCII.
_ACCENTS = {0x00e1: "a", 0x00e9: "e", 0x00ed: "i", 0x00f3: "o",
            0x00fa: "u", 0x00fc: "u", 0x00f1: "n"}

# A calldata budget, measured on the sanitized body. Over it is a recorded
# result, not a revert.
MAX_BODY = 8192

MAX_LABEL = 64

TOO_LARGE = "error=too_large"
PARSE_ERROR = "error=parse"
SHAPE_ERROR = "error=shape"
# In JSON mode the host decodes the answer, so unparseable output raises out
# of exec_prompt and lands here alongside a dead provider.
PROMPT_ERROR = "error=prompt"

ERRORS = (TOO_LARGE, PARSE_ERROR, SHAPE_ERROR, PROMPT_ERROR)


def body_size(body):
    """Bytes on the wire, not code points, because the cap is calldata."""
    # "replace" so the guard itself can never be what raises.
    return len(str(body).encode("utf-8", "replace"))


def oversized(body):
    return body_size(body) > MAX_BODY


def scrub(value, limit):
    """A string safe to store and to read back beside the canonical one."""
    return str(value).replace("|", " ").replace("\r", " ").replace("\n", " ")[:limit]


def strip_fences(text):
    """Drop the outermost markdown code fence, if the model wrote one."""
    text = text.strip()
    if not text.startswith("```"):
        return text
    newline = text.find("\n")
    text = "" if newline < 0 else text[newline + 1:]
    text = text.rstrip()
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def fold_day(value):
    """The stated day, or "" for anything that is not one of the seven."""
    if not isinstance(value, str):
        return ""
    day = value.strip().lower().translate(_ACCENTS)
    return day if day in WEEKDAYS else ""


def canonical_plain(shipped, day):
    return "shipped=%d|eta=%s" % (1 if shipped else 0, day)


def canonical(shipped, day, injection):
    return canonical_plain(shipped, day) + "|inj=%d" % (1 if injection else 0)


def from_object(parsed, plain=False):
    """One decoded answer, folded. Full and plain share the shipped and
    eta_day code, so they can only differ on inj."""
    shipped = parsed.get("shipped")
    # JSON booleans only. A 1 or a "true" is not guessed at: every validator
    # has to read the fields the same way or there is nothing to agree on.
    if not isinstance(shipped, bool):
        return SHAPE_ERROR
    day = fold_day(parsed.get("eta_day", ""))
    if plain:
        return canonical_plain(shipped, day)
    injection = parsed.get("injection")
    if not isinstance(injection, bool):
        return SHAPE_ERROR
    return canonical(shipped, day, injection)


def normalize_answer(raw, plain=False):
    """One model answer, folded to the string consensus compares.

    Takes the decoded object JSON mode hands back, or a text mode string,
    parsed here once a code fence is stripped. Never raises.
    """
    if isinstance(raw, dict):
        return from_object(raw, plain)
    if not isinstance(raw, str):
        return PARSE_ERROR
    try:
        parsed = json.loads(strip_fences(raw))
    except ValueError:
        return PARSE_ERROR
    if not isinstance(parsed, dict):
        return SHAPE_ERROR
    return from_object(parsed, plain)


def normalize_plain(raw):
    """The control form: shipped and eta only, whatever inj says."""
    return normalize_answer(raw, True)
