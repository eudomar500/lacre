"""The canonical form of one model answer about a shipping notice.

scripts/build_contract.py splices this file into the contract, so it imports
nothing the pinned runner does not carry and names nothing from the SDK.
Everything here is deterministic: the same answer folds to the same string on
every validator, which is the only reason strict equality has a chance of
agreeing on the output of a language model. It is also where the vocabulary
of results lives, so a validator never has to agree on the text of an
exception.

A candidate for lacre/llmfields.py once the probe is answered; nothing in it
is specific to the experiment.
"""

import json

# The seven Spanish weekdays, ASCII folded. A day outside this set is not a
# day, whatever the model called it.
WEEKDAYS = ("lunes", "martes", "miercoles", "jueves", "viernes", "sabado",
            "domingo")

# An accented byte must never reach the canonical string, because two
# validators can spell the same day differently and consensus compares bytes.
# By code point rather than by literal, so the contract source stays ASCII:
# the accented Spanish vowels, and the n with a tilde.
_ACCENTS = {0x00e1: "a", 0x00e9: "e", 0x00ed: "i", 0x00f3: "o",
            0x00fa: "u", 0x00fc: "u", 0x00f1: "n"}

# The body rides in the calldata of the write, so the cap is a transaction
# budget rather than a limit on what a model could read. Over it is a recorded
# result, not a revert.
MAX_BODY = 8192

MAX_LABEL = 64

TOO_LARGE = "error=too_large"
PARSE_ERROR = "error=parse"
SHAPE_ERROR = "error=shape"
# Anything exec_prompt raised on. In JSON mode the host decodes the answer,
# so unparseable output raises out of the call rather than reaching here:
# this one string covers a dead provider and a rambling model alike.
PROMPT_ERROR = "error=prompt"

ERRORS = (TOO_LARGE, PARSE_ERROR, SHAPE_ERROR, PROMPT_ERROR)


def body_size(body):
    """Bytes on the wire, not code points, because the cap is calldata."""
    # "replace" rather than the default: this runs before any guard and must
    # not be the thing that raises. Nothing is undercounted by it, since a
    # replacement is one byte for one code point.
    return len(str(body).encode("utf-8", "replace"))


def oversized(body):
    return body_size(body) > MAX_BODY


def scrub(value, limit):
    """A string safe to store and to read back beside the canonical one."""
    return str(value).replace("|", " ").replace("\r", " ").replace("\n", " ")[:limit]


def strip_fences(text):
    """Drop a markdown code fence the prompt asked the model not to write.

    Only the outermost one: the content of an answer is a JSON object, and a
    fence inside one is part of a string the parser will handle.
    """
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


def canonical(shipped, day):
    return "shipped=%d|eta=%s" % (1 if shipped else 0, day)


def from_object(parsed):
    """The two fields of one decoded answer, checked and folded."""
    shipped = parsed.get("shipped")
    # True and False only. A 1, or the string "true", is not the answer the
    # prompt asked for and is not guessed at: the two fields have to be read
    # the same way by every validator or there is nothing to agree on.
    if not isinstance(shipped, bool):
        return SHAPE_ERROR
    return canonical(shipped, fold_day(parsed.get("eta_day", "")))


def normalize_answer(raw):
    """One model answer, folded to the string consensus compares.

    Takes either shape exec_prompt can return: the decoded object JSON mode
    hands back, or the text mode string, parsed here once a code fence is
    stripped. The text path is kept so a switch back needs no second
    normalizer.

    Never raises. Every way an answer can be wrong has its own result string,
    because a validator that raises here disagrees for a reason that has
    nothing to do with what the model read.
    """
    if isinstance(raw, dict):
        return from_object(raw)
    if not isinstance(raw, str):
        return PARSE_ERROR
    try:
        parsed = json.loads(strip_fences(raw))
    except ValueError:
        return PARSE_ERROR
    if not isinstance(parsed, dict):
        return SHAPE_ERROR
    return from_object(parsed)
