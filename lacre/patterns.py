# Pattern extraction over a body that already matched its DKIM bh=. Pure
# stdlib and no file or network access: contracts/extractor/build.py splices
# this into the Extractor next to lacre/dkimbody.py, and tools/extract_check.py
# runs the same functions off chain, so the canonical string a validator
# agrees on can be reproduced from the .eml without a node.
#
# The matching rules are the body probe's, measured on Bradbury: the first
# text/plain part, decoded as UTF-8 with replacement, accents folded to ASCII
# and lowercased before any expression sees it. What changed is that the
# expressions are data, one document per sender, instead of three constants.
# The rules are written out in docs/extractor.md.

import hashlib
import json
import re

from lacre.dkimbody import WEEKDAYS, _ACCENTS, body_hash_b64, first_text_part

KEYS = ["eta_date", "eta_day", "order_id", "shipped"]
MAX_PATTERNS = 4096
MAX_BODY = 262144


def clean_document(document):
    # Surrounding whitespace is not part of the document, so a file read with
    # its trailing newline and the same text passed through a shell hash alike.
    return str(document).strip()


def document_sha256(document):
    return hashlib.sha256(clean_document(document).encode()).hexdigest()


def load_patterns(document):
    # Raises ValueError. Every expression is compiled here, so a stored
    # document cannot fail later, inside the non-deterministic block, for a
    # reason the owner could have seen when setting it.
    text = clean_document(document)
    if len(text.encode()) > MAX_PATTERNS:
        raise ValueError("patterns too large")
    try:
        doc = json.loads(text)
    except ValueError:
        raise ValueError("patterns not JSON")
    if (not isinstance(doc, dict) or sorted(doc) != KEYS
            or not all(isinstance(doc[key], list) for key in KEYS)):
        raise ValueError("patterns need lists under " + " ".join(KEYS))
    for key in KEYS:
        for expr in doc[key]:
            try:
                groups = re.compile(expr).groupindex
            except (re.error, TypeError):
                raise ValueError("patterns key does not compile: " + key)
            if key == "eta_date" and not {"y", "m", "d"} <= set(groups):
                raise ValueError("eta_date needs groups y m d")
    return doc


def weekday(hit):
    # The probe kept group 1 when it was one of seven words; an expression
    # with no group offers its whole match instead.
    word = hit.group(1 if hit.re.groups else 0)
    return word if word in WEEKDAYS else ""


def iso_date(hit):
    y, m, d = (hit.group(key) or "" for key in "ymd")
    # A bare \d also matches digits of other scripts; only ASCII ones make
    # a date.
    if not re.fullmatch("[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}", "-".join((y, m, d))):
        return ""
    y, m, d = int(y), int(m), int(d)
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    # Thirty-one days in odd months up to July and even ones from August.
    last = 28 + leap if m == 2 else 30 + (m + m // 8) % 2
    return "%04d-%02d-%02d" % (y, m, d) if 0 < m < 13 and 0 < d <= last else ""


def first_value(exprs, text, pick):
    # In document order; each expression offers its first match only, as the
    # probe's single expression did, and the first usable value wins.
    for expr in exprs:
        hit = re.search(expr, text)
        if hit and pick(hit):
            return pick(hit)
    return ""


def canonical(reason, digest, match=0, shipped=0, day="", date="", order=0):
    # Written in the order match|shipped|eta_day|eta_date|order_id_found|
    # patterns_sha256|reason. The reason is one of a fixed set of phrases or
    # an exception class name; nothing read from the body can reach it.
    return "%d|%d|%s|%s|%d|%s|%s" % (match, shipped, day, date, order, digest,
                                     reason.replace("|", " ")[:96])


def extract_body(raw, bh, canon, document):
    # Never raises: every outcome is a string the validators can compare.
    digest = document_sha256(document)
    if len(raw) > MAX_BODY:
        return canonical("body too large", digest)
    try:
        if body_hash_b64(raw, canon) != bh:
            return canonical("bh mismatch", digest)
        text = first_text_part(raw)
        if not text:
            return canonical("no text part", digest, 1)
        doc = load_patterns(document)
        folded = text.decode("utf-8", "replace").translate(_ACCENTS).lower()
        return canonical(
            "extracted", digest, 1,
            any(re.search(expr, folded) for expr in doc["shipped"]),
            first_value(doc["eta_day"], folded, weekday),
            first_value(doc["eta_date"], folded, iso_date),
            # A boolean and nothing else: the order number is never kept, so
            # it cannot reach the canonical string, storage or a log.
            any(re.search(expr, folded) for expr in doc["order_id"]))
    except Exception as error:
        return canonical("extract failed: " + type(error).__name__, digest)
