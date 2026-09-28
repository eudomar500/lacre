#!/usr/bin/env python3
"""Run the Extractor's reading of a message locally, before anything is sent.

Takes a .eml and a patterns document. The document is checked with the same
function set_patterns runs, the body is verified against the DKIM
signature's bh= under the signature's own body canonicalization, and the
patterns are applied with the same code the contract splices in
(lacre/dkimbody.py and lacre/patterns.py). What it prints is the canonical
string the validators would agree on for that body served at a URL, and the
SHA-256 the record would carry as patterns_sha256.

Nothing from the message is printed but the signing domain, the body
canonicalization and the extracted fields: no header value, no address and
no order number. The message is read and never written anywhere.

Usage:
    python3 tools/extract_check.py MESSAGE.eml PATTERNS.json [--domain DOMAIN]
        [--selector SELECTOR]

--domain and --selector pick the DKIM-Signature the way the Verifier does,
by d= and s=; without them the first DKIM-Signature is used.

Exit codes:
  0  the body matches bh= and the patterns ran
  1  usage error, unreadable file, rejected document or no usable signature
  2  the body does not match bh=, or the reading failed; the contract would
     store match false
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lacre import dkimcore, patterns

FIELDS = ("match", "shipped", "eta_day", "eta_date", "order_id_found",
          "patterns_sha256", "reason")


def split_message(raw):
    """The header block and the body, cut at the first empty line.

    The body is every byte after it, untouched: that is what a server hands
    the validators and what bh= was computed over.
    """
    found = [(raw.find(sep), sep) for sep in (b"\r\n\r\n", b"\n\n")]
    found = [(index, sep) for index, sep in found if index >= 0]
    if not found:
        return raw, b""
    index, sep = min(found)
    return raw[:index], raw[index + len(sep):]


def signature(headers, domain, selector):
    """The tags of the DKIM-Signature the Verifier would select, or None.

    Only a field named exactly DKIM-Signature: ARC and X-Google signatures
    carry the same tags over other input.
    """
    for name, value in dkimcore.parse_headers(headers):
        if dkimcore.field_name(name) != b"dkim-signature":
            continue
        tags = dkimcore.parse_tags(value.decode("latin-1"))
        if domain and tags.get("d", "").strip().lower() != domain:
            continue
        if selector and tags.get("s", "").strip().lower() != selector:
            continue
        return tags
    return None


def body_canon(tags):
    """The body half of c=, as the Verifier records it."""
    return tags.get("c", "").partition("/")[2].strip().lower() or "simple"


def check(raw, document, domain="", selector=""):
    """(canonical string, facts) for one message, or raises ValueError."""
    patterns.load_patterns(document)
    headers, body = split_message(raw)
    tags = signature(headers, domain.strip().lower().strip("."),
                     selector.strip().lower().strip("."))
    if tags is None:
        raise ValueError("no DKIM-Signature for that domain and selector")
    if "l" in tags:
        raise ValueError("the signature carries l=; the Verifier refuses it")
    canon = body_canon(tags)
    if canon not in ("simple", "relaxed"):
        raise ValueError("body canonicalization %r; the Extractor refuses it" % (canon,))
    agreed = patterns.extract_body(body, dkimcore.unfold(tags.get("bh", "")), canon,
                                   document)
    return agreed, {"domain": tags.get("d", "").strip().lower(), "body_canon": canon}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("message", help="path to a .eml file")
    parser.add_argument("patterns", help="path to a patterns document")
    parser.add_argument("--domain", default="", help="d= of the signature to use")
    parser.add_argument("--selector", default="", help="s= of the signature to use")
    args = parser.parse_args(argv)

    try:
        raw = Path(args.message).read_bytes()
        document = Path(args.patterns).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        print("error: %s" % (error,), file=sys.stderr)
        return 1
    try:
        agreed, facts = check(raw, document, args.domain, args.selector)
    except ValueError as error:
        print("error: %s" % (error,), file=sys.stderr)
        return 1

    print("domain          : %s" % (facts["domain"],))
    print("body_canon      : %s" % (facts["body_canon"],))
    for name, value in zip(FIELDS, agreed.split("|")):
        print("%-16s: %s" % (name, value))
    print("canonical       : %s" % (agreed,))
    print("document sha256 : %s" % (patterns.document_sha256(document),))
    return 0 if agreed.split("|")[0] == "1" and agreed.endswith("|extracted") else 2


if __name__ == "__main__":
    sys.exit(main())
