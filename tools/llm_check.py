#!/usr/bin/env python3
"""Run the LLM Extractor's steps before the model call locally, on one message.

Takes a .eml. The body is verified against the DKIM signature's bh= under
the signature's own body canonicalization, the text part is taken, the
prefilter runs, and the prompt is built, with the same code the contract
splices in (lacre/dkimbody.py and lacre/llmfields.py). No model is called.

What it prints: the signing domain, the body canonicalization, whether the
body matches bh=, the prefilter's verdict and the reasons it gives, the
string the validators would agree on when no model call is due, the prompt
that would be sent, and PROMPT_SHA256, which every record of the lane
carries. In the prompt the body is replaced by its length and SHA-256: the
text itself is never printed, nor any header value, address or order
number. A flagged body is never sent to the model; its prompt is still
printed, marked as not sent, so the layout can be read.

Usage:
    python3 tools/llm_check.py MESSAGE.eml [--domain DOMAIN] [--selector SELECTOR]

--domain and --selector pick the DKIM-Signature the way the Verifier does,
by d= and s=; without them the first DKIM-Signature is used.

Exit codes:
  0  the body matches bh= and the contract would ask the model
  1  usage error, unreadable file or no usable signature
  2  no model call would be made: the agreed string printed is the record
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from extract_check import body_canon, signature, split_message
from lacre import dkimbody, dkimcore, llmfields


def redacted(prompt, clean):
    """prompt with the body's JSON string replaced by its size and digest."""
    data = clean.encode("utf-8")
    stand_in = "<body: %d bytes UTF-8, sha256 %s>" % (len(data), hashlib.sha256(data).hexdigest())
    # By position, the line after the opening marker: a short body such as
    # "" also occurs in the rules, so a text replacement could hit those.
    lines = prompt.split("\n")
    at = lines.index("BEGIN-" + llmfields.body_tag(clean)) + 1
    if lines[at] != json.dumps(clean, ensure_ascii=True):
        raise ValueError("the prompt does not carry the body where the layout puts it")
    lines[at] = stand_in
    return "\n".join(lines)


def check(raw, domain="", selector=""):
    """The facts about one message, or raises ValueError."""
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
    bh = dkimcore.unfold(tags.get("bh", ""))
    outcome, prompt = llmfields.prepare(body, bh, canon)
    text = dkimbody.first_text_part(body).decode("utf-8", "replace")
    clean = llmfields.sanitize(text)
    return {
        "domain": tags.get("d", "").strip().lower(),
        "body_canon": canon,
        "match": len(body) <= llmfields.MAX_BODY and dkimbody.body_hash_b64(body, canon) == bh,
        "flags": llmfields.flags(text) if text else [],
        "outcome": outcome,
        # Built for display when the contract would not build it, so a
        # flagged body's prompt can still be read; never sent either way.
        "prompt": redacted(prompt or llmfields.build_prompt(clean), clean) if text else "",
        "sent": bool(prompt),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("message", help="path to a .eml file")
    parser.add_argument("--domain", default="", help="d= of the signature to use")
    parser.add_argument("--selector", default="", help="s= of the signature to use")
    args = parser.parse_args(argv)

    try:
        raw = Path(args.message).read_bytes()
    except OSError as error:
        print("error: %s" % (error,), file=sys.stderr)
        return 1
    try:
        facts = check(raw, args.domain, args.selector)
    except ValueError as error:
        print("error: %s" % (error,), file=sys.stderr)
        return 1

    print("domain          : %s" % (facts["domain"],))
    print("body_canon      : %s" % (facts["body_canon"],))
    print("bh match        : %s" % ("yes" if facts["match"] else "no",))
    print("prefilter       : %s" % ("flagged: " + ", ".join(facts["flags"])
                                    if facts["flags"] else "passed",))
    if facts["outcome"]:
        print("agreed          : %s (no model call)" % (facts["outcome"],))
    else:
        print("agreed          : decided by the model's answer")
    print("prompt_sha256   : %s" % (llmfields.PROMPT_SHA256,))
    if facts["prompt"]:
        print("prompt          : %s" % ("would be sent" if facts["sent"]
                                        else "NOT sent; shown for reading only",))
        print("-" * 72)
        print(facts["prompt"], end="")
        print("-" * 72)
    return 0 if facts["sent"] else 2


if __name__ == "__main__":
    sys.exit(main())
