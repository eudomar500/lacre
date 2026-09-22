#!/usr/bin/env python3
"""Cut the smallest blob that a DKIM header signature can be checked from.

The output is the DKIM-Signature whose d= matches --domain plus exactly the
header fields that signature covers, in their original order, with CRLF line
endings. Nothing else from the message is written, and nothing from the
message is ever printed: this script reports a byte count and that is all.

Usage:
    python3 make_blob.py path/to/message.eml --domain amazon.com
    python3 make_blob.py path/to/message.eml --domain amazon.com --out /tmp/blob.txt
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dkim import rfc6376

DEFAULT_OUT = "/tmp/lacre-blob.txt"


def select_signature(fields, domain):
    """Index of the DKIM-Signature signing for domain, and its tags."""
    for index, (name, value) in enumerate(fields):
        if rfc6376.field_name(name) != b"dkim-signature":
            continue
        tags = rfc6376.parse_tag_list(value.decode("latin-1"))
        if tags.get("d") == domain:
            return index, tags
    raise SystemExit("no DKIM-Signature with d=%s in this message" % (domain,))


def signed_indexes(fields, sig_index, h_names):
    """Indexes of the fields that signature covers, RFC 6376 section 5.4.2.

    Selection runs over indexes rather than values so that a repeated header
    name resolves to the same instances the verifier will pick later, and the
    blob keeps the message's own order rather than the h= order.
    """
    pool = {}
    for index, (name, _) in enumerate(fields):
        if index != sig_index:
            pool.setdefault(rfc6376.field_name(name), []).append(index)
    chosen = {sig_index}
    for entry in h_names:
        instances = pool.get(entry.strip().lower().encode("latin-1"))
        if instances:
            chosen.add(instances.pop())
    return sorted(chosen)


def build_blob(raw_message, domain):
    raw_headers, _ = rfc6376.split_message(raw_message)
    fields = rfc6376.parse_header_fields(raw_headers)
    sig_index, tags = select_signature(fields, domain)
    h_names = [entry for entry in tags.get("h", "").split(":") if entry.strip()]
    if not h_names:
        raise SystemExit("the DKIM-Signature for d=%s has an empty h= tag" % (domain,))
    chosen = signed_indexes(fields, sig_index, h_names)
    return b"".join(fields[i][0] + b":" + fields[i][1] + b"\r\n" for i in chosen)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("message", help="path to a .eml file")
    parser.add_argument("--domain", required=True, help="the d= tag to select")
    parser.add_argument("--out", default=DEFAULT_OUT, help="output path")
    args = parser.parse_args()

    source = Path(args.message)
    if not source.is_file():
        raise SystemExit("message not found: %s" % (source,))

    blob = build_blob(source.read_bytes(), args.domain)
    Path(args.out).write_bytes(blob)
    print(len(blob))


if __name__ == "__main__":
    main()
