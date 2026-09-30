#!/usr/bin/env python3
"""Print the headers blob attest_inline takes, cut from one .eml file.

The blob is the DKIM-Signature whose d= and s= are the ones given, plus the
header fields it signs, in the message's own order, with CRLF line endings.
It is chosen with the functions the Verifier runs on it, from
lacre/dkimcore.py: parse_headers splits the fields, and signed_data decides
which instance of a repeated name a signature covers (RFC 6376 section 5.4.2,
the lowest unused instance first). So the blob holds exactly the instances
the contract will hash: one fewer and the RSA check fails, one more and the
record is refused as "duplicate signed header". Every other field, and the
body, is left out.

attest_inline puts the blob in calldata, which is public and permanent: To,
Subject and everything else it carries can be read by anyone, forever. See
docs/direct-use.md.

Messages belong in a gitignored directory such as samples/. A file inside
this repository that git would track is refused, so a message cannot be
committed by way of this tool.

Usage:
    python3 tools/headers_blob.py samples/message.eml DOMAIN [SELECTOR] > blob.txt
    python3 tools/headers_blob.py samples/message.eml DOMAIN [SELECTOR] --digest

--digest prints the blob's length and SHA-256 instead of the blob. SELECTOR
may be left out when the message carries one signature for DOMAIN.
"""

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lacre.dkimcore import field_name, parse_headers, parse_tags

# attest_inline refuses a blob over this many bytes as encoded in UTF-8.
MAX_BLOB = 16384


class BlobError(Exception):
    pass


def header_block(raw):
    """The bytes before the first empty line, whichever line ending it uses."""
    found = [(raw.find(sep), sep) for sep in (b"\r\n\r\n", b"\n\n")]
    found = [(index, sep) for index, sep in found if index >= 0]
    if not found:
        return raw
    index, sep = min(found)
    return raw[:index + len(sep) // 2]


def select(fields, domain, selector):
    """Index and tags of the signature the Verifier will select.

    The Verifier takes the first DKIM-Signature whose d= and s=, lowercased,
    equal the normalized domain and selector (attest_blob in
    contracts/verifier/verifier_template.py).
    """
    domain = domain.strip().lower().strip(".")
    matches = []
    for index, (name, value) in enumerate(fields):
        if field_name(name) != b"dkim-signature":
            continue
        tags = parse_tags(value.decode("latin-1"))
        if tags.get("d", "").lower() != domain:
            continue
        if selector is None or tags.get("s", "").lower() == selector.strip().lower().strip("."):
            matches.append((index, tags))
    if not matches:
        raise BlobError("no DKIM-Signature with d=%s%s in this message"
                        % (domain, "" if selector is None else " and s=%s" % (selector,)))
    if selector is None and len({tags.get("s", "").lower() for _, tags in matches}) > 1:
        raise BlobError("more than one selector signs for d=%s; pass SELECTOR" % (domain,))
    return matches[0]


def covered(fields, sig_index, names):
    """Indexes of the fields the signature covers, as signed_data picks them.

    signed_data pops each name's list from the end, so a repeated name is
    taken bottom up; indexes rather than values keep the message's order.
    """
    pool = {}
    for index, (name, _) in enumerate(fields):
        if index != sig_index:
            pool.setdefault(field_name(name), []).append(index)
    chosen = {sig_index}
    for name in names:
        found = pool.get(name.strip().lower().encode("latin-1"))
        if found:
            chosen.add(found.pop())
    return sorted(chosen)


def build(raw, domain, selector=None):
    """The blob, as text: attest_inline takes a string and encodes it UTF-8."""
    fields = parse_headers(header_block(raw))
    sig_index, tags = select(fields, domain, selector)
    names = [name for name in tags.get("h", "").split(":") if name.strip()]
    if not names:
        raise BlobError("the signature has an empty h= tag")
    blob = b"".join(fields[i][0] + b":" + fields[i][1] + b"\r\n"
                    for i in covered(fields, sig_index, names))
    try:
        # A header byte that is not UTF-8 would be re-encoded on its way into
        # calldata, and the signature would no longer cover what arrives.
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        raise BlobError("the signed headers are not UTF-8 text; attest_inline cannot carry them")
    if len(blob) > MAX_BLOB:
        raise BlobError("the blob is %d bytes, over the %d attest_inline takes"
                        % (len(blob), MAX_BLOB))
    return text


def tracked(path):
    """Whether git would track path: inside this repository and not ignored."""
    try:
        path.resolve().relative_to(ROOT)
    except ValueError:
        return False
    try:
        answer = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", str(path.resolve())],
                                capture_output=True)
    except OSError:
        return True
    # check-ignore exits 0 for an ignored path and 1 for one that is not.
    return answer.returncode != 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("message", help="path to a .eml file in a gitignored directory")
    parser.add_argument("domain", help="the d= of the signature to cut")
    parser.add_argument("selector", nargs="?", help="the s= of the signature to cut")
    parser.add_argument("--digest", action="store_true",
                        help="print the length and SHA-256 instead of the blob")
    args = parser.parse_args(argv)

    source = Path(args.message)
    if not source.is_file():
        raise SystemExit("message not found: %s" % (source,))
    if tracked(source):
        raise SystemExit("%s is inside the repository and not gitignored; move it to "
                         "samples/" % (source,))
    try:
        text = build(source.read_bytes(), args.domain, args.selector)
    except BlobError as error:
        raise SystemExit(str(error))
    data = text.encode("utf-8")
    if args.digest:
        print("bytes        : %d" % (len(data),))
        print("sha256       : %s" % (hashlib.sha256(data).hexdigest(),))
        return
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
