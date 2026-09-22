#!/usr/bin/env python3
"""Cut the raw body of a message, exactly as it was delivered.

The output is every byte after the first empty line, with the line endings the
file already carries and no decoding of any kind. That octet stream is what a
DKIM signature's bh= tag is computed over, so a single rewritten byte changes
the hash. Nothing from the message is printed: stdout carries the byte count
and the simple canonicalized body hash, and that is all, so the hash can be
compared with the signature's bh= before any gas is spent.

Usage:
    python3 make_body.py path/to/message.eml
    python3 make_body.py path/to/message.eml --out /tmp/body.bin
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dkim import rfc6376
from dkim.body import body_hash

DEFAULT_OUT = "/tmp/lacre-body.bin"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("message", help="path to a .eml file")
    parser.add_argument("--out", default=DEFAULT_OUT, help="output path")
    args = parser.parse_args()

    source = Path(args.message)
    if not source.is_file():
        raise SystemExit("message not found: %s" % (source,))

    _, raw_body = rfc6376.split_message(source.read_bytes())
    if not raw_body:
        raise SystemExit("no body: nothing follows the first empty line")

    Path(args.out).write_bytes(raw_body)
    print(len(raw_body))
    print(body_hash(raw_body))


if __name__ == "__main__":
    main()
