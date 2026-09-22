#!/usr/bin/env python3
"""Build contracts/body_probe.py from the template and dkim/body.py.

body.py is the one source of the canonicalization, the quoted-printable
decoder and the field patterns; it is used unchanged by make_body.py, by the
tests and by the contract. This script splices it into
scripts/contract_template.py at the "# @@BODY@@" marker and writes the result,
so the deployed source can never drift from the tested source.

The build fails above MAX_SOURCE bytes. Bradbury caps a transaction at 2^24
gas and a deploy costs roughly 840 gas per byte of contract source, comments
included; this probe carries no RSA and has no reason to come near the ceiling
the header probe measured.

Usage:
    python3 scripts/build_contract.py
    python3 scripts/build_contract.py --check
"""

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "scripts" / "contract_template.py"
BODY = ROOT.parent / "dkim-probe" / "dkim" / "body.py"
OUTPUT = ROOT / "contracts" / "body_probe.py"
MARKER = "# @@BODY@@"
MAX_SOURCE = 12000


def build():
    template = TEMPLATE.read_text(encoding="ascii")
    if template.count(MARKER) != 1:
        raise SystemExit("expected exactly one %s line in %s" % (MARKER, TEMPLATE.name))
    body = BODY.read_text(encoding="ascii").strip("\n")
    return template.replace(MARKER, body)


def check(source):
    """Everything a deploy would reject, before any gas is spent."""
    problems = []
    if not source.startswith('# { "Depends":'):
        problems.append("the runner Depends comment must be the first line")
    try:
        source.encode("ascii")
    except UnicodeEncodeError as error:
        problems.append("non-ASCII byte at offset %d" % (error.start,))
    try:
        ast.parse(source)
    except SyntaxError as error:
        problems.append("syntax error on line %s: %s" % (error.lineno, error.msg))
    if len(source) > MAX_SOURCE:
        problems.append(
            "contract source is %d bytes, over the %d byte limit"
            % (len(source), MAX_SOURCE)
        )
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the built file is current instead of writing it",
    )
    args = parser.parse_args()

    source = build()
    problems = check(source)
    for problem in problems:
        print("error: %s" % (problem,), file=sys.stderr)

    print("template     : %6d bytes" % (len(TEMPLATE.read_text(encoding="ascii")),))
    print("body.py      : %6d bytes" % (len(BODY.read_text(encoding="ascii")),))
    print("contract     : %6d bytes (limit %d)" % (len(source), MAX_SOURCE))
    print("headroom     : %6d bytes" % (MAX_SOURCE - len(source),))

    if problems:
        sys.exit(1)

    if args.check:
        current = OUTPUT.read_text(encoding="ascii") if OUTPUT.is_file() else ""
        if current != source:
            print("error: %s is out of date; run without --check" % (OUTPUT.name,),
                  file=sys.stderr)
            sys.exit(1)
        print("status       : up to date")
        return

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(source, encoding="ascii")
    print("written      : %s" % (OUTPUT.relative_to(ROOT.parent.parent),))


if __name__ == "__main__":
    main()
