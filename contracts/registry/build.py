#!/usr/bin/env python3
"""Build contracts/registry/registry.py from the template and lacre/dkimkey.py.

dkimkey.py is the one source of the DoH and DER parsing: the tests drive that
file, this script splices it into registry_template.py at the "# @@DKIMKEY@@"
line, and the result is what gets deployed, so the deployed source cannot
drift from the tested source.

Bradbury caps a transaction at 2^24 gas and a deploy costs roughly 870 gas per
byte of source, comments included: 11 889 bytes estimated at 10 373 247 gas,
62 percent of the cap. The build refuses anything over MAX_SOURCE bytes rather
than let the node refuse the signed transaction.

Usage:
    python3 contracts/registry/build.py
    python3 contracts/registry/build.py --check
"""

import argparse
import ast
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TEMPLATE = HERE / "registry_template.py"
SOURCE = ROOT / "lacre" / "dkimkey.py"
OUTPUT = HERE / "registry.py"
MARKER = "# @@DKIMKEY@@"
MAX_SOURCE = 13000


def build():
    template = TEMPLATE.read_text(encoding="ascii")
    if template.count(MARKER) != 1:
        raise SystemExit("expected exactly one %s line in %s" % (MARKER, TEMPLATE.name))
    return template.replace(MARKER, SOURCE.read_text(encoding="ascii").strip("\n"))


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
    print("dkimkey.py   : %6d bytes" % (len(SOURCE.read_text(encoding="ascii")),))
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

    OUTPUT.write_text(source, encoding="ascii")
    print("written      : %s" % (OUTPUT.relative_to(ROOT),))


if __name__ == "__main__":
    main()
