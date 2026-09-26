#!/usr/bin/env python3
"""Build contracts/router/router.py from router_template.py.

The Router inlines nothing from lacre/, so the build does one thing the
Registry and Verifier builds also do: it drops full-line comments, because
source is charged by the byte and a deploy has one transaction to fit in. The
template keeps them and is where the code is read; the deployed artifact
carries none. The runner Depends line is the one comment kept, because the
runner reads it.

Bradbury caps a transaction at 2^24 gas and a deploy costs roughly 870 gas per
byte of source. The build refuses anything over MAX_SOURCE bytes rather than
let the node refuse the signed transaction.

Usage:
    python3 contracts/router/build.py
    python3 contracts/router/build.py --check
"""

import argparse
import ast
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TEMPLATE = HERE / "router_template.py"
OUTPUT = HERE / "router.py"
MAX_SOURCE = 8000
GAS_PER_BYTE = 870
GAS_CAP = 2 ** 24


def strip_comments(template):
    first, _, rest = template.partition("\n")
    kept = [line for line in rest.split("\n") if not line.lstrip().startswith("#")]
    return first + "\n" + "\n".join(kept)


def build():
    return strip_comments(TEMPLATE.read_text(encoding="ascii"))


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

    gas = GAS_PER_BYTE * len(source)
    print("template     : %6d bytes" % (len(TEMPLATE.read_text(encoding="ascii")),))
    print("contract     : %6d bytes (limit %d)" % (len(source), MAX_SOURCE))
    print("headroom     : %6d bytes" % (MAX_SOURCE - len(source),))
    print("deploy gas   : %6d estimated at %d gas per byte, %.1f%% of 2^24"
          % (gas, GAS_PER_BYTE, 100.0 * gas / GAS_CAP))

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
