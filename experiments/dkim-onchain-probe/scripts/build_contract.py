#!/usr/bin/env python3
"""Build contracts/dkim_probe.py from the template and dkim/core.py.

core.py is the one source of the verification logic; it is used unchanged by
the off-chain probe, by the tests and by the contract. This script splices it
into scripts/contract_template.py at the "# @@CORE@@" marker and writes the
result, so the deployed source can never drift from the tested source.

The build fails above MAX_SOURCE bytes. Bradbury caps a transaction at 2^24
gas and a deploy costs roughly 730 gas per byte of contract source, comments
included, which puts the practical ceiling near 20 KB.

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
CORE = ROOT.parent / "dkim-probe" / "dkim" / "core.py"
OUTPUT = ROOT / "contracts" / "dkim_probe.py"
MARKER = "# @@CORE@@"
MAX_SOURCE = 19000


def build():
    template = TEMPLATE.read_text(encoding="ascii")
    if template.count(MARKER) != 1:
        raise SystemExit("expected exactly one %s line in %s" % (MARKER, TEMPLATE.name))
    core = CORE.read_text(encoding="ascii").strip("\n")
    return template.replace(MARKER, core)


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
    print("core.py      : %6d bytes" % (len(CORE.read_text(encoding="ascii")),))
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
