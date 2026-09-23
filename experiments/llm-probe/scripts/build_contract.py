#!/usr/bin/env python3
"""Build contracts/llm_probe.py from the template and llm/fields.py.

fields.py is the one source of the normalization, the weekday table and the
result vocabulary; the tests import it directly and the contract carries a
copy of it spliced in at the "# @@FIELDS@@" marker, so the deployed source
cannot drift from the tested source.

The build fails above MAX_SOURCE bytes. Bradbury caps a transaction at 2^24
gas and a deploy costs roughly 840 gas per byte of contract source, comments
included. This probe carries a prompt rather than a verifier, so the ceiling
is here to catch a runaway prompt, not to be approached.

Usage:
    python3 experiments/llm-probe/scripts/build_contract.py
    python3 experiments/llm-probe/scripts/build_contract.py --check
"""

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "scripts" / "contract_template.py"
FIELDS = ROOT / "llm" / "fields.py"
OUTPUT = ROOT / "contracts" / "llm_probe.py"
MARKER = "# @@FIELDS@@"
MAX_SOURCE = 12000


def build():
    template = TEMPLATE.read_text(encoding="ascii")
    if template.count(MARKER) != 1:
        raise SystemExit("expected exactly one %s line in %s" % (MARKER, TEMPLATE.name))
    fields = FIELDS.read_text(encoding="ascii").strip("\n")
    return template.replace(MARKER, fields)


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
    print("fields.py    : %6d bytes" % (len(FIELDS.read_text(encoding="ascii")),))
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
