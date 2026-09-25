#!/usr/bin/env python3
"""Build contracts/llm_probe2.py from the template, llm/prompt.py and llm/fields.py.

The two modules are the one source of the prompt and the normalization; the
tests import them directly and the contract carries copies spliced in at the
"# @@PROMPT@@" and "# @@FIELDS@@" markers, so the deployed source cannot drift
from the tested source. llm/prefilter.py is not spliced: it is measured
locally and the contract does not call it.

The build fails above MAX_SOURCE bytes, the same cap as probe D. Bradbury caps
a transaction at 2^24 gas and a deploy costs roughly 870 gas per byte of
contract source, comments included.

Usage:
    python3 experiments/llm-probe-2/scripts/build_contract.py
    python3 experiments/llm-probe-2/scripts/build_contract.py --check
"""

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "scripts" / "contract_template.py"
PARTS = (
    ("# @@PROMPT@@", ROOT / "llm" / "prompt.py"),
    ("# @@FIELDS@@", ROOT / "llm" / "fields.py"),
)
OUTPUT = ROOT / "contracts" / "llm_probe2.py"
MAX_SOURCE = 12000


def build():
    source = TEMPLATE.read_text(encoding="ascii")
    for marker, path in PARTS:
        if source.count(marker) != 1:
            raise SystemExit("expected exactly one %s line in %s"
                             % (marker, TEMPLATE.name))
        source = source.replace(marker, path.read_text(encoding="ascii").strip("\n"))
    return source


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
    for _, path in PARTS:
        print("%-13s: %6d bytes" % (path.name, len(path.read_text(encoding="ascii"))))
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
