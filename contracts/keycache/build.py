#!/usr/bin/env python3
"""Build contracts/keycache/keycache.py from the template and lacre/dkimkey.py.

dkimkey.py is the one source of the DoH and DER parsing: the tests drive that
file, this script splices it into keycache_template.py at the "# @@DKIMKEY@@"
line, and the result is what gets deployed, so the deployed source cannot
drift from the tested source.

This is the Registry v1 build with the names changed: the KeyCache took over
the Registry's key half, dkimkey.py and all.

Two things are dropped on the way in, the same way the Verifier build drops
them, because source is charged by the byte and a deploy has one transaction
to fit in:

- Definitions the contract never reaches. The KeyCache compares the DER two
  resolvers publish and decodes it itself, so key_from_tags, which the tests
  still use, is dead code on chain. What survives is computed from the
  template's own names, transitively, not from a list that could go stale.
- Full-line comments, from both halves. The source files keep them and are
  where the code is read; the deployed artifact carries none. The runner
  Depends line is the one comment kept, because the runner reads it.

Bradbury caps a transaction at 2^24 gas and a deploy costs roughly 870 gas per
byte of source. The build refuses anything over MAX_SOURCE bytes rather than
let the node refuse the signed transaction.

Usage:
    python3 contracts/keycache/build.py
    python3 contracts/keycache/build.py --check
"""

import argparse
import ast
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TEMPLATE = HERE / "keycache_template.py"
SOURCE = ROOT / "lacre" / "dkimkey.py"
OUTPUT = HERE / "keycache.py"
MARKER = "# @@DKIMKEY@@"
MAX_SOURCE = 14000


def defined_names(node):
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.Assign):
        return [t.id for t in node.targets if isinstance(t, ast.Name)]
    return []


def reachable(source, wanted):
    """The top level names of source that wanted needs, transitively."""
    defined = {}
    for node in ast.parse(source).body:
        names = defined_names(node)
        used = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
        for name in names:
            defined[name] = used - set(names)

    keep = set()
    pending = {name for name in defined if name in wanted}
    while pending:
        name = pending.pop()
        keep.add(name)
        pending |= {used for used in defined[name] if used in defined} - keep
    return keep


def prune(source, wanted):
    """source with the unreachable definitions and the comments removed.

    Imports and anything else that is not a definition are kept: they are a
    handful of bytes and dropping one would be a way to break the contract
    quietly.
    """
    lines = source.split("\n")
    keep = reachable(source, wanted)
    spliced = ""
    for node in ast.parse(source).body:
        names = defined_names(node)
        if names and not set(names) & keep:
            continue
        start = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
        body = [
            line
            for line in lines[start - 1:node.end_lineno]
            if not line.lstrip().startswith("#")
        ]
        if not spliced:
            spliced = "\n".join(body)
        else:
            gap = "\n" if isinstance(node, (ast.Import, ast.ImportFrom)) else "\n\n\n"
            spliced += gap + "\n".join(body)
    return spliced, keep


def strip_comments(template):
    first, _, rest = template.partition("\n")
    kept = [
        line
        for line in rest.split("\n")
        if line.strip() == MARKER or not line.lstrip().startswith("#")
    ]
    return first + "\n" + "\n".join(kept)


def build():
    template = TEMPLATE.read_text(encoding="ascii")
    if template.count(MARKER) != 1:
        raise SystemExit("expected exactly one %s line in %s" % (MARKER, TEMPLATE.name))
    template = strip_comments(template)
    source = SOURCE.read_text(encoding="ascii")
    wanted = {n.id for n in ast.walk(ast.parse(template)) if isinstance(n, ast.Name)}
    spliced, kept = prune(source, wanted)
    dropped = sorted(
        name
        for node in ast.parse(source).body
        for name in defined_names(node)
        if name not in kept
    )
    return template.replace(MARKER, spliced), spliced, dropped


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

    source, spliced, dropped = build()
    problems = check(source)
    for problem in problems:
        print("error: %s" % (problem,), file=sys.stderr)

    print("template     : %6d bytes" % (len(TEMPLATE.read_text(encoding="ascii")),))
    print("dkimkey.py   : %6d bytes" % (len(SOURCE.read_text(encoding="ascii")),))
    print("spliced      : %6d bytes" % (len(spliced),))
    print("dropped      : %s" % (", ".join(dropped) or "nothing",))
    print("contract     : %6d bytes (limit %d)" % (len(source), MAX_SOURCE))
    print("headroom     : %6d bytes" % (MAX_SOURCE - len(source),))
    print("deploy gas   : %6d estimated at 870 gas per byte, %.1f%% of 2^24"
          % (870 * len(source), 100.0 * 870 * len(source) / 2 ** 24))

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
