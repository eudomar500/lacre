#!/usr/bin/env python3
"""Build contracts/extractor/extractor.py from the template and two lacre modules.

lacre/dkimbody.py holds the body canonicalization and the MIME walk the body
probe measured on Bradbury; lacre/patterns.py holds the pattern document and
the canonical string. The tests drive both files, tools/extract_check.py runs
them off chain, and this script splices them into extractor_template.py at
the "# @@DKIMBODY@@" and "# @@PATTERNS@@" lines, so the deployed source cannot
drift from the tested source.

What is dropped on the way in, as in the Verifier build, because source is
charged by the byte:

- Definitions the contract never reaches, computed from the template's own
  names, transitively. dkimbody.py's fixed Amazon patterns are among them:
  the Extractor takes its patterns from storage.
- The "from lacre..." import in patterns.py. In the contract the names it
  imports are already defined above it, by the splice.
- Full-line comments, from all three files. The runner Depends line is the
  one comment kept, because the runner reads it.
- A second "import hashlib" and "import re", from the second module.
- Indentation beyond one space per level, and blank lines. See compact().

The limit is lower than the Verifier's on purpose: the Extractor is meant to
deploy well under the per-transaction cap, and MAX_SOURCE at roughly 870 gas
per byte keeps it near two thirds of 2^24.

Usage:
    python3 contracts/extractor/build.py
    python3 contracts/extractor/build.py --check
"""

import argparse
import ast
import io
import sys
import tokenize
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TEMPLATE = HERE / "extractor_template.py"
BODY = ROOT / "lacre" / "dkimbody.py"
PATTERNS = ROOT / "lacre" / "patterns.py"
OUTPUT = HERE / "extractor.py"
BODY_MARKER = "# @@DKIMBODY@@"
PATTERNS_MARKER = "# @@PATTERNS@@"
MAX_SOURCE = 13000


def defined_names(node):
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.Assign):
        return [t.id for t in node.targets if isinstance(t, ast.Name)]
    return []


def used_names(source):
    return {n.id for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Name)}


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


def local_import(node):
    return isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "lacre"


def prune(source, wanted):
    """source without unreachable definitions, lacre imports and comments.

    Other imports are kept: they are a handful of bytes and dropping one
    would be a way to break the contract quietly.
    """
    lines = source.split("\n")
    keep = reachable(source, wanted)
    spliced = ""
    for node in ast.parse(source).body:
        names = defined_names(node)
        if (names and not set(names) & keep) or local_import(node):
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
        if line.strip() in (BODY_MARKER, PATTERNS_MARKER) or not line.lstrip().startswith("#")
    ]
    return first + "\n" + "\n".join(kept)


def compact(source):
    """source with one space per indentation level and no blank lines.

    Worth about an eighth of the bytes, and so of the deploy gas. Only
    whitespace Python ignores is touched: a line that starts a statement gets
    one space per block level, a continuation line one more, and a line inside
    a multi-line string is left exactly as it was. build() refuses the result
    unless it parses to the same tree as the input.
    """
    lines = source.split("\n")
    starts, raw = {}, set()
    depth, fresh = 0, True
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.INDENT:
            depth += 1
        elif token.type == tokenize.DEDENT:
            depth -= 1
        elif token.type in (tokenize.NEWLINE, tokenize.NL, tokenize.COMMENT):
            fresh = fresh or token.type == tokenize.NEWLINE
            continue
        if token.type == tokenize.STRING and token.start[0] != token.end[0]:
            raw.update(range(token.start[0] + 1, token.end[0] + 1))
        if fresh and token.type not in (tokenize.INDENT, tokenize.DEDENT):
            starts[token.start[0]] = depth
            fresh = False
    out = [lines[0]]
    for number, line in enumerate(lines[1:], 2):
        if number in raw:
            out.append(line)
        elif line.strip():
            # Inside brackets indentation means nothing, so a continuation
            # line gets none.
            out.append(" " * starts.get(number, 0) + line.strip())
    return "\n".join(out) + ("\n" if source.endswith("\n") else "")


def without_repeated_imports(source):
    # Both modules import hashlib and re; importing a module twice at the top
    # level binds the same object again, so the second line is dropped.
    seen, out = set(), []
    for line in source.split("\n"):
        if line.startswith("import ") and line in seen:
            continue
        seen.add(line)
        out.append(line)
    return "\n".join(out)


def dropped_from(source, kept):
    return sorted(
        name
        for node in ast.parse(source).body
        for name in defined_names(node)
        if name not in kept
    )


def build():
    """(contract source, {module: dropped names})."""
    template = TEMPLATE.read_text(encoding="ascii")
    for marker in (BODY_MARKER, PATTERNS_MARKER):
        if template.count(marker) != 1:
            raise SystemExit("expected exactly one %s line in %s" % (marker, TEMPLATE.name))
    template = strip_comments(template)
    patterns = PATTERNS.read_text(encoding="ascii")
    body = BODY.read_text(encoding="ascii")
    # patterns.py is pruned against the template, and dkimbody.py against
    # both, since patterns.py is what reaches most of it.
    patterns_part, patterns_kept = prune(patterns, used_names(template))
    body_part, body_kept = prune(body, used_names(template) | used_names(patterns_part)
                                 | {n for node in ast.parse(patterns).body if local_import(node)
                                    for n in (alias.name for alias in node.names)})
    spliced = without_repeated_imports(
        template.replace(BODY_MARKER, body_part).replace(PATTERNS_MARKER, patterns_part))
    source = compact(spliced)
    if ast.dump(ast.parse(source)) != ast.dump(ast.parse(spliced)):
        raise SystemExit("compacting changed the program; refusing to write it")
    return source, {
        BODY.name: dropped_from(body, body_kept),
        PATTERNS.name: dropped_from(patterns, patterns_kept),
    }


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
    if "from lacre" in source or "import lacre" in source:
        problems.append("a lacre import survived the splice")
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

    source, dropped = build()
    problems = check(source)
    for problem in problems:
        print("error: %s" % (problem,), file=sys.stderr)

    print("template     : %6d bytes" % (len(TEMPLATE.read_text(encoding="ascii")),))
    print("dkimbody.py  : %6d bytes" % (len(BODY.read_text(encoding="ascii")),))
    print("patterns.py  : %6d bytes" % (len(PATTERNS.read_text(encoding="ascii")),))
    for name, names in dropped.items():
        print("dropped      : %s: %s" % (name, ", ".join(names) or "nothing"))
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
