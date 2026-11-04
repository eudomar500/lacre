#!/usr/bin/env python3
"""Run a contract's stub harness on its Bradbury Phase 2 build (contracts/<name>/<name>_p2.py).

The harness is the same file and the same checks as for the original contract; only the
stubbed SDK is shown to the contract under the GenVM v0.3.0 names (tools/build_p2.py):
import genlayer as gl, genlayer.storage, genlayer.types, gl.contract.Contract, gl.contract.get_at,
gl.contract.StorageView and gl.message.raw. StorageView.LATEST_FINALIZED is the stub's
StorageType.LATEST_FINAL (both are 1). Each name points at the very object the harness
built for the original, so a check that passes on one and fails on the other can only come
from the contract. The old names are removed, so the _p2 build cannot fall back on them.

Two checks of the built file are read with the Phase 2 layout, in this run only: the comments are
the two header lines (# v0.3.0 and the runner line), and the size limit is 150 bytes higher, for
that header and the longer imports. Every other check is the original's.

Usage:
    python3 tests/p2_stub_run.py router|keycache|verifier|extractor|llmextractor
    python3 tests/p2_stub_run.py --compare      runs each harness on both builds and compares the output
"""

import importlib
import re
import subprocess
import sys
import types
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
NAMES = ("router", "keycache", "verifier", "extractor", "llmextractor")
P2_LIMITS = {"the built contract is under 13000 bytes": 13150, "the built contract is under 14000 bytes": 14150}
P2_HEADER = "only the runner line survives as a comment"
MOVED = ("Contract", "get_contract_at", "message_raw")


def p2_sdk(old, storage_type):
    """The original stub's genlayer module, as GenVM v0.3.0 names it."""
    g = old.gl
    p = types.ModuleType("genlayer")
    for key, value in vars(g).items():
        if key not in MOVED:
            setattr(p, key, value)
    p.gl = g  # the harnesses patch sys.modules["genlayer"].gl.nondet and .eq_principle while they run
    contract = types.ModuleType("genlayer.contract")
    contract.Contract = g.Contract
    contract.get_at = getattr(g, "get_contract_at", None)
    contract.StorageView = types.SimpleNamespace(DEFAULT=storage_type.DEFAULT,
                                                 LATEST_FINALIZED=storage_type.LATEST_FINAL,
                                                 LATEST_DECIDED=storage_type.LATEST_NON_FINAL)
    p.contract = contract
    # gl.message.raw reads gl.message_raw at call time, as the original does
    type(g.message).raw = property(lambda _self: g.message_raw)
    storage = types.ModuleType("genlayer.storage")
    storage.TreeMap, storage.DynArray, storage.allow = old.TreeMap, old.DynArray, old.allow_storage
    p.storage = storage
    typ = types.ModuleType("genlayer.types")
    typ.Address, typ.u256 = old.Address, old.u256
    p.types = typ
    sys.modules.update({"genlayer.contract": contract, "genlayer.storage": storage, "genlayer.types": typ})
    return p


def run(name):
    sys.path.insert(0, str(TESTS))
    sys.path.insert(0, str(ROOT))
    mod = importlib.import_module(name + "_stub_run")
    p2 = ROOT / "contracts" / name / (name + "_p2.py")
    if not p2.is_file():
        sys.exit("%s does not exist; run tools/build_p2.py first" % p2)
    verifier = importlib.import_module("verifier_stub_run")
    storage_type = verifier.StorageType
    for m in {mod, verifier, *(sys.modules.get(n + "_stub_run") for n in NAMES)} - {None}:
        if hasattr(m, "build_sdk"):
            original = m.build_sdk
            m.build_sdk = (lambda orig: lambda node: p2_sdk(orig(node), storage_type))(original)
    source = p2.read_text(encoding="ascii")
    original_check = verifier.Report.check

    def check(self, label, condition, detail=""):
        if label in P2_LIMITS:
            condition = len(source) < P2_LIMITS[label]
            detail = "%d bytes, Phase 2 limit %d" % (len(source), P2_LIMITS[label])
        elif label == P2_HEADER:
            lines = source.split("\n")
            condition = [line for line in lines if line.lstrip().startswith("#")] == lines[:2]
            detail = "Phase 2: the two header lines"
        return original_check(self, label, condition, detail)

    verifier.Report.check = check
    mod.CONTRACT = p2
    if name in ("router", "keycache"):
        sys.argv = [sys.argv[0], str(p2)]
    mod.main()


def normalize(text):
    """The run output without the lines that name the file and its size, and the live DNS answer's size;
    the two build checks read with the Phase 2 layout are compared on their verdict and label only."""
    out = []
    for line in text.splitlines():
        if re.match(r"\s*(contract|resolver)\s*:", line):
            line = "<contract>"
        elif any(label in line for label in (*P2_LIMITS, P2_HEADER)):
            line = line[:63].rstrip()
        out.append(line)
    return out


def compare():
    failed = 0
    for name in NAMES:
        a = subprocess.run([sys.executable, str(TESTS / (name + "_stub_run.py"))], capture_output=True, text=True, cwd=ROOT)
        b = subprocess.run([sys.executable, __file__, name], capture_output=True, text=True, cwd=ROOT)
        same = a.returncode == b.returncode == 0 and normalize(a.stdout) == normalize(b.stdout)
        summary = (a.stdout.strip().splitlines() or ["(no output)"])[-1]
        print("%-13s original exit %d, p2 exit %d, output %s  (%s)" % (name, a.returncode, b.returncode, "identical" if same else "DIFFERS", summary))
        if not same:
            failed += 1
            for x, y in zip(normalize(a.stdout), normalize(b.stdout)):
                if x != y:
                    print("   original: %s\n   p2:       %s" % (x[:160], y[:160]))
                    break
            if b.stderr.strip():
                print("   p2 stderr: " + b.stderr.strip().splitlines()[-1][:200])
    print("p2 stub runs: %s" % ("all identical" if not failed else "%d differ" % failed))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    if sys.argv[1:] == ["--compare"]:
        compare()
    elif len(sys.argv) == 2 and sys.argv[1] in NAMES:
        run(sys.argv[1])
    else:
        sys.exit(__doc__)
