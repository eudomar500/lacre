"""lacre/dkimcore.py against the probe's verifier, and the built contract.

The header verification on chain is a copy of the file the probe's own suite
drives, experiments/dkim-probe/dkim/core.py. Two copies of one verifier are a
liability unless something fails the moment they differ, which is what the
first test is for; the second one closes the same gap on the other side, so
that a change to either source has to be built before it can be deployed.
"""

import ast
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COPY = ROOT / "lacre" / "dkimcore.py"
ORIGIN = ROOT / "experiments" / "dkim-probe" / "dkim" / "core.py"
CONTRACT = ROOT / "contracts" / "verifier" / "verifier.py"
BUILD = ROOT / "contracts" / "verifier" / "build.py"


def load_build():
    spec = importlib.util.spec_from_file_location("verifier_build", BUILD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_dkimcore_is_the_probe_verifier_byte_for_byte():
    assert COPY.read_bytes() == ORIGIN.read_bytes()


def test_the_built_contract_is_current():
    build = load_build()
    source, _, _ = build.build()
    assert CONTRACT.read_text(encoding="ascii") == source
    assert len(source) <= build.MAX_SOURCE
    ast.parse(source)
