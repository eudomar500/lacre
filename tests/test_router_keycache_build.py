"""The Router and KeyCache artifacts against what their builds produce now.

tests/test_dkimcore.py does this for the Verifier. The two contracts that
split the Registry get the same check, so a template edit that was not built
fails here instead of at deploy time, and the source a deploy would send is
held to the cap its build enforces.
"""

import ast
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ["router", "keycache"]


def load_build(name):
    path = ROOT / "contracts" / name / "build.py"
    spec = importlib.util.spec_from_file_location("%s_build" % (name,), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def built(build):
    # The Router build returns the source alone; the KeyCache build, like
    # the Registry's, returns it with what it spliced and dropped.
    result = build.build()
    return result[0] if isinstance(result, tuple) else result


@pytest.mark.parametrize("name", CONTRACTS)
def test_the_built_contract_is_current(name):
    build = load_build(name)
    source = built(build)
    artifact = ROOT / "contracts" / name / ("%s.py" % (name,))
    assert artifact.read_text(encoding="ascii") == source
    assert build.check(source) == []
    ast.parse(source)


@pytest.mark.parametrize("name", CONTRACTS)
def test_only_the_runner_line_survives_as_a_comment(name):
    source = built(load_build(name))
    comments = [line for line in source.split("\n") if line.lstrip().startswith("#")]
    assert comments == [source.split("\n", 1)[0]]
    assert comments[0].startswith('# { "Depends": "py-genlayer:')


def test_the_keycache_splices_the_key_parser():
    build = load_build("keycache")
    source, _, dropped = build.build()
    assert "def decode_spki(" in source and "def txt_from_doh(" in source
    assert dropped == ["key_from_tags"]


def test_the_router_knows_nothing_about_keys_or_fees():
    source = built(load_build("router"))
    for word in ("payable", "web.get", "eq_principle", "fee", "domainkey"):
        assert word not in source, word
