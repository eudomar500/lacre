"""integrations/consumer_example.py against the stubbed SDK.

tests/consumer_stub_run.py walks the example as a script before anyone copies
it; these are the same properties held in CI, one per test, so a change that
breaks the pattern the example is there to show fails here: reads at
LATEST_FINAL only, the Router resolved on every use, nothing that raises in a
view, and one delivery per signed message.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = load(ROOT / "tests" / "consumer_stub_run.py", "lacre_test_consumer_harness")
stub = harness.stub
FINAL = stub.StorageType.LATEST_FINAL


@pytest.fixture
def world(monkeypatch):
    # The loader installs a fake genlayer module; monkeypatch puts back
    # whatever was there so no other test sees it.
    for name in ("genlayer", "genlayer.py", "genlayer.py.public_abi"):
        monkeypatch.setitem(sys.modules, name, None)
    node, router, verifier, verifier_b, patterns, llm = harness.world()
    contract, module = harness.load_contract(node)
    return {"node": node, "router": router, "verifier": verifier, "verifier_b": verifier_b,
            "patterns": patterns, "llm": llm, "contract": contract, "module": module}


def test_the_source_is_ascii_and_starts_with_the_runner_line():
    source = harness.CONTRACT.read_text(encoding="ascii")
    lines = source.split("\n")
    assert lines[0].startswith('# { "Depends": "py-genlayer:')
    assert lines[2:4] == ["# Lacre: a signed-evidence primitive for GenLayer.",
                          "# By Insidr Labs, MIT license."]


def test_only_the_router_is_kept(world):
    contract = world["contract"]
    assert contract.router() == harness.ROUTER.lower()
    kept = [name for name, value in vars(contract).items() if isinstance(value, stub.Address)]
    assert kept == ["router_address"]


@pytest.mark.parametrize("fields,domain,bits,expected", [
    ({}, "amazon.com", 1024, True),
    ({}, " Amazon.COM. ", 1024, True),
    ({}, "amazon.com", 1025, False),
    ({}, "example.com", 1024, False),
    ({"valid": False}, "amazon.com", 1024, False),
    ({"aligned": False}, "amazon.com", 1024, False),
    ({"requester": harness.AGENT}, "amazon.com", 1024, True),
])
def test_require_attestation_is_check_for(world, fields, domain, bits, expected):
    world["verifier"].records["5"] = harness.verifier_record("5", **fields)
    assert world["contract"].require_attestation("5", domain, bits) is expected


def test_an_unknown_record_is_not_attested(world):
    assert world["contract"].require_attestation("42", "amazon.com", 1024) is False


@pytest.mark.parametrize("lane", ["patterns", "llm", " Patterns "])
def test_require_shipped_on_each_lane(world, lane):
    assert world["contract"].require_shipped("0", lane) is True


@pytest.mark.parametrize("fields", [
    {"match": False},
    {"shipped": False},
    {"reason": "no text part"},
    {"verifier": harness.VERIFIER_B},
    {"requester": harness.AGENT},
])
def test_require_shipped_refuses_anything_but_a_shipped_extraction(world, fields):
    world["verifier"].records["5"] = harness.verifier_record("5")
    world["patterns"].add("5", **fields)
    assert world["contract"].require_shipped("5", "patterns") is False


def test_an_unknown_lane_is_not_shipped(world):
    assert world["contract"].require_shipped("0", "extractor") is False


def test_every_read_is_at_latest_final(world):
    contract = world["contract"]
    contract.require_attestation("0", "amazon.com", 1024)
    contract.require_shipped("0", "patterns")
    contract.require_shipped("0", "llm")
    for name in ("router", "verifier", "patterns", "llm"):
        assert world[name].states and set(world[name].states) == {FINAL}, name


def test_the_router_is_resolved_on_every_use(world):
    contract, router = world["contract"], world["router"]
    assert contract.require_attestation("0", "amazon.com", 1024) is True
    router.names["verifier"] = harness.VERIFIER_B
    assert contract.require_attestation("0", "amazon.com", 1024) is False
    assert contract.require_shipped("0", "patterns") is False
    assert world["verifier_b"].states


@pytest.mark.parametrize("broken", ["router", "verifier", "patterns"])
def test_an_unreadable_contract_reads_as_false_and_never_raises(world, broken):
    world[broken].broken = True
    contract = world["contract"]
    assert contract.require_attestation("0", "amazon.com", 1024) is (broken == "patterns")
    assert contract.require_shipped("0", "patterns") is False


def test_the_scan_is_bounded_to_the_newest_extractions(world):
    patterns, limit = world["patterns"], world["module"].MAX_SCAN
    world["verifier"].records["5"] = harness.verifier_record("5")
    patterns.add("5")
    for _ in range(limit):
        patterns.add("0")
    before = patterns.reads
    assert world["contract"].require_shipped("5", "patterns") is False
    assert patterns.reads - before == limit


def test_mark_delivered_needs_both_checks(world):
    contract = world["contract"]
    world["verifier"].records["5"] = harness.verifier_record("5", aligned=False)
    world["patterns"].add("5")
    world["verifier"].records["6"] = harness.verifier_record("6")
    with pytest.raises(stub.UserError, match="no accepted attestation"):
        contract.mark_delivered("5", "patterns")
    with pytest.raises(stub.UserError, match="no shipped extraction"):
        contract.mark_delivered("6", "patterns")
    assert len(contract.delivered) == 0 and len(contract.messages) == 0


def test_mark_delivered_stores_the_verifier_and_the_record_once_per_message(world):
    contract, verifier = world["contract"], world["verifier"]
    key = contract.mark_delivered("0", "patterns")
    assert key == harness.VERIFIER.lower() + "/0"
    assert contract.delivered_at(harness.VERIFIER, "0") == harness.DATETIME
    assert contract.delivered_at(harness.VERIFIER_B, "0") == ""
    with pytest.raises(stub.UserError, match="already delivered"):
        contract.mark_delivered("0", "llm")
    # The same signed message attested again is a new record, not a new delivery.
    verifier.records["5"] = harness.verifier_record("5")
    world["llm"].add("5")
    with pytest.raises(stub.UserError, match="already delivered"):
        contract.mark_delivered("5", "llm")
    verifier.records["5"] = harness.verifier_record("5", bh="another-bh")
    assert contract.mark_delivered("5", "llm") == harness.VERIFIER.lower() + "/5"
