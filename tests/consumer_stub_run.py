#!/usr/bin/env python3
"""Drive integrations/consumer_example.py against a stubbed SDK.

The example is executed as written, with a stand-in for what the runner gives
it: storage, gl.message, and the views of the Router, the Verifier and the
two Extractors. The Verifier's check_for is reproduced from docs/interfaces.md
section 4.5, and the Extractor records carry the fields section 10 lists, so
what is tested is the example's reading of them, not the Lacre contracts,
which have their own stub runs. Nothing is deployed and no network is used.

Usage:
    python3 tests/consumer_stub_run.py
"""

import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

import verifier_stub_run as stub

CONTRACT = ROOT / "integrations" / "consumer_example.py"

VERIFIER = "0x5555555555555555555555555555555555555555"
VERIFIER_B = "0x6666666666666666666666666666666666666666"
EXTRACTOR = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
EXTRACTOR_LLM = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ROUTER, STRANGER, AGENT, OWNER = stub.ROUTER, stub.STRANGER, stub.AGENT, stub.OWNER
DATETIME = stub.DATETIME
BH = stub.BH


class Verifier:
    """get() and check_for() as Verifier v1.2 answers them."""

    def __init__(self):
        self.records = {}
        self.states = []
        self.broken = False

    def view(self, *, state=stub.StorageType.LATEST_NON_FINAL):
        self.states.append(state)
        return self

    def get(self, record_id):
        if self.broken:
            raise RuntimeError("the Verifier reverted")
        return dict(self.records.get(str(record_id), {}))

    def check_for(self, record_id, domain, min_key_bits, requester):
        if self.broken:
            raise RuntimeError("the Verifier reverted")
        held = self.records.get(str(record_id))
        try:
            who = stub.Address(requester)
        except ValueError:
            return False
        return held is not None and (
            held["valid"] and held["aligned"]
            and held["domain"] == str(domain).strip().lower().strip(".")
            and int(held["key_bits"]) >= int(min_key_bits)
            and stub.Address(held["requester"]) == who)


class Extractor:
    """records_of() and get_record() as both Extractor lanes answer them."""

    def __init__(self, method):
        self.method = method
        self.records = []
        self.states = []
        self.broken = False
        self.reads = 0

    def view(self, *, state=stub.StorageType.LATEST_NON_FINAL):
        self.states.append(state)
        return self

    def add(self, record_id, verifier=VERIFIER, requester=STRANGER, match=True,
            shipped=True, reason="extracted"):
        self.records.append({
            "id": str(len(self.records)), "schema_version": "1", "method": self.method,
            "verifier": verifier, "record_id": str(record_id), "domain": "amazon.com",
            "bh": BH, "match": match, "reason": reason, "shipped": match and shipped,
            "eta_day": "miercoles", "eta_date": "", "order_id_found": False,
            "signed_at": stub.SIGNED_AT, "requester": requester,
            "extracted_at": DATETIME, "fee_paid": "0"})
        return str(len(self.records) - 1)

    def records_of(self, requester):
        if self.broken:
            raise RuntimeError("the Extractor reverted")
        who = str(requester).lower()
        return [r["id"] for r in self.records if r["requester"].lower() == who]

    def get_record(self, record_id):
        self.reads += 1
        index = int(record_id)
        return dict(self.records[index]) if 0 <= index < len(self.records) else {}


def verifier_record(record_id, domain="amazon.com", key_bits="1024", valid=True,
                    aligned=True, requester=STRANGER, bh=BH, signed_at=stub.SIGNED_AT):
    return {"id": str(record_id), "domain": domain, "selector": stub.SELECTOR, "bh": bh,
            "body_canon": "simple", "message_id_sha256": "", "key_bits": key_bits,
            "key_sha256": "", "valid": valid, "reason": "header signature verified",
            "from_domain": domain, "aligned": aligned, "signed_at": signed_at,
            "source": "inline", "requester": requester, "attested_at": DATETIME,
            "fee_paid": "0", "schema_version": "2"}


class Node(stub.Node):
    """stub.Node with every Lacre contract the example may reach."""

    def __init__(self, router, contracts):
        super().__init__(router, {})
        self.contracts = contracts

    def contract_at(self, address):
        if not isinstance(address, stub.Address):
            raise TypeError("address expected")
        if address == stub.Address(ROUTER):
            return self.router
        for where, contract in self.contracts.items():
            if address == stub.Address(where):
                return contract
        raise AssertionError("the contract reached an address it should not")


def load_contract(node):
    """The example, loaded against node, as (contract, module)."""
    sys.modules["genlayer"] = stub.build_sdk(node)
    sys.modules["genlayer.py"] = types.ModuleType("genlayer.py")
    public_abi = types.ModuleType("genlayer.py.public_abi")
    public_abi.StorageType = stub.StorageType
    sys.modules["genlayer.py.public_abi"] = public_abi
    module = types.ModuleType("consumer_example")
    module.__file__ = str(CONTRACT)
    exec(compile(CONTRACT.read_text(encoding="ascii"), str(CONTRACT), "exec"),
         module.__dict__)

    contract = module.Contract.__new__(module.Contract)
    for name, annotation in module.Contract.__annotations__.items():
        if getattr(annotation, "__origin__", annotation) is stub.TreeMap:
            setattr(contract, name, stub.TreeMap())
    contract.__init__(ROUTER)
    return contract, module


def world():
    """A Router naming one Verifier and both lanes, with record 0 extracted
    and shipped on each lane: (node, router, verifier, patterns, llm)."""
    verifier, verifier_b = Verifier(), Verifier()
    patterns, llm = Extractor("patterns"), Extractor("llm")
    verifier.records["0"] = verifier_record("0")
    patterns.add("0")
    llm.add("0")
    router = stub.Router({"verifier": VERIFIER, "extractor": EXTRACTOR,
                          "extractor_llm": EXTRACTOR_LLM})
    node = Node(router, {VERIFIER: verifier, VERIFIER_B: verifier_b,
                         EXTRACTOR: patterns, EXTRACTOR_LLM: llm})
    return node, router, verifier, verifier_b, patterns, llm


def main():
    node, router, verifier, verifier_b, patterns, llm = world()
    contract, module = load_contract(node)
    source = CONTRACT.read_text(encoding="ascii")
    print("contract     : %s (%d bytes)\n" % (CONTRACT.relative_to(ROOT), len(source)))
    report = stub.Report()

    def attestation(record_id="0", domain="amazon.com", bits=1024):
        return contract.require_attestation(record_id, domain, bits)

    report.check("the runner Depends line is the first line",
                 source.startswith('# { "Depends": "py-genlayer:'))
    report.check("router() is the constructor argument", contract.router() == ROUTER.lower())
    report.check("the Router is the only Lacre address in state",
                 [name for name, value in vars(contract).items()
                  if isinstance(value, stub.Address)] == ["router_address"])

    # require_attestation
    report.check("a valid, aligned record of the domain passes", attestation() is True)
    report.check("the domain is compared as the Verifier normalizes it",
                 attestation(" 0 ", "Amazon.COM.") is True)
    report.check("a key floor above the record's key_bits fails",
                 attestation(bits=2048) is False)
    report.check("another domain fails", attestation(domain="example.com") is False)
    report.check("an unknown record fails", attestation("9") is False)
    for record_id, label, fields in (("1", "a record with valid false fails", {"valid": False}),
                                     ("2", "a record with aligned false fails",
                                      {"aligned": False})):
        verifier.records[record_id] = verifier_record(record_id, **fields)
        report.check(label, attestation(record_id) is False)
    report.check("every Router and Verifier read was at LATEST_FINAL",
                 set(router.states) == set(verifier.states) == {stub.StorageType.LATEST_FINAL})

    router.broken = True
    report.check("an unreadable Router fails, and does not raise", attestation() is False)
    router.broken = False
    verifier.broken = True
    report.check("an unreadable Verifier fails, and does not raise", attestation() is False)
    verifier.broken = False
    router.names["verifier"] = ""
    report.check("a Router that resolves no verifier fails", attestation() is False)
    router.names["verifier"] = VERIFIER_B
    report.check("the Router is resolved on every call: a new Verifier is used at once",
                 attestation() is False and verifier_b.states)
    router.names["verifier"] = VERIFIER

    # require_shipped
    report.check("patterns lane: matched and shipped passes",
                 contract.require_shipped("0", "patterns") is True)
    report.check("llm lane: matched and shipped passes",
                 contract.require_shipped("0", " LLM ") is True)
    report.check("an unknown lane fails", contract.require_shipped("0", "regex") is False)
    for record_id, label, fields in (
            ("3", "an extraction with match false fails", {"match": False}),
            ("4", "an extraction with shipped false fails", {"shipped": False}),
            ("5", "a matched extraction whose reason is not extracted fails",
             {"reason": "no text part", "shipped": True}),
            ("6", "an extraction of the same id on another Verifier fails",
             {"verifier": VERIFIER_B})):
        verifier.records[record_id] = verifier_record(record_id)
        patterns.add(record_id, **fields)
        report.check(label, contract.require_shipped(record_id, "patterns") is False)
    verifier.records["7"] = verifier_record("7")
    patterns.add("7", requester=AGENT)
    report.check("an extraction by someone other than the attester is not found",
                 contract.require_shipped("7", "patterns") is False)
    report.check("a lane with no extraction of the record fails",
                 contract.require_shipped("3", "llm") is False)
    report.check("a record the Verifier does not hold fails",
                 contract.require_shipped("99", "patterns") is False)
    report.check("every Extractor read was at LATEST_FINAL",
                 set(patterns.states) == set(llm.states) == {stub.StorageType.LATEST_FINAL})

    patterns.broken = True
    report.check("an unreadable Extractor fails, and does not raise",
                 contract.require_shipped("0", "patterns") is False)
    patterns.broken = False
    del router.names["extractor_llm"]
    report.check("a Router that resolves no lane fails",
                 contract.require_shipped("0", "llm") is False)
    router.names["extractor_llm"] = EXTRACTOR_LLM

    verifier.records["8"] = verifier_record("8")
    patterns.add("8")
    for _ in range(module.MAX_SCAN):
        patterns.add("0")
    reads = patterns.reads
    report.check("an extraction older than the newest MAX_SCAN is not read",
                 contract.require_shipped("8", "patterns") is False
                 and patterns.reads - reads == module.MAX_SCAN,
                 "%d reads" % (patterns.reads - reads,))
    patterns.add("8")
    report.check("and a newer one of the same record is",
                 contract.require_shipped("8", "patterns") is True)

    # mark_delivered
    node.sender = stub.Address(OWNER)
    report.raises("mark_delivered refuses a record that fails the attestation check",
                  lambda: contract.mark_delivered("1", "patterns"), "no accepted attestation")
    report.raises("mark_delivered refuses a record with no shipped extraction",
                  lambda: contract.mark_delivered("4", "patterns"), "no shipped extraction")
    report.check("nothing was stored by the refusals",
                 len(contract.delivered) == 0 and len(contract.messages) == 0)
    key = contract.mark_delivered(" 0 ", "patterns")
    report.check("mark_delivered stores the Verifier and the record id",
                 key == VERIFIER.lower() + "/0" and contract.delivered_at(VERIFIER, "0") == DATETIME,
                 key)
    report.raises("the same record cannot be marked twice",
                  lambda: contract.mark_delivered("0", "llm"), "already delivered")
    verifier.records["9"] = verifier_record("9", requester=AGENT)
    llm.add("9", requester=AGENT)
    report.raises("nor a second record of the same signed message",
                  lambda: contract.mark_delivered("9", "llm"), "already delivered")
    verifier.records["9"] = verifier_record("9", requester=AGENT, signed_at="1790011068")
    report.check("a different signed message is marked",
                 contract.mark_delivered("9", "llm") == VERIFIER.lower() + "/9")
    report.check("delivered_at is empty for a record never marked",
                 contract.delivered_at(VERIFIER, "3") == ""
                 and contract.delivered_at(VERIFIER_B, "0") == "")

    print("\n%d checks, %d failed" % (report.total, report.failed))
    sys.exit(1 if report.failed else 0)


if __name__ == "__main__":
    main()
