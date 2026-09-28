#!/usr/bin/env python3
"""Drive contracts/extractor/extractor.py against a stubbed SDK.

The built contract is executed as written, with a stand-in for the parts of
the runner it touches: storage, gl.message and its value, the balance, the
equivalence principle, the web fetch, the Router and Verifier views, and the
external message path. Nothing is deployed and no value moves.

The body is the real one: the harness cuts it out of the sample message in
memory and serves it through the stubbed fetch. It is never written to a file
and never printed; the order number in it is used only to assert that it
appears nowhere in the contract's state or in what the validators agree on.
Synthetic bodies drive the relaxed canonicalization, the date patterns and
the failure paths. Run it before a deploy, not in CI.

Usage:
    python3 tests/extractor_stub_run.py
"""

import base64
import hashlib
import json
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import verifier_stub_run as stub
from lacre import dkimbody, patterns

CONTRACT = ROOT / "contracts" / "extractor" / "extractor.py"
TEMPLATE = ROOT / "contracts" / "extractor" / "extractor_template.py"
VERIFIER_SOURCE = ROOT / "contracts" / "verifier" / "verifier.py"
DEPLOYMENTS = ROOT / "deployments.json"
AMAZON = ROOT / "lacre" / "extractors" / "amazon.json"
MESSAGE = ROOT / "experiments" / "dkim-probe" / "samples" / "amazon-shipped.eml"

VERIFIER = "0x5555555555555555555555555555555555555555"
VERIFIER_B = "0x6666666666666666666666666666666666666666"
ROUTER = stub.ROUTER
OWNER, STRANGER, TREASURY, NEW_OWNER, ZERO = (
    stub.OWNER, stub.STRANGER, stub.TREASURY, stub.NEW_OWNER, stub.ZERO)
FEE = stub.FEE
BODY_URL = "https://lacre.in-sidr.xyz/stub-body.txt"
DATETIME = stub.DATETIME

DATES = json.dumps({
    "eta_date": [r"llega\s+el\s+(?:[a-z]+\s+)?(?P<d>\d{1,2})/(?P<m>\d{1,2})/(?P<y>\d{4})",
                 r"entrega (?P<y>\d{4})-(?P<m>\d\d)-(?P<d>\d\d)"],
    "eta_day": [r"\bllega\s+el\s+([a-z]+)"],
    "order_id": [r"\b\d{3}-\d{7}-\d{7}\b"],
    "shipped": [r"\benviado\b"],
})


class Verifier:
    """The Verifier as the Extractor sees it: get(id) and nothing else."""

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


def verifier_record(bh, canon="simple", valid=True, aligned=True, domain="amazon.com"):
    return {"id": "0", "domain": domain, "selector": "sel", "bh": bh,
            "body_canon": canon, "message_id_sha256": "", "key_bits": "1024",
            "key_sha256": "", "valid": valid, "reason": "", "from_domain": domain,
            "aligned": aligned, "signed_at": "1790011067", "source": "url",
            "requester": STRANGER, "attested_at": DATETIME, "fee_paid": "0",
            "schema_version": "2"}


class Node(stub.Node):
    """stub.Node with the Verifiers behind the Router instead of KeyCaches."""

    def __init__(self, router, verifiers):
        super().__init__(router, {})
        self.verifiers = verifiers
        self.headers = []
        self.agreed = []

    def get(self, url, headers=None):
        self.headers.append(headers)
        return super().get(url, headers)

    def strict_eq(self, fn):
        agreed = super().strict_eq(fn)
        self.agreed.append(agreed)
        return agreed

    def contract_at(self, address):
        if not isinstance(address, stub.Address):
            raise TypeError("address expected")
        if address == stub.Address(ROUTER):
            return self.router
        for where, verifier in self.verifiers.items():
            if address == stub.Address(where):
                return verifier
        raise AssertionError("the contract reached an address it should not")


def load_contract(node):
    sys.modules["genlayer"] = stub.build_sdk(node)
    sys.modules["genlayer.py"] = types.ModuleType("genlayer.py")
    public_abi = types.ModuleType("genlayer.py.public_abi")
    public_abi.StorageType = stub.StorageType
    sys.modules["genlayer.py.public_abi"] = public_abi
    module = types.ModuleType("extractor")
    module.__file__ = str(CONTRACT)
    exec(compile(CONTRACT.read_text(encoding="ascii"), str(CONTRACT), "exec"),
         module.__dict__)

    contract = module.Contract.__new__(module.Contract)
    # Storage starts zeroed on chain: an unset Address is twenty zero bytes
    # and an unset u256 is 0. The constructor relies on that.
    for name, annotation in module.Contract.__annotations__.items():
        origin = getattr(annotation, "__origin__", annotation)
        if origin is stub.TreeMap:
            setattr(contract, name, stub.TreeMap())
        elif annotation is stub.Address:
            setattr(contract, name, stub.Address(ZERO))
        else:
            setattr(contract, name, 0)
    contract.__init__(ROUTER)
    return contract, module


def sample_body():
    if not MESSAGE.is_file():
        sys.exit("%s is not here; samples are not tracked" % (MESSAGE,))
    raw = MESSAGE.read_bytes()
    found = [(raw.find(sep), sep) for sep in (b"\r\n\r\n", b"\n\n")]
    index, sep = min((index, sep) for index, sep in found if index >= 0)
    return raw[index + len(sep):]


def mime(text, encoding="7bit"):
    """A one-part multipart body, the shape first_text_part walks."""
    payload = text.encode("utf-8")
    if encoding == "base64":
        payload = base64.b64encode(payload)
    return (b"--b1\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: " + encoding.encode() + b"\r\n\r\n"
            + payload + b"\r\n--b1--\r\n")


def call(node, sender, wei, method, *args):
    return stub.call(node, sender, wei, method, *args)


def main():
    if not CONTRACT.is_file():
        sys.exit("%s does not exist; run contracts/extractor/build.py first" % (CONTRACT,))

    body = sample_body()
    bh = dkimbody.body_hash_b64(body, "simple")
    order_ids = set(re.findall(r"\b\d{3}-\d{7}-\d{7}\b",
                               dkimbody.first_text_part(body).decode("utf-8", "replace")))
    amazon = AMAZON.read_text(encoding="ascii")

    verifier = Verifier()
    verifier_b = Verifier()
    verifier.records["0"] = verifier_record(bh)
    verifier.records["1"] = verifier_record(bh, valid=False)
    verifier.records["2"] = verifier_record(bh, aligned=False)
    verifier.records["3"] = verifier_record(bh, canon="nowsp")
    verifier.records["4"] = verifier_record(bh, domain="example.com")
    router = stub.Router({"verifier": VERIFIER})
    node = Node(router, {VERIFIER: verifier, VERIFIER_B: verifier_b})
    node.blob = body
    contract, module = load_contract(node)

    source = CONTRACT.read_text(encoding="ascii")
    print("contract     : %s (%d bytes)" % (CONTRACT.relative_to(ROOT), len(source)))
    print("body         : %d bytes, cut in memory from the sample" % (len(body),))
    print("owner        : %s" % (OWNER,))
    print("fee          : %d wei\n" % (FEE,))

    report = stub.Report()

    def refused(label, reason, send):
        """A refusal, with value and without: refunded whole, nothing stored."""
        for wei in (FEE, 0):
            stored, queued = contract.count(), len(node.external)
            answer = send(wei)
            report.check("%s%s" % (label, "" if wei else ", carrying nothing"),
                         answer == reason and contract.last_refusal(STRANGER) == reason,
                         answer)
            report.check("  refunds %s and stores nothing"
                         % ("the %d wei whole" % (wei,) if wei else "nothing",),
                         node.external[queued:] == ([(STRANGER, {"value": wei})]
                                                    if wei else [])
                         and contract.count() == stored,
                         str(node.external[queued:]))

    def extract(wei, record_id="0", url=BODY_URL, sender=STRANGER):
        return call(node, sender, wei, contract.extract, record_id, url)

    def owner(method, *args):
        node.sender = stub.Address(OWNER)
        return method(*args)

    # The runner's modules. re and json are imported by the contract; re is
    # the module Verifier v1.2 already runs on Bradbury.
    deployed = json.loads(DEPLOYMENTS.read_text())["bradbury"]["verifier"]
    verifier_bytes = VERIFIER_SOURCE.read_bytes()
    report.check("the Extractor imports re at the top level",
                 "\nimport re\n" in source)
    report.check("so does the deployed Verifier v1.2 source",
                 "\nimport re\n" in verifier_bytes.decode("ascii")
                 and hashlib.sha256(verifier_bytes).hexdigest() == deployed["source_sha256"],
                 deployed["source_sha256"][:16] + "...")
    report.check("the Extractor imports json, used only by load_patterns",
                 "\nimport json\n" in source and source.count("json.") == 1)
    report.check("the built contract is under 13000 bytes", len(source) < 13000,
                 "%d bytes" % (len(source),))
    report.check("only the runner line survives as a comment",
                 [line for line in source.split("\n") if line.lstrip().startswith("#")]
                 == [source.split("\n", 1)[0]])
    report.check("the fixed Amazon patterns of dkimbody.py are not in the contract",
                 "_ORDER_ID" not in source and "extract_fields" not in source)

    report.check("owner() is the deployer", contract.owner() == OWNER)
    report.check("router() is the constructor argument", contract.router() == ROUTER.lower())
    report.check("treasury() starts as the owner", contract.treasury() == OWNER)
    report.check("pending_owner and pending_treasury start empty",
                 contract.pending_owner() == "" and contract.pending_treasury() == "")
    report.check("fee() starts at zero and nothing is stored",
                 contract.fee() == 0 and contract.count() == 0)
    report.check("records_of and last_refusal start empty",
                 contract.records_of(STRANGER) == [] and contract.last_refusal(STRANGER) == "")
    report.check("a malformed requester reads as empty, not as an error",
                 contract.records_of("nope") == [] and contract.last_refusal("nope") == "")
    report.check("the Verifier is not stored anywhere",
                 not any(value == stub.Address(VERIFIER) for value in vars(contract).values()))

    # Patterns are owner data, checked when they are set.
    node.sender = stub.Address(STRANGER)
    report.raises("set_patterns by a stranger raises",
                  lambda: contract.set_patterns("amazon.com", amazon), "owner only")
    node.sender = stub.Address(OWNER)
    too_big = json.dumps({"eta_date": [], "eta_day": [], "order_id": [],
                          "shipped": ["x" * 4100]})
    for label, document, message in (
            ("a document that is not JSON", "{shipped: []}", "patterns not JSON"),
            ("a document missing a key", json.dumps({"shipped": [], "eta_day": [],
                                                     "order_id": []}), None),
            ("a document with an extra key",
             json.dumps({"shipped": [], "eta_day": [], "eta_date": [], "order_id": [],
                         "order_number": []}), None),
            ("a key that is not a list", json.dumps({"shipped": "x", "eta_day": [],
                                                     "eta_date": [], "order_id": []}), None),
            ("an expression that is not a string",
             json.dumps({"shipped": [1], "eta_day": [], "eta_date": [], "order_id": []}),
             "patterns key does not compile: shipped"),
            ("an expression that does not compile",
             json.dumps({"shipped": ["("], "eta_day": [], "eta_date": [], "order_id": []}),
             "patterns key does not compile: shipped"),
            ("an eta_date expression without y, m and d",
             json.dumps({"shipped": [], "eta_day": [], "eta_date": [r"(\d+)"],
                         "order_id": []}), "eta_date needs groups y m d"),
            ("a document over 4096 bytes", too_big, "patterns too large"),
            ("a JSON array", "[]", None)):
        report.raises("set_patterns rejects %s" % (label,),
                      lambda document=document: contract.set_patterns("amazon.com", document),
                      message)
    report.raises("set_patterns rejects an empty domain",
                  lambda: contract.set_patterns(" . ", amazon), "bad domain")
    report.check("nothing was stored by the rejections",
                 contract.patterns("amazon.com") == "" and contract.patterns_sha256("amazon.com") == "")

    # Refusals before any patterns exist, in the contract's order.
    refused("no patterns for the record's domain refuses", "no patterns for domain",
            lambda wei: extract(wei))
    digest = owner(contract.set_patterns, "Amazon.COM.", amazon + "\n\n")
    report.check("set_patterns stores the trimmed document under the normalized domain",
                 contract.patterns("amazon.com") == amazon.strip())
    report.check("and returns its sha256, which patterns_sha256 reports",
                 digest == contract.patterns_sha256("AMAZON.com")
                 == hashlib.sha256(amazon.strip().encode()).hexdigest(), digest[:16] + "...")
    report.check("patterns of an unknown domain is empty",
                 contract.patterns("example.org") == "" and contract.patterns_sha256("x") == "")

    reads, fetched = len(verifier.states), len(node.urls)
    owner(contract.set_fee, 2 * FEE)
    refused("under the fee refuses", "fee not paid", lambda wei: extract(wei))
    report.check("  and neither the Verifier nor the body was read",
                 len(verifier.states) == reads and len(node.urls) == fetched)
    owner(contract.set_fee, 0)
    refused("an unknown Verifier record refuses", "record not found",
            lambda wei: extract(wei, "99"))
    refused("a record id that is not digits refuses the same way", "record not found",
            lambda wei: extract(wei, "0; drop"))
    refused("an invalid Verifier record refuses", "record not valid",
            lambda wei: extract(wei, "1"))
    refused("an unaligned Verifier record refuses", "record not aligned",
            lambda wei: extract(wei, "2"))
    refused("a record whose body_canon is neither simple nor relaxed refuses",
            "body canonicalization not supported", lambda wei: extract(wei, "3"))
    refused("a record from a domain without patterns refuses", "no patterns for domain",
            lambda wei: extract(wei, "4"))
    refused("a plain HTTP body URL refuses", "url not allowed",
            lambda wei: extract(wei, "0", "http://lacre.in-sidr.xyz/b.txt"))
    refused("a body URL over 512 characters refuses", "url not allowed",
            lambda wei: extract(wei, "0", "https://x.io/" + "a" * 500))
    report.check("  no refusal fetched the body", len(node.urls) == fetched)
    report.check("  every Verifier read was at LATEST_FINAL",
                 set(verifier.states) == {stub.StorageType.LATEST_FINAL})

    router.broken = True
    refused("an unreadable Router refuses", "router unreadable", lambda wei: extract(wei))
    router.broken = False
    router.names = {}
    refused("a Router with no verifier refuses", "router resolves no verifier",
            lambda wei: extract(wei))
    router.names = {"verifier": VERIFIER}
    verifier.broken = True
    refused("an unreadable Verifier refuses", "verifier unreadable", lambda wei: extract(wei))
    verifier.broken = False
    report.check("  every Router read was at LATEST_FINAL",
                 set(router.states) == {stub.StorageType.LATEST_FINAL})

    # The real body, the way it was measured on Bradbury.
    agreed_before = len(node.agreed)
    first = extract(0, " 0 ")
    record = contract.get_record(first)
    expected = patterns.extract_body(body, bh, "simple", amazon)
    report.check("extract returns the first id", first == "0", first)
    report.check("the validators agree on what extract_check.py computes",
                 node.agreed[agreed_before:] == [expected], expected)
    report.check("the body matches the record's bh", record.get("match") is True,
                 record.get("reason"))
    report.check("shipped, eta_day and order_id_found are the probe's",
                 record.get("shipped") is True and record.get("eta_day") == "miercoles"
                 and record.get("order_id_found") is True)
    report.check("eta_date is empty: amazon.json has no date expression",
                 record.get("eta_date") == "")
    report.check("schema_version is 1 and method is patterns",
                 record.get("schema_version") == "1" and record.get("method") == "patterns")
    report.check("the record names the Verifier, the record id, the domain and bh",
                 record.get("verifier") == VERIFIER and record.get("record_id") == "0"
                 and record.get("domain") == "amazon.com" and record.get("bh") == bh)
    report.check("patterns_sha256 names the document that read it",
                 record.get("patterns_sha256") == digest)
    report.check("signed_at is copied from the Verifier record",
                 record.get("signed_at") == "1790011067")
    report.check("requester, extracted_at and fee_paid are the call's",
                 record.get("requester") == STRANGER and record.get("extracted_at") == DATETIME
                 and record.get("fee_paid") == "0")
    report.check("get_record returns exactly the documented fields",
                 sorted(record) == sorted(
                     ["id", "schema_version", "verifier", "record_id", "domain", "bh",
                      "match", "reason", "method", "patterns_sha256", "shipped", "eta_day",
                      "eta_date", "order_id_found", "signed_at", "requester",
                      "extracted_at", "fee_paid"]), str(sorted(record)))
    report.check("records_of lists it", contract.records_of(STRANGER) == ["0"])
    report.check("an unknown id reads as empty", contract.get_record("7") == {})
    report.check("the body was fetched over the URL, every validator alike",
                 node.urls[-2:] == [BODY_URL, BODY_URL]
                 and node.headers[-1] == {"accept": "*/*"})

    state = repr(vars(contract)) + repr(node.agreed) + repr(record)
    report.check("the sample carries an order number to leak", len(order_ids) == 1)
    report.check("the order number is nowhere in state or in what was agreed",
                 not any(order in state for order in order_ids))

    # The Verifier is resolved on every call: a new one behind the Router is
    # used at once, with no change to the Extractor.
    verifier_b.records["0"] = verifier_record(bh)
    router.names = {"verifier": VERIFIER_B}
    moved = extract(0)
    report.check("a Verifier replaced behind the Router is used by the next call",
                 contract.get_record(moved).get("verifier") == VERIFIER_B
                 and verifier_b.states[-1] == stub.StorageType.LATEST_FINAL)
    router.names = {"verifier": VERIFIER}

    # A body that is not the signed one is a paid record, not a refusal.
    queued = len(node.external)
    node.blob = body.replace(b"\r\n", b"\r\n ", 1)
    owner(contract.set_fee, FEE)
    tampered = extract(FEE)
    record = contract.get_record(tampered)
    report.check("a body that does not hash to bh is recorded, match false",
                 record.get("match") is False and record.get("reason") == "bh mismatch",
                 record.get("reason"))
    report.check("  with every field empty",
                 record.get("shipped") is False and record.get("eta_day") == ""
                 and record.get("eta_date") == "" and record.get("order_id_found") is False)
    report.check("  and the fee kept, as the Verifier keeps it on a false record",
                 record.get("fee_paid") == str(FEE) and len(node.external) == queued)
    owner(contract.set_fee, 0)

    node.blob = b"x" * (patterns.MAX_BODY + 1)
    record = contract.get_record(extract(0))
    report.check("a body over 262144 bytes is recorded as body too large",
                 record.get("match") is False and record.get("reason") == "body too large",
                 record.get("reason"))
    node.blob = b"x" * patterns.MAX_BODY
    record = contract.get_record(extract(0))
    report.check("a body of exactly 262144 bytes is hashed",
                 record.get("reason") == "bh mismatch", record.get("reason"))

    node.blob, node.status = body, 404
    record = contract.get_record(extract(0))
    report.check("an HTTP error is recorded with its status",
                 record.get("match") is False and record.get("reason") == "body HTTP 404",
                 record.get("reason"))
    node.status = 200

    def failing(url, headers=None):
        raise ConnectionError("https://secret.example/path")

    real_get = node.get
    sys.modules["genlayer"].gl.nondet.web.get = failing
    record = contract.get_record(extract(0))
    sys.modules["genlayer"].gl.nondet.web.get = real_get
    report.check("a fetch that raises is recorded by class name, not by its text",
                 record.get("reason") == "body fetch failed: ConnectionError",
                 record.get("reason"))

    # Relaxed canonicalization, dates and replacement of a document.
    relaxed = mime("Tu pedido ha sido enviado.  \r\nLlega el   Mi\u00e9rcoles 07/10/2026\t\r\n"
                   "Pedido 123-1234567-1234567\r\n", "base64")
    relaxed_bh = dkimbody.body_hash_b64(relaxed, "relaxed")
    verifier.records["5"] = verifier_record(relaxed_bh, canon="relaxed", domain="lacre.test")
    owner(contract.set_patterns, "lacre.test", DATES)
    node.blob = relaxed
    record = contract.get_record(extract(0, "5"))
    report.check("a relaxed signature is checked under relaxed canonicalization",
                 record.get("match") is True, record.get("reason"))
    report.check("a base64 text part is decoded and read",
                 record.get("shipped") is True and record.get("order_id_found") is True)
    report.check("an accent is folded before the weekday pattern runs",
                 record.get("eta_day") == "miercoles", record.get("eta_day"))
    report.check("a full date is captured as an ISO date",
                 record.get("eta_date") == "2026-10-07", record.get("eta_date"))

    for text, want, label in (
            ("llega el 30/02/2026", "", "February 30th is not a date"),
            ("llega el 29/02/2028", "2028-02-29", "a leap day is"),
            ("llega el 29/02/2100", "", "2100 is not a leap year"),
            ("llega el 31/04/2026 entrega 2026-05-01", "2026-05-01",
             "an invalid first expression falls through to the next"),
            ("llega el 13/13/2026", "", "month 13 is not a date")):
        node.blob = mime(text)
        verifier.records["6"] = verifier_record(dkimbody.body_hash_b64(node.blob, "simple"),
                                                domain="lacre.test")
        got = contract.get_record(extract(0, "6")).get("eta_date")
        report.check("eta_date: %s" % (label,), got == want, repr(got))

    node.blob = b"no multipart here\r\n"
    verifier.records["7"] = verifier_record(dkimbody.body_hash_b64(node.blob, "simple"),
                                            domain="lacre.test")
    record = contract.get_record(extract(0, "7"))
    report.check("a matching body with no text part is match true with empty fields",
                 record.get("match") is True and record.get("reason") == "no text part"
                 and record.get("shipped") is False, record.get("reason"))

    node.blob = relaxed
    old_digest = contract.get_record("0").get("patterns_sha256")
    newer = json.dumps({"eta_date": [], "eta_day": [], "order_id": [], "shipped": []})
    owner(contract.set_patterns, "lacre.test", newer)
    later = contract.get_record(extract(0, "5"))
    report.check("replaced patterns read later records",
                 later.get("patterns_sha256") == patterns.document_sha256(newer)
                 and later.get("shipped") is False)
    report.check("and earlier records keep the digest they were read with",
                 contract.get_record("0").get("patterns_sha256") == old_digest == digest)

    # The order number's group reaches nothing but a boolean.
    template = TEMPLATE.read_text(encoding="ascii")
    library = (ROOT / "lacre" / "patterns.py").read_text(encoding="ascii")
    uses = [line.strip() for line in library.split("\n") if 'doc["order_id"]' in line]
    report.check("order_id expressions are only ever reduced to any(...)",
                 uses == ['any(re.search(expr, folded) for expr in doc["order_id"]))'],
                 str(uses))
    report.check("the template stores order_id_found from the agreed flag only",
                 "order_id_found=match and parts[4] == \"1\"" in template)

    # Money: fee, treasury and ownership move as on the Verifier.
    refunds = list(node.external)
    node.sender = stub.Address(STRANGER)
    report.raises("set_fee by a stranger raises", lambda: contract.set_fee(FEE), "owner only")
    report.raises("propose_treasury by a stranger raises",
                  lambda: contract.propose_treasury(STRANGER), "owner only")
    report.raises("withdraw by a stranger raises", lambda: contract.withdraw(FEE),
                  "owner only")
    node.sender = stub.Address(OWNER)
    report.raises("a negative fee raises", lambda: contract.set_fee(-1), "negative fee")
    report.raises("the zero address cannot be proposed as treasury",
                  lambda: contract.propose_treasury(ZERO))
    report.check("propose_treasury stores the candidate",
                 contract.propose_treasury(TREASURY) == TREASURY
                 and contract.pending_treasury() == TREASURY
                 and contract.treasury() == OWNER)
    report.raises("accept_treasury by the owner raises", contract.accept_treasury,
                  "pending treasury only")
    node.sender = stub.Address(TREASURY)
    report.check("accept_treasury by the proposed address takes it",
                 contract.accept_treasury() == TREASURY and contract.treasury() == TREASURY
                 and contract.pending_treasury() == "")
    report.raises("the treasury cannot withdraw", lambda: contract.withdraw(FEE), "owner only")
    node.sender = stub.Address(OWNER)
    report.raises("withdraw of zero raises", lambda: contract.withdraw(0),
                  "amount out of range")
    report.raises("withdraw of more than the balance raises",
                  lambda: contract.withdraw(node.balance + 1), "amount out of range")
    held = node.balance
    report.check("withdraw by the owner returns the amount",
                 contract.withdraw(held) == str(held))
    report.check("one external transfer is queued to the treasury, nothing internal",
                 node.external == refunds + [(TREASURY, {"value": held})]
                 and node.internal == [])

    node.sender = stub.Address(STRANGER)
    report.raises("propose_owner by a stranger raises",
                  lambda: contract.propose_owner(STRANGER), "owner only")
    node.sender = stub.Address(OWNER)
    report.check("propose_owner stores the candidate",
                 contract.propose_owner(NEW_OWNER) == NEW_OWNER
                 and contract.pending_owner() == NEW_OWNER and contract.owner() == OWNER)
    node.sender = stub.Address(STRANGER)
    report.raises("accept_owner by a stranger raises", contract.accept_owner,
                  "pending owner only")
    node.sender = stub.Address(NEW_OWNER)
    report.check("accept_owner by the pending owner takes it",
                 contract.accept_owner() == NEW_OWNER and contract.owner() == NEW_OWNER
                 and contract.pending_owner() == "")
    node.sender = stub.Address(OWNER)
    report.raises("the old owner can no longer set patterns",
                  lambda: contract.set_patterns("amazon.com", amazon), "owner only")

    print("\n%d checks, %d failed" % (report.total, report.failed))
    sys.exit(1 if report.failed else 0)


if __name__ == "__main__":
    main()
