#!/usr/bin/env python3
"""Drive contracts/llmextractor/llmextractor.py against a stubbed SDK.

The built contract is executed as written, with a stand-in for the parts of
the runner it touches: storage, gl.message and its value, the balance, the
equivalence principle, the web fetch, the model call, the Router and
Verifier views, and the external message path. Nothing is deployed, no
model is called and no value moves. The model is a script: it answers what
each check tells it to, and records every prompt it was handed.

The body is the real one: the harness cuts it out of the sample message in
memory and serves it through the stubbed fetch. It is never written to a
file and never printed; the order number in it is used only to assert that
it appears nowhere in the contract's state, in what the validators agree on
or in anything the model was asked. Synthetic bodies and probe D2's bodies
drive the prefilter, relaxed canonicalization and the failure paths. Run it
before a deploy, not in CI.

Usage:
    python3 tests/llmextractor_stub_run.py
"""

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import extractor_stub_run as base
import verifier_stub_run as stub
from lacre import dkimbody, llmfields

CONTRACT = ROOT / "contracts" / "llmextractor" / "llmextractor.py"
BODIES = ROOT / "experiments" / "llm-probe-2" / "bodies"

VERIFIER, VERIFIER_B, ROUTER = base.VERIFIER, base.VERIFIER_B, base.ROUTER
OWNER, STRANGER, TREASURY, NEW_OWNER, ZERO = (
    stub.OWNER, stub.STRANGER, stub.TREASURY, stub.NEW_OWNER, stub.ZERO)
FEE = stub.FEE
BODY_URL = base.BODY_URL
DATETIME = stub.DATETIME

# The order number's shape, used here only to find the one in the sample so
# the run can prove it never leaves the body.
ORDER_SHAPE = r"\b\d{3}-\d{7}-\d{7}\b"

RECORD_FIELDS = ["id", "schema_version", "verifier", "record_id", "domain", "bh", "match",
                 "reason", "method", "prompt_sha256", "shipped", "eta_day", "eta_date",
                 "order_id_found", "flagged", "signed_at", "requester", "extracted_at",
                 "fee_paid"]


class Model:
    """gl.nondet.exec_prompt, scripted: returns answer, or raises it."""

    def __init__(self):
        self.answer = {"shipped": False, "eta_day": ""}
        self.prompts = []
        self.formats = []

    def __call__(self, prompt, response_format=None):
        self.prompts.append(prompt)
        self.formats.append(response_format)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def load_contract(node, model):
    """base.load_contract with the model call added to gl.nondet."""
    real = base.CONTRACT
    base.CONTRACT = CONTRACT
    try:
        sdk_before = stub.build_sdk

        def build_sdk(n):
            sdk = sdk_before(n)
            sdk.gl.nondet.exec_prompt = model
            return sdk

        stub.build_sdk = build_sdk
        try:
            return base.load_contract(node)
        finally:
            stub.build_sdk = sdk_before
    finally:
        base.CONTRACT = real


def probe_body(name):
    return (BODIES / name).read_text(encoding="ascii")


def main():
    if not CONTRACT.is_file():
        sys.exit("%s does not exist; run contracts/llmextractor/build.py first" % (CONTRACT,))

    body = base.sample_body()
    bh = dkimbody.body_hash_b64(body, "simple")
    text = dkimbody.first_text_part(body).decode("utf-8", "replace")
    order_ids = set(re.findall(ORDER_SHAPE, text))

    verifier = base.Verifier()
    verifier_b = base.Verifier()
    verifier.records["0"] = base.verifier_record(bh)
    verifier.records["1"] = base.verifier_record(bh, valid=False)
    verifier.records["2"] = base.verifier_record(bh, aligned=False)
    verifier.records["3"] = base.verifier_record(bh, canon="nowsp")
    router = stub.Router({"verifier": VERIFIER})
    node = base.Node(router, {VERIFIER: verifier, VERIFIER_B: verifier_b})
    node.blob = body
    model = Model()
    contract, module = load_contract(node, model)

    source = CONTRACT.read_text(encoding="ascii")
    print("contract     : %s (%d bytes)" % (CONTRACT.relative_to(ROOT), len(source)))
    print("body         : %d bytes, cut in memory from the sample" % (len(body),))
    print("prompt       : sha256 %s" % (llmfields.PROMPT_SHA256,))
    print("fee          : %d wei\n" % (FEE,))

    report = stub.Report()

    def refused(label, reason, send):
        """A refusal, with value and without: refunded whole, nothing stored,
        nothing fetched and no model call."""
        for wei in (FEE, 0):
            stored, queued = contract.count(), len(node.external)
            fetched, asked = len(node.urls), len(model.prompts)
            answer = send(wei)
            report.check("%s%s" % (label, "" if wei else ", carrying nothing"),
                         answer == reason and contract.last_refusal(STRANGER) == reason,
                         answer)
            report.check("  refunds %s, stores, fetches and asks nothing"
                         % ("the %d wei whole" % (wei,) if wei else "nothing",),
                         node.external[queued:] == ([(STRANGER, {"value": wei})]
                                                    if wei else [])
                         and contract.count() == stored and len(node.urls) == fetched
                         and len(model.prompts) == asked,
                         str(node.external[queued:]))

    def extract(wei, record_id="0", url=BODY_URL, sender=STRANGER):
        return base.call(node, sender, wei, contract.extract, record_id, url)

    def owner(method, *args):
        node.sender = stub.Address(OWNER)
        return method(*args)

    def serve(raw, record_id, canon="simple", domain="example.org"):
        node.blob = raw
        verifier.records[record_id] = base.verifier_record(
            dkimbody.body_hash_b64(raw, canon), canon=canon, domain=domain)

    # The built file.
    report.check("the built contract is under 14000 bytes", len(source) < 14000,
                 "%d bytes" % (len(source),))
    report.check("only the runner line survives as a comment",
                 [line for line in source.split("\n") if line.lstrip().startswith("#")]
                 == [source.split("\n", 1)[0]])
    report.check("the contract's prompt is lacre/llmfields.py's",
                 module.PROMPT == llmfields.PROMPT
                 and module.PROMPT_SHA256 == llmfields.PROMPT_SHA256)
    report.check("no order number expression and no patterns code is in the contract",
                 ORDER_SHAPE[2:-2] not in source and "_ORDER_ID" not in source
                 and "load_patterns" not in source and "set_patterns" not in source)
    report.check("the model is asked in JSON mode under strict equality only",
                 'exec_prompt(prompt, response_format="json")' in source
                 and "strict_eq" in source and "prompt_comparative" not in source
                 and "prompt_non_comparative" not in source)

    report.check("owner() is the deployer", contract.owner() == OWNER)
    report.check("router() is the constructor argument", contract.router() == ROUTER.lower())
    report.check("treasury() starts as the owner", contract.treasury() == OWNER)
    report.check("pending_owner and pending_treasury start empty",
                 contract.pending_owner() == "" and contract.pending_treasury() == "")
    report.check("fee() starts at zero and nothing is stored",
                 contract.fee() == 0 and contract.count() == 0)
    report.check("prompt_sha256() is the sha256 of the prompt template",
                 contract.prompt_sha256()
                 == hashlib.sha256(llmfields.PROMPT.encode()).hexdigest())
    report.check("records_of and last_refusal start empty",
                 contract.records_of(STRANGER) == [] and contract.last_refusal(STRANGER) == "")
    report.check("a malformed requester reads as empty, not as an error",
                 contract.records_of("nope") == [] and contract.last_refusal("nope") == "")
    report.check("the Verifier is not stored anywhere",
                 not any(value == stub.Address(VERIFIER) for value in vars(contract).values()))

    # Every refusal, in the contract's order.
    owner(contract.set_fee, 2 * FEE)
    refused("under the fee refuses", "fee not paid", lambda wei: extract(wei))
    owner(contract.set_fee, 0)
    router.broken = True
    refused("an unreadable Router refuses", "router unreadable", lambda wei: extract(wei))
    router.broken = False
    router.names = {}
    refused("a Router with no verifier refuses", "router resolves no verifier",
            lambda wei: extract(wei))
    router.names = {"verifier": "not an address"}
    refused("a Router naming something that is not an address refuses",
            "verifier unreadable", lambda wei: extract(wei))
    router.names = {"verifier": VERIFIER}
    verifier.broken = True
    refused("an unreadable Verifier refuses", "verifier unreadable", lambda wei: extract(wei))
    verifier.broken = False
    refused("an unknown Verifier record refuses", "record not found",
            lambda wei: extract(wei, "99"))
    refused("an invalid Verifier record refuses", "record not valid",
            lambda wei: extract(wei, "1"))
    refused("an unaligned Verifier record refuses", "record not aligned",
            lambda wei: extract(wei, "2"))
    refused("a record whose body_canon is neither simple nor relaxed refuses",
            "body canonicalization not supported", lambda wei: extract(wei, "3"))
    refused("a plain HTTP body URL refuses", "url not allowed",
            lambda wei: extract(wei, "0", "http://lacre.in-sidr.xyz/b.txt"))
    refused("a body URL over 512 characters refuses", "url not allowed",
            lambda wei: extract(wei, "0", "https://x.io/" + "a" * 500))
    report.check("  every Router and Verifier read was at LATEST_FINAL",
                 set(router.states) == {stub.StorageType.LATEST_FINAL}
                 and set(verifier.states) == {stub.StorageType.LATEST_FINAL})

    # The real body. Its sender has no patterns anywhere and is accepted. Its
    # text carries an image name with "shipped" in it, which the probe's
    # prefilter flagged; the narrowed key rule lets it through to the model.
    model.answer = {"shipped": True, "eta_day": "Mi\u00e9rcoles"}
    agreed_before, asked_before = len(node.agreed), len(model.prompts)
    first = extract(0, " 0 ")
    record = contract.get_record(first)
    outcome, sample_prompt = llmfields.prepare(body, bh, "simple")
    report.check("extract returns the first id", first == "0", first)
    report.check("the sample body matches bh and passes the prefilter",
                 llmfields.flags(text) == [] and outcome == "" and sample_prompt,
                 str(llmfields.flags(text)))
    report.check("every validator asks the model once, in JSON mode, with llm_check's prompt",
                 model.prompts[asked_before:] == [sample_prompt, sample_prompt]
                 and set(model.formats) == {"json"})
    report.check("the validators agree on match|shipped|eta_day|flagged|reason",
                 node.agreed[agreed_before:] == ["1|1|miercoles|0|extracted"],
                 str(node.agreed[agreed_before:]))
    report.check("the record reads what the model said, folded to ASCII",
                 record.get("match") is True and record.get("reason") == "extracted"
                 and record.get("shipped") is True and record.get("eta_day") == "miercoles"
                 and record.get("flagged") is False, record.get("reason"))
    report.check("eta_date is empty and order_id_found false: not produced in v1",
                 record.get("eta_date") == "" and record.get("order_id_found") is False)
    report.check("schema_version is 1, method llm, prompt_sha256 the template's",
                 record.get("schema_version") == "1" and record.get("method") == "llm"
                 and record.get("prompt_sha256") == llmfields.PROMPT_SHA256)
    report.check("the record names the Verifier, the record id, the domain and bh",
                 record.get("verifier") == VERIFIER and record.get("record_id") == "0"
                 and record.get("domain") == "amazon.com" and record.get("bh") == bh)
    report.check("signed_at, requester, extracted_at and fee_paid are as the Extractor's",
                 record.get("signed_at") == "1790011067" and record.get("requester") == STRANGER
                 and record.get("extracted_at") == DATETIME and record.get("fee_paid") == "0")
    report.check("get_record returns exactly the documented fields",
                 sorted(record) == sorted(RECORD_FIELDS), str(sorted(record)))
    report.check("records_of lists it", contract.records_of(STRANGER) == ["0"])
    report.check("an unknown id reads as empty", contract.get_record("70") == {})
    report.check("the body was fetched over the URL, every validator alike",
                 node.urls[-2:] == [BODY_URL, BODY_URL]
                 and node.headers[-1] == {"accept": "*/*"})

    # A body the prefilter passes, with an order number of the sample's shape
    # in it, so the model sees one and the record must not.
    planted = "Pedido 902-4417385-2210954"
    reading = base.mime(probe_body("01_shipped.txt") + "\n" + planted + "\n")
    serve(reading, "4")
    model.answer = {"shipped": True, "eta_day": "Mi\u00e9rcoles"}
    agreed_before, asked_before = len(node.agreed), len(model.prompts)
    record = contract.get_record(extract(0, "4"))
    outcome, prompt = llmfields.prepare(reading, verifier.records["4"]["bh"], "simple")
    report.check("a clean matching body is due a model call", outcome == "" and prompt)
    report.check("every validator asks the model once, in JSON mode, with llm_check's prompt",
                 model.prompts[asked_before:] == [prompt, prompt]
                 and set(model.formats) == {"json"})
    report.check("the validators agree on match|shipped|eta_day|flagged|reason",
                 node.agreed[agreed_before:] == ["1|1|miercoles|0|extracted"],
                 str(node.agreed[agreed_before:]))
    report.check("the record reads what the model said, folded to ASCII",
                 record.get("match") is True and record.get("reason") == "extracted"
                 and record.get("shipped") is True and record.get("eta_day") == "miercoles"
                 and record.get("flagged") is False and record.get("domain") == "example.org",
                 record.get("reason"))
    lines = prompt.split("\n")
    data = lines[lines.index("BEGIN-" + llmfields.body_tag(llmfields.sanitize(
        dkimbody.first_text_part(reading).decode()))) + 1]
    report.check("the planted number reached the model inside the escaped body only",
                 planted in data and prompt.count(planted) == 1)

    # A model that ignores the schema cannot put text in a record.
    model.answer = {"shipped": True, "eta_day": "jueves|1|x", "note": "anything"}
    record = contract.get_record(extract(0, "4"))
    report.check("a day outside the seven words is stored empty",
                 record.get("eta_day") == "" and record.get("reason") == "extracted"
                 and node.agreed[-1] == "1|1||0|extracted", node.agreed[-1])

    # Model failures are records with match true and nothing read.
    for label, answer, reason in (
            ("a model call that raises", TimeoutError("provider slow"),
             "model failed: TimeoutError"),
            ("a model call that raises on undecodable output", ValueError("bad json"),
             "model failed: ValueError"),
            ("a non-boolean shipped", {"shipped": "true", "eta_day": "jueves"},
             "model output unparseable"),
            ("an answer that is not an object", ["shipped", True],
             "model output unparseable"),
            ("a text mode string", '{"shipped": true, "eta_day": "jueves"}',
             "model output unparseable")):
        model.answer = answer
        node.blob = reading
        record = contract.get_record(extract(0, "4"))
        report.check("%s is a record, not a revert" % (label,),
                     record.get("match") is True and record.get("reason") == reason
                     and record.get("shipped") is False and record.get("eta_day") == ""
                     and record.get("flagged") is False, record.get("reason"))

    # The prefilter: a flagged body never reaches the model.
    model.answer = {"shipped": True, "eta_day": "miercoles"}
    for name in ("03_injection_direct.txt", "05_injection_marker.txt",
                 "07_fake_marker.txt"):
        serve(base.mime(probe_body(name)), "5")
        asked = len(model.prompts)
        record = contract.get_record(extract(0, "5"))
        report.check("probe body %s is flagged with no model call" % (name[:2],),
                     record.get("match") is True and record.get("flagged") is True
                     and record.get("reason") == "prefilter flagged"
                     and record.get("shipped") is False and record.get("eta_day") == ""
                     and len(model.prompts) == asked, record.get("reason"))
    report.check("  agreed as 1|0||1|prefilter flagged",
                 node.agreed[-1] == "1|0||1|prefilter flagged", node.agreed[-1])

    serve(base.mime(probe_body("08_injection_english.txt")), "5")
    model.answer = {"shipped": False, "eta_day": ""}
    asked = len(model.prompts)
    record = contract.get_record(extract(0, "5"))
    report.check("probe body 08, a key in prose only, now reaches the model",
                 record.get("flagged") is False and record.get("reason") == "extracted"
                 and len(model.prompts) == asked + 2, record.get("reason"))

    serve(base.mime(probe_body("09_gift_message.txt")), "5")
    model.answer = {"shipped": True, "eta_day": "jueves"}
    record = contract.get_record(extract(0, "5"))
    report.check("probe body 09 is not flagged and reaches the model",
                 record.get("flagged") is False and record.get("reason") == "extracted"
                 and record.get("eta_day") == "jueves")
    asked = model.prompts[-1]
    report.check("  as one JSON string between markers tagged by its hash",
                 "\nBEGIN-%s\n" % (llmfields.body_tag(llmfields.sanitize(
                     dkimbody.first_text_part(node.blob).decode())),) in asked
                 and asked.count(llmfields.RULES.split("\n", 1)[0]) == 2)

    # Relaxed canonicalization, base64, and the body outcomes before the model.
    serve(base.mime(probe_body("01_shipped.txt"), "base64"), "6", canon="relaxed")
    record = contract.get_record(extract(0, "6"))
    report.check("a relaxed, base64 body is checked and read",
                 record.get("match") is True and record.get("reason") == "extracted",
                 record.get("reason"))

    for label, raw, reason, match in (
            ("a body with no text part", b"no multipart here\r\n", "no text part", True),
            ("a text part over 8192 bytes after sanitizing",
             base.mime("hola " * 1700), "text too large", True)):
        serve(raw, "7")
        asked = len(model.prompts)
        record = contract.get_record(extract(0, "7"))
        report.check("%s is a record with no model call" % (label,),
                     record.get("match") is match and record.get("reason") == reason
                     and len(model.prompts) == asked, record.get("reason"))

    node.blob = base.mime(probe_body("01_shipped.txt"))
    queued, asked = len(node.external), len(model.prompts)
    owner(contract.set_fee, FEE)
    record = contract.get_record(extract(FEE, "6"))
    report.check("a body that does not hash to bh is recorded, match false",
                 record.get("match") is False and record.get("reason") == "bh mismatch",
                 record.get("reason"))
    report.check("  with no model call, every field empty and the fee kept",
                 len(model.prompts) == asked and record.get("shipped") is False
                 and record.get("eta_day") == "" and record.get("flagged") is False
                 and record.get("fee_paid") == str(FEE) and len(node.external) == queued)
    owner(contract.set_fee, 0)

    node.blob = b"x" * (llmfields.MAX_BODY + 1)
    record = contract.get_record(extract(0))
    report.check("a body over 262144 bytes is recorded as body too large",
                 record.get("match") is False and record.get("reason") == "body too large",
                 record.get("reason"))
    node.blob = b"x" * llmfields.MAX_BODY
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

    # A Verifier replaced behind the Router is used at once.
    verifier_b.records["0"] = base.verifier_record(bh)
    router.names = {"verifier": VERIFIER_B}
    node.blob = body
    moved = extract(0)
    report.check("a Verifier replaced behind the Router is used by the next call",
                 contract.get_record(moved).get("verifier") == VERIFIER_B)
    router.names = {"verifier": VERIFIER}

    # The agreed string is the only thing the block hands over, and the
    # deterministic side holds each field to its shape whatever it says.
    real_eq = node.strict_eq
    for label, forged, want in (
            ("a mismatch cannot carry fields", "0|1|jueves|1|bh mismatch",
             (False, False, "", False)),
            ("a day outside the seven words is dropped", "1|1|thursday|0|extracted",
             (True, True, "", False)),
            ("a flag other than 1 is false", "1|0||yes|extracted", (True, False, "", False)),
            ("a short string stores empty fields", "1", (True, False, "", False))):
        node.strict_eq = lambda fn, forged=forged: forged
        sys.modules["genlayer"].gl.eq_principle.strict_eq = node.strict_eq
        record = contract.get_record(extract(0))
        got = (record.get("match"), record.get("shipped"), record.get("eta_day"),
               record.get("flagged"))
        report.check("the deterministic side: %s" % (label,), got == want, str(got))
    node.strict_eq = real_eq
    sys.modules["genlayer"].gl.eq_principle.strict_eq = real_eq

    # The order number of the sample reaches nothing.
    state = (repr(vars(contract)) + repr(node.agreed)
             + repr([contract.get_record(str(i)) for i in range(contract.count())]))
    report.check("the sample carries an order number to leak", len(order_ids) == 1)
    report.check("the order number is nowhere in state or in what was agreed",
                 not any(order in state for order in order_ids))
    lines = sample_prompt.split("\n")
    data = lines[lines.index("BEGIN-" + llmfields.body_tag(llmfields.sanitize(text))) + 1]
    report.check("it reached the model only inside the escaped body",
                 all(order in data and sample_prompt.count(order) == data.count(order)
                     for order in order_ids))
    report.check("the planted number is nowhere in state or in what was agreed",
                 planted not in state)

    # Money: fee, treasury and ownership move as on the Extractor.
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
                 and contract.pending_treasury() == TREASURY and contract.treasury() == OWNER)
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
    report.raises("the old owner can no longer set the fee",
                  lambda: contract.set_fee(1), "owner only")

    print("\n%d checks, %d failed" % (report.total, report.failed))
    sys.exit(1 if report.failed else 0)


if __name__ == "__main__":
    main()
