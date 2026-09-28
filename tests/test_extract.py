"""tools/extract.py: the pre-checks, matching a record and judging the outcome.

The protocol itself is tools/attest.py's and is tested in test_attest.py;
this covers what extract.py adds on top of it. The Router and Verifier
addresses are the Bradbury entries of deployments.json; the Extractor is not
deployed, so its address here is a placeholder, and the views are stubbed
from contracts/extractor/extractor.py and contracts/verifier/verifier.py.
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import attest
import chain
import extract

DEPLOYED = json.loads((ROOT / "deployments.json").read_text())["bradbury"]
ROUTER = DEPLOYED["router"]["address"]
VERIFIER = DEPLOYED["verifier"]["address"]
EXTRACTOR = "0x" + "e1" * 20
SENDER = "0xF27E3A6d7Bf4BfC0A837020FD74E73055aF17D53"
URL = "https://lacre.in-sidr.xyz/body.txt"
RECORD = {"domain": "amazon.com", "bh": "x", "body_canon": "simple", "valid": True,
          "aligned": True, "signed_at": "1790011067"}
STATE = {"status": "FINALIZED"}


def stubbed(answers):
    """view(address, method, args, variant) answering from a table."""
    seen = []

    def view(address, method, args, variant):
        seen.append((address, method, tuple(args), variant))
        answer = answers.get((address, method))
        return answer(*args) if callable(answer) else answer

    view.seen = seen
    return view


def views(record=RECORD, fee=0, patterns='{"shipped": []}', extractor_router=ROUTER):
    return stubbed({
        (ROUTER, "resolve"): lambda name: {"extractor": EXTRACTOR,
                                           "verifier": VERIFIER}.get(name, ""),
        (EXTRACTOR, "router"): extractor_router,
        (EXTRACTOR, "fee"): fee,
        (EXTRACTOR, "patterns"): lambda domain: patterns if domain == "amazon.com" else "",
        (VERIFIER, "get"): lambda record_id: dict(record) if record_id == "0" else {},
    })


@pytest.mark.parametrize("change, reason", [
    ({"value": 0, "fee": 1}, "fee not paid"),
    ({"record_id": "9"}, "record not found"),
    ({"record": dict(RECORD, valid=False)}, "record not valid"),
    ({"record": dict(RECORD, aligned=False)}, "record not aligned"),
    ({"record": dict(RECORD, body_canon="nowsp")}, "body canonicalization not supported"),
    ({"record": dict(RECORD, domain="example.com")}, "no patterns for domain"),
    ({"url": "http://lacre.in-sidr.xyz/b"}, "url not allowed"),
    ({"url": "https://x.io/" + "a" * 500}, "url not allowed"),
])
def test_refusals_are_predicted_in_the_extractors_order(change, reason):
    view = views(**{key: change[key] for key in ("record", "fee") if key in change})
    got = extract.refusal(view, EXTRACTOR, VERIFIER, change.get("record_id", "0"),
                          change.get("url", URL), change.get("value", 0))
    assert got == reason


def test_a_call_that_would_go_through_is_not_refused():
    view = views()
    assert extract.refusal(view, EXTRACTOR, VERIFIER, " 0 ", URL, 0) is None
    # The Verifier record is read final, as the Extractor reads it.
    assert (VERIFIER, "get", ("0",), attest.FINAL) in view.seen


def test_no_verifier_behind_the_router_is_a_refusal():
    assert extract.refusal(views(), EXTRACTOR, "", "0", URL, 0) == "router resolves no verifier"


def test_an_unreadable_view_stops_before_anything_is_sent():
    view = stubbed({(EXTRACTOR, "fee"): chain.UNKNOWN})
    with pytest.raises(attest.Stop):
        extract.refusal(view, EXTRACTOR, VERIFIER, "0", URL, 0)


def test_resolve_finds_both_contracts_through_the_router():
    assert extract.resolve(views(), ROUTER) == (EXTRACTOR, VERIFIER)


def test_resolve_stops_on_an_extractor_behind_another_router():
    with pytest.raises(attest.Stop):
        extract.resolve(views(extractor_router="0x" + "99" * 20), ROUTER)


def test_resolve_stops_when_the_router_has_no_extractor():
    view = stubbed({(ROUTER, "resolve"): lambda name: ""})
    with pytest.raises(attest.Stop):
        extract.resolve(view, ROUTER)


def extraction(**changes):
    base = {"id": "3", "record_id": "0", "requester": SENDER.lower(), "fee_paid": "0",
            "match": True, "verifier": VERIFIER}
    base.update(changes)
    return base


def test_a_record_is_ours_on_requester_record_id_and_fee():
    call = {"record_id": " 0 ", "sender": SENDER, "value": 0}
    assert extract.ours(extraction(), call)
    assert not extract.ours(extraction(record_id="1"), call)
    assert not extract.ours(extraction(fee_paid="5"), call)
    assert not extract.ours(extraction(requester="0x" + "11" * 20), call)
    assert not extract.ours({}, call)


def test_a_new_matching_record_is_recorded_even_with_match_false():
    call = {"verifier": EXTRACTOR, "record_id": "0", "sender": SENDER, "value": 0}
    view = stubbed({
        (EXTRACTOR, "records_of"): ["3"],
        (EXTRACTOR, "last_refusal"): "",
        (EXTRACTOR, "get_record"): lambda record_id: extraction(match=False),
    })
    found = attest.outcome(view, lambda: [], STATE, call, {"ids": [], "refusal": ""},
                           getter="get_record", matches=extract.ours, contract="Extractor")
    verdict, _ = attest.judge(dict(STATE, result="AGREE", execution="FINISHED_WITH_RETURN",
                                   previous="", rounds=1, value=0, eq_outputs=[]),
                              "finalized", found, SENDER)
    assert [record_id for record_id, _ in found["records"]] == ["3"]
    assert verdict == attest.RECORDED


def test_a_refusal_names_the_extractor():
    call = {"verifier": EXTRACTOR, "record_id": "0", "sender": SENDER, "value": 0}
    view = stubbed({
        (EXTRACTOR, "records_of"): [],
        (EXTRACTOR, "last_refusal"): "no patterns for domain",
    })
    found = attest.outcome(view, lambda: [], STATE, call, {"ids": [], "refusal": ""},
                           getter="get_record", matches=extract.ours, contract="Extractor")
    verdict, message = attest.judge(
        dict(STATE, result="AGREE", execution="FINISHED_WITH_RETURN", previous="",
             rounds=1, value=0, eq_outputs=[]), "finalized", found, SENDER)
    assert verdict == attest.REFUSED
    assert message == "the Extractor refused the call: no patterns for domain"


def test_the_session_reads_extractor_records_with_get_record():
    session = extract.Session(None, None, None, None,
                              {"verifier": EXTRACTOR, "record_id": "0", "sender": SENDER,
                               "value": 0})
    view = stubbed({
        (EXTRACTOR, "records_of"): ["3"],
        (EXTRACTOR, "last_refusal"): "",
        (EXTRACTOR, "get_record"): lambda record_id: extraction(),
    })
    session.view = view
    session.messages = lambda tx_id: (lambda: [])
    found = session.outcome(STATE, "0xabc", {"ids": [], "refusal": ""})
    assert found["records"][0][0] == "3"
    assert (EXTRACTOR, "get_record", ("3",), attest.FINAL) in view.seen
