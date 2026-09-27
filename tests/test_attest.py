"""tools/attest.py: judging an attempt and deciding whether to send again.

The consensus fixtures are real Bradbury answers of
ConsensusData.getTransactionAllData, with the messages of
getTransactionData, recorded read-only on 24 September 2026:

  consensus_call36_timeout.json      probe D2 call 36: FINALIZED, result
                                     TIMEOUT, execution FINISHED_WITH_RETURN,
                                     and no record written
  consensus_call37_agree.json        probe D2 call 37: FINALIZED, AGREE,
                                     FINISHED_WITH_RETURN, record 35 written
  consensus_verifier_underpaid.json  Verifier v1.1 attest with 5e15 wei
                                     against a fee of 1e16: FINALIZED,
                                     AGREE, refused with "fee not paid" and
                                     one refund message to the sender

verifier_record.json is built to the shape Verifier.get() returns; no
Verifier after v1 has written a record on chain to record one from, and the
tests add the v1.2 schema_version to it. The Router, KeyCache and Verifier
addresses are the Bradbury entries of deployments.json; the views they answer
are stubbed from contracts/router/router.py, contracts/keycache/keycache.py
and contracts/verifier/verifier.py. Stored states for CANCELED and an appeal
are the recorded ones with the status changed.
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import attest
import chain
import txstate
from genlayer_py.chains import testnet_bradbury

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ABI = testnet_bradbury.consensus_data_contract["abi"]
SENDER = "0xF27E3A6d7Bf4BfC0A837020FD74E73055aF17D53"
DEPLOYED = json.loads((ROOT / "deployments.json").read_text())["bradbury"]
ROUTER = DEPLOYED["router"]["address"]
KEYCACHE = DEPLOYED["keycache"]["address"]
VERIFIER = DEPLOYED["verifier"]["address"]
EXPLORER = "https://explorer-bradbury.genlayer.com"
NO_L = "body length limit not supported"


def recorded(name):
    """(stored state, messages) of a recorded consensus fixture."""
    raw = json.loads((FIXTURES / name).read_text(encoding="ascii"))
    transaction, rounds = raw["getTransactionAllData"]
    transaction = list(transaction)
    index = txstate.fields(ABI, "getTransactionAllData").index("eqBlocksOutputs")
    transaction[index] = bytes.fromhex(transaction[index][2:])
    state = txstate.decode_stored(ABI, [transaction, rounds])
    return state, txstate.decode_messages(ABI, raw["getTransactionData_messages"])


TIMEOUT, _ = recorded("consensus_call36_timeout.json")
AGREE, _ = recorded("consensus_call37_agree.json")
UNDERPAID, REFUND = recorded("consensus_verifier_underpaid.json")
CANCELED = dict(AGREE, status="CANCELED")
APPEALED = dict(TIMEOUT, status="APPEAL_COMMITTING")
UNDETERMINED = dict(TIMEOUT, status="UNDETERMINED", result="NO_MAJORITY")
RECORD = dict(json.loads((FIXTURES / "verifier_record.json").read_text(encoding="ascii")),
              schema_version="2")
KEY = {"domain": "amazon.com", "selector": "sel1", "state": "active", "n_hex": "c3" * 128,
       "e": "65537", "key_bits": "1024", "key_sha256": "ab" * 32,
       "first_seen": "2026-09-26T21:34:15Z", "activated_at": "2026-09-27T21:40:00Z",
       "refreshed_at": "2026-09-27T21:40:00Z"}
NOTHING = {"ids": [], "refusal": ""}


def call(**changes):
    base = {"verifier": VERIFIER, "method": "attest_inline", "payload": "From: x\r\n",
            "domain": "amazon.com", "selector": "sel1", "sender": SENDER, "value": 0}
    base.update(changes)
    return base


def verifier(records=(), fee=0, key=KEY, ids=None, refusal="", router=ROUTER,
             resolves=None):
    """A view function over the Router, the KeyCache and a Verifier holding
    records from id 0. ids is what records_of answers for the sender, every
    record by default; refusal is what last_refusal answers."""
    records = list(records)
    ids = [str(index) for index in range(len(records))] if ids is None else ids
    resolves = {"verifier": VERIFIER, "keycache": KEYCACHE} if resolves is None else resolves

    def view(address, method, args, variant):
        if address == ROUTER and method == "resolve":
            return resolves.get(args[0], "")
        if address == KEYCACHE and method == "key_status":
            return key
        if address == VERIFIER:
            if method == "records_of":
                assert args == [SENDER]
                return ids
            if method == "last_refusal":
                assert args == [SENDER]
                return refusal
            if method == "get":
                index = int(args[0])
                return records[index] if index < len(records) else {}
            if method == "fee":
                return fee
            if method == "router":
                return router
        raise AssertionError((address, method, args))
    return view


class Session:
    """attest.Session without the chain: one stored state and one Verifier
    snapshot per attempt, in order. The Verifier is read only for an
    attempt that executed."""

    def __init__(self, states, snapshots=(), messages=(), the_call=None, before=None):
        self.call = the_call or call()
        self.states = list(states)
        self.snapshots = list(snapshots)
        self.message_list = list(messages)
        self.before = NOTHING if before is None else before
        self.sent = []

    def start(self):
        return self.before

    def send(self):
        tx_id = "0x%064x" % (len(self.sent) + 1,)
        self.sent.append(tx_id)
        return tx_id

    def wait(self, tx_id, until):
        return self.states.pop(0)

    def outcome(self, state, tx_id, before):
        view = self.snapshots.pop(0)
        return attest.outcome(view, lambda: self.message_list, state, self.call, before)


def run(session, attempts=3, until="finalized"):
    return attest.protocol(session, attempts, until, EXPLORER)


# ---- the recorded states -------------------------------------------------

def test_call_36_finalized_without_executing_though_its_execution_says_return():
    assert (TIMEOUT["status"], TIMEOUT["result"], TIMEOUT["execution"]) \
        == ("FINALIZED", "TIMEOUT", "FINISHED_WITH_RETURN")
    assert TIMEOUT["previous"] == "LEADER_TIMEOUT"
    assert not txstate.executed(TIMEOUT)


def test_call_37_executed():
    assert txstate.executed(AGREE)


def test_the_underpaid_call_executed_and_refunded_the_sender():
    assert txstate.executed(UNDERPAID)
    assert UNDERPAID["value"] == 5 * 10 ** 15
    assert REFUND == [{"type": 0, "recipient": SENDER, "value": 5 * 10 ** 15,
                       "on_acceptance": False}]
    assert txstate.eq_block_values(UNDERPAID["eq_outputs"]) == []


# ---- the protocol --------------------------------------------------------

def test_a_record_read_back_with_our_requester_exits_0(capsys):
    session = Session([AGREE], [verifier([RECORD])])
    assert run(session) == attest.EXIT_RECORDED
    out = capsys.readouterr().out
    assert len(session.sent) == 1
    assert "verdict      : recorded: record 0, requester %s" % (SENDER,) in out
    assert "RECORD       : 0" in out
    assert "attempt 1    : %s  %s/tx/%s" % (session.sent[0], EXPLORER, session.sent[0]) in out


def test_a_changed_last_refusal_exits_2_and_is_not_sent_again(capsys):
    session = Session([UNDERPAID], [verifier(refusal="fee not paid")], REFUND,
                      call(method="attest", payload="https://example.com/h",
                           value=5 * 10 ** 15))
    assert run(session) == attest.EXIT_REFUSED
    out = capsys.readouterr().out
    assert len(session.sent) == 1
    assert "the Verifier refused the call: fee not paid" in out
    assert "not sent again" in out


def test_an_unchanged_last_refusal_with_a_refund_is_this_calls(capsys):
    # last_refusal is not cleared, so the same reason twice reads the same;
    # the refund on the transaction is what ties it to this call.
    before = {"ids": [], "refusal": "fee not paid"}
    session = Session([UNDERPAID], [verifier(refusal="fee not paid")], REFUND,
                      call(method="attest", payload="https://example.com/h",
                           value=5 * 10 ** 15), before=before)
    assert run(session) == attest.EXIT_REFUSED
    assert "the Verifier refused the call: fee not paid" in capsys.readouterr().out
    assert len(session.sent) == 1


def test_an_unchanged_last_refusal_without_a_refund_stops(capsys):
    before = {"ids": [], "refusal": NO_L}
    session = Session([AGREE, AGREE], [verifier(refusal=NO_L)], before=before)
    assert run(session) == attest.EXIT_STOPPED
    out = capsys.readouterr().out
    assert len(session.sent) == 1
    assert "last_refusal still reads %r" % (NO_L,) in out


def test_the_body_length_refusal_comes_after_the_non_deterministic_block(capsys):
    # Call 37 carries a non-deterministic output. On v1.2 that no longer
    # rules a refusal out: l= is refused on the agreed verdict.
    assert txstate.eq_block_values(AGREE["eq_outputs"])
    before = {"ids": [], "refusal": "key pending"}
    session = Session([AGREE], [verifier(refusal=NO_L)],
                      the_call=call(method="attest", payload="https://example.com/h"),
                      before=before)
    assert run(session) == attest.EXIT_REFUSED
    assert "the Verifier refused the call: %s" % (NO_L,) in capsys.readouterr().out


def test_timeout_then_success_on_attempt_2(capsys):
    session = Session([TIMEOUT, AGREE], [verifier([RECORD])])
    assert run(session) == attest.EXIT_RECORDED
    out = capsys.readouterr().out
    assert len(session.sent) == 2
    assert "FINALIZED with result TIMEOUT" in out
    assert "refunds the value" in out
    assert "sending the same attestation again as a new transaction" in out
    for tx_id in session.sent:
        assert "explorer     : %s/tx/%s" % (EXPLORER, tx_id) in out


def test_attempts_exhausted_exits_3(capsys):
    session = Session([TIMEOUT] * 3)
    assert run(session, attempts=3) == attest.EXIT_NOT_EXECUTED
    assert len(session.sent) == 3
    assert "NOT EXECUTED : 3 attempts, none executed" in capsys.readouterr().out


def test_canceled_stops_without_sending_again(capsys):
    session = Session([CANCELED, AGREE])
    assert run(session) == attest.EXIT_STOPPED
    assert len(session.sent) == 1
    assert "the transaction was CANCELED" in capsys.readouterr().out


def test_an_appeal_in_progress_stops_without_sending_again(capsys):
    session = Session([APPEALED, AGREE])
    assert run(session) == attest.EXIT_STOPPED
    assert len(session.sent) == 1
    assert "an appeal is in progress (stored status APPEAL_COMMITTING)" \
        in capsys.readouterr().out


def test_a_record_id_whose_get_is_empty_is_sent_again(capsys):
    # records_of lists "0", but get("0") answers {}: executed, nothing readable.
    first = verifier([{}])
    second = verifier([{}, dict(RECORD, id="1")])
    session = Session([AGREE, AGREE], [first, second])
    assert run(session) == attest.EXIT_RECORDED
    out = capsys.readouterr().out
    assert len(session.sent) == 2
    assert "no record it wrote can be read at LATEST_FINAL" in out
    assert "RECORD       : 1" in out


def test_no_new_record_and_no_refusal_ever_is_sent_again(capsys):
    session = Session([AGREE, AGREE], [verifier(), verifier([RECORD])])
    assert run(session) == attest.EXIT_RECORDED
    assert len(session.sent) == 2
    assert "no record it wrote can be read at LATEST_FINAL" in capsys.readouterr().out


def test_a_new_record_of_another_attestation_is_not_ours(capsys):
    other = dict(RECORD, domain="example.com")
    session = Session([AGREE], [verifier([other])])
    assert run(session, attempts=1) == attest.EXIT_NOT_EXECUTED
    assert "RECORD" not in capsys.readouterr().out


def test_a_record_of_another_requester_is_not_recorded(capsys):
    other = dict(RECORD, requester="0x" + "11" * 20)
    session = Session([AGREE], [verifier([other])])
    assert run(session, attempts=1) == attest.EXIT_NOT_EXECUTED
    assert "RECORD" not in capsys.readouterr().out


def test_two_matching_records_are_both_listed(capsys):
    session = Session([AGREE], [verifier([RECORD, dict(RECORD, id="1")])])
    assert run(session) == attest.EXIT_RECORDED
    assert "2 records match this attestation: 0, 1" in capsys.readouterr().out


def test_a_read_failure_stops(capsys):
    session = Session([AGREE, AGREE], [verifier(ids=chain.UNKNOWN)])
    assert run(session) == attest.EXIT_STOPPED
    assert len(session.sent) == 1
    assert "could not read records_of() on %s" % (VERIFIER,) in capsys.readouterr().out


def test_undetermined_at_accepted_is_not_final_and_stops(capsys):
    session = Session([UNDETERMINED])
    assert run(session, until="accepted") == attest.EXIT_STOPPED
    assert "not final" in capsys.readouterr().out


def test_still_accepted_at_the_finalized_bound_stops(capsys):
    session = Session([dict(AGREE, status="ACCEPTED")])
    assert run(session) == attest.EXIT_STOPPED
    assert "not FINALIZED at the bound: the stored status is ACCEPTED" \
        in capsys.readouterr().out


def test_ids_listed_before_the_first_attempt_are_not_this_calls():
    view = verifier([RECORD, dict(RECORD, id="1")])
    found = attest.outcome(view, lambda: [], AGREE, call(), {"ids": ["0"], "refusal": ""})
    assert [record_id for record_id, _ in found["records"]] == ["1"]


def test_the_views_are_read_at_the_state_the_decision_was_read_at():
    variants = []

    def view(address, method, args, variant):
        variants.append((method, variant))
        return verifier()(address, method, args, variant)

    attest.outcome(view, lambda: [], AGREE, call(), NOTHING)
    attest.outcome(view, lambda: [], dict(AGREE, status="ACCEPTED"), call(), NOTHING)
    assert variants == [("records_of", attest.FINAL), ("last_refusal", attest.FINAL),
                        ("records_of", attest.NONFINAL), ("last_refusal", attest.NONFINAL)]


# ---- judging without a send ----------------------------------------------

@pytest.mark.parametrize("state,verdict", [
    (TIMEOUT, attest.RESEND),
    (CANCELED, attest.STOP),
    (APPEALED, attest.STOP),
    (dict(AGREE, status="PENDING"), attest.STOP),
])
def test_judge_without_an_outcome(state, verdict):
    assert attest.judge(state, "finalized", None, SENDER)[0] == verdict


def refused(view, method="attest_inline", payload="x", domain="a.com", selector="s", value=0,
            keycache=KEYCACHE):
    return attest.refusal(view, VERIFIER, keycache, method, payload, domain, selector, value)


def test_the_refusal_checks_run_in_the_verifiers_order():
    view = verifier(fee=10)
    assert refused(view, method="attest", payload="http://x") == "url not allowed"
    assert refused(view, payload="x" * 16385) == "blob too large"
    assert refused(view, value=9) == "fee not paid"
    assert refused(view, domain=" . ", value=10) == "bad domain or selector"
    assert refused(view, value=10, keycache="") == "router resolves no keycache"
    assert refused(verifier(), domain="Amazon.com.", selector="sel1") is None


@pytest.mark.parametrize("key,reason", [
    ({}, "key not registered"),
    (dict(KEY, state="pending", activated_at=""), "key pending"),
    (dict(KEY, state="rotated"), "key rotated"),
    (dict(KEY, state="retired"), "key retired"),
    (dict(KEY, state="unknown"), "key not registered"),
    (dict(KEY, n_hex="01"), "key not registered"),
    (dict(KEY, e="2"), "key not registered"),
    (dict(KEY, n_hex="zz"), "keycache unreadable"),
    (KEY, None),
])
def test_only_an_active_key_passes(key, reason):
    assert refused(verifier(key=key)) == reason


def test_the_key_is_read_at_latest_final_from_the_keycache():
    reads = []

    def view(address, method, args, variant):
        reads.append((address, method, args, variant))
        return verifier()(address, method, args, variant)

    refused(view, domain=" Amazon.COM. ", selector="Sel1")
    assert reads[-1] == (KEYCACHE, "key_status", ["amazon.com", "sel1"], attest.FINAL)


def test_a_failed_key_read_stops_instead_of_guessing():
    with pytest.raises(attest.Stop, match="could not read key_status"):
        refused(verifier(key=chain.UNKNOWN))


# ---- resolving through the Router -----------------------------------------

def test_the_verifier_and_the_keycache_come_from_the_router():
    assert attest.resolve(verifier(), ROUTER) == (VERIFIER, KEYCACHE)


def test_a_router_with_no_keycache_resolves_to_empty():
    view = verifier(resolves={"verifier": VERIFIER})
    assert attest.resolve(view, ROUTER) == (VERIFIER, "")


def test_a_router_with_no_verifier_stops():
    with pytest.raises(attest.Stop, match="resolves no verifier"):
        attest.resolve(verifier(resolves={}), ROUTER)


def test_a_verifier_reading_another_router_stops():
    with pytest.raises(attest.Stop, match="reads its keys through the Router"):
        attest.resolve(verifier(router="0x" + "22" * 20), ROUTER)


def test_a_verifier_without_router_view_stops():
    # A Verifier before v1.2 has no router() view; the read fails.
    with pytest.raises(attest.Stop, match="could not read router"):
        attest.resolve(verifier(router=chain.UNKNOWN), ROUTER)


def test_the_router_defaults_to_the_deployments_entry():
    assert attest.router_address("bradbury") == ROUTER


# ---- the send: a refused broadcast ----------------------------------------

L2_A = "0x" + "aa" * 32
L2_B = "0x" + "bb" * 32
TX = "0x" + "cc" * 32


def chain_session(monkeypatch, outcomes, known):
    sends = []
    pauses = []

    def send(net, client, account, encoded, gas, value=0, nonce=None):
        sends.append(nonce)
        answer = outcomes.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer, 1000

    monkeypatch.setattr(chain, "estimate", lambda *args, **kwargs: 1000)
    monkeypatch.setattr(chain, "send", send)
    monkeypatch.setattr(chain, "l2_known", lambda net, l2_hash, sleep=None: known[l2_hash])
    session = attest.Session(chain.NETWORKS["bradbury"], None, None, "0x", call(),
                             sleep=pauses.append)
    return session, sends, pauses


def not_sent(l2_hash, nonce=None):
    return chain.SendFailed(chain.NOT_SENT, "not sent: refused", l2_hash, nonce)


def test_a_broadcast_not_sent_is_repeated_with_the_first_nonce(monkeypatch):
    session, sends, pauses = chain_session(
        monkeypatch, [not_sent(L2_A, 355), not_sent(L2_B, 355), TX],
        {L2_A: False, L2_B: False})
    assert session.send() == TX
    assert sends == [None, 355, 355]
    assert pauses == [30, 60]


def test_a_not_sent_hash_that_turns_up_on_chain_stops(monkeypatch):
    session, sends, _ = chain_session(monkeypatch, [not_sent(L2_A, 355), TX], {L2_A: True})
    with pytest.raises(attest.Stop, match="is on chain after all"):
        session.send()
    assert sends == [None]


def test_every_earlier_hash_is_checked_before_sending_again(monkeypatch):
    session, sends, _ = chain_session(
        monkeypatch, [not_sent(L2_A, 355), not_sent(L2_B, 355), TX],
        {L2_A: False, L2_B: None})
    with pytest.raises(attest.Stop, match="could not check whether %s" % (L2_B,)):
        session.send()
    assert sends == [None, 355]


def test_an_unknown_broadcast_outcome_stops(monkeypatch):
    failure = chain.SendFailed(chain.OUTCOME_UNKNOWN, "broadcast outcome unknown", L2_A, 1)
    session, sends, _ = chain_session(monkeypatch, [failure], {})
    with pytest.raises(attest.Stop):
        session.send()
    assert sends == [None]


def test_not_sent_every_time_stops(monkeypatch):
    session, sends, _ = chain_session(
        monkeypatch, [not_sent("0x%064x" % (n,), 7) for n in range(4)],
        {"0x%064x" % (n,): False for n in range(4)})
    with pytest.raises(attest.Stop, match="not sent 4 times"):
        session.send()
    assert sends == [None, 7, 7, 7]


def test_a_refusal_before_anything_reached_the_chain_is_nothing_sent(monkeypatch):
    failure = chain.SendFailed(chain.REFUSED, "broadcast refused: insufficient funds", L2_A, 1)
    session, _, _ = chain_session(monkeypatch, [failure], {})
    with pytest.raises(attest.NothingSent):
        session.send()


# ---- waiting for FINALIZED -------------------------------------------------

def test_the_final_wait_prints_progress_and_ends_on_finalized(monkeypatch, capsys):
    states = [dict(AGREE, status="ACCEPTED")] * 12 + [AGREE]
    monkeypatch.setattr(txstate, "stored", lambda client, tx_id, sleep=None: states.pop(0))
    now = [0.0]

    def sleep(seconds):
        now[0] += seconds

    state = txstate.wait_stored(None, TX, statuses=txstate.FINAL, budget=3600, interval=30,
                                progress=300, sleep=sleep, clock=lambda: now[0])
    out = capsys.readouterr().out
    assert state["status"] == "FINALIZED"
    assert "waiting      : %s is ACCEPTED after 5 min" % (TX[:10],) in out
    assert "stored status: FINALIZED (reached after 360 s)" in out


def test_the_final_wait_gives_up_at_its_bound(monkeypatch, capsys):
    monkeypatch.setattr(txstate, "stored",
                        lambda client, tx_id, sleep=None: dict(AGREE, status="ACCEPTED"))
    now = [0.0]

    def sleep(seconds):
        now[0] += seconds

    state = txstate.wait_stored(None, TX, statuses=txstate.FINAL, budget=600, interval=30,
                                sleep=sleep, clock=lambda: now[0])
    assert state["status"] == "ACCEPTED"
    assert "NOT reached" in capsys.readouterr().out
