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

verifier_record.json is built to the shape Verifier.get() returns; v1.1 has
written no record on chain to record one from. Stored states for CANCELED
and an appeal are the recorded ones with the status changed.
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
VERIFIER = "0x9821cfa5fe33a24f9d1D3Cca15885f1a2781EA1d"
REGISTRY = "0x1E1380B71F1C9c622C432B6FD6fa56097B1E4Ddc"
EXPLORER = "https://explorer-bradbury.genlayer.com"


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
RECORD = json.loads((FIXTURES / "verifier_record.json").read_text(encoding="ascii"))
KEY = {"domain": "amazon.com", "selector": "sel1", "n_hex": "c3" * 128, "e": "65537",
       "key_bits": "1024", "retired": False, "rotated": False}


def call(**changes):
    base = {"verifier": VERIFIER, "method": "attest_inline", "payload": "From: x\r\n",
            "domain": "amazon.com", "selector": "sel1", "sender": SENDER, "value": 0}
    base.update(changes)
    return base


def verifier(records=(), fee=0, key=KEY, count=None):
    """A view function over a Verifier holding records, from id 0."""
    records = list(records)

    def view(address, method, args, variant):
        if address == VERIFIER:
            if method == "count":
                return len(records) if count is None else count
            if method == "get":
                index = int(args[0])
                return records[index] if index < len(records) else {}
            if method == "fee":
                return fee
            if method == "registry":
                return REGISTRY
        if address == REGISTRY and method == "get_key":
            return key
        raise AssertionError((address, method, args))
    return view


class Session:
    """attest.Session without the chain: one stored state and one Verifier
    snapshot per attempt, in order. The Verifier is read only for an
    attempt that executed."""

    def __init__(self, states, snapshots=(), messages=(), the_call=None, start=0):
        self.call = the_call or call()
        self.states = list(states)
        self.snapshots = list(snapshots)
        self.message_list = list(messages)
        self.first = start
        self.sent = []

    def start(self):
        return self.first

    def send(self):
        tx_id = "0x%064x" % (len(self.sent) + 1,)
        self.sent.append(tx_id)
        return tx_id

    def wait(self, tx_id, until):
        return self.states.pop(0)

    def outcome(self, state, tx_id, start):
        view = self.snapshots.pop(0)
        return attest.outcome(view, lambda: self.message_list, state, self.call, start)


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


def test_a_reason_string_exits_2_and_is_not_sent_again(capsys):
    session = Session([UNDERPAID], [verifier(fee=10 ** 16)], REFUND,
                      call(method="attest", payload="https://example.com/h",
                           value=5 * 10 ** 15))
    assert run(session) == attest.EXIT_REFUSED
    out = capsys.readouterr().out
    assert len(session.sent) == 1
    assert "the Verifier refused the call: fee not paid" in out


def test_a_refund_is_a_refusal_even_when_the_checks_pass_now(capsys):
    # The fee was set back to 0 after the underpaid call, as it was on chain.
    session = Session([UNDERPAID], [verifier(fee=0)], REFUND,
                      call(method="attest", payload="https://example.com/h",
                           value=5 * 10 ** 15))
    assert run(session) == attest.EXIT_REFUSED
    assert "refused, with the value refunded" in capsys.readouterr().out
    assert len(session.sent) == 1


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
    # count() moved to 1, but get("0") answers {}: executed, nothing readable.
    first = verifier([{}])
    second = verifier([{}, dict(RECORD, id="1")])
    session = Session([AGREE, AGREE], [first, second])
    assert run(session) == attest.EXIT_RECORDED
    out = capsys.readouterr().out
    assert len(session.sent) == 2
    assert "no record it wrote can be read at LATEST_FINAL" in out
    assert "RECORD       : 1" in out


def test_a_record_of_another_requester_is_not_ours(capsys):
    other = dict(RECORD, requester="0x" + "11" * 20)
    session = Session([AGREE], [verifier([other])])
    assert run(session, attempts=1) == attest.EXIT_NOT_EXECUTED
    assert "RECORD" not in capsys.readouterr().out


def test_two_matching_records_are_both_listed(capsys):
    session = Session([AGREE], [verifier([RECORD, dict(RECORD, id="1")])])
    assert run(session) == attest.EXIT_RECORDED
    assert "2 records match this attestation: 0, 1" in capsys.readouterr().out


def test_a_read_failure_stops(capsys):
    session = Session([AGREE, AGREE], [verifier(count=chain.UNKNOWN)])
    assert run(session) == attest.EXIT_STOPPED
    assert len(session.sent) == 1
    assert "could not read count() on the Verifier" in capsys.readouterr().out


def test_undetermined_at_accepted_is_not_final_and_stops(capsys):
    session = Session([UNDETERMINED])
    assert run(session, until="accepted") == attest.EXIT_STOPPED
    assert "not final" in capsys.readouterr().out


def test_still_accepted_at_the_finalized_bound_stops(capsys):
    session = Session([dict(AGREE, status="ACCEPTED")])
    assert run(session) == attest.EXIT_STOPPED
    assert "not FINALIZED at the bound: the stored status is ACCEPTED" \
        in capsys.readouterr().out


def test_records_start_at_the_count_before_the_first_attempt():
    view = verifier([RECORD, dict(RECORD, id="1")])
    found = attest.outcome(view, lambda: [], AGREE, call(), 1)
    assert [record_id for record_id, _ in found["records"]] == ["1"]


# ---- judging without a send ----------------------------------------------

@pytest.mark.parametrize("state,verdict", [
    (TIMEOUT, attest.RESEND),
    (CANCELED, attest.STOP),
    (APPEALED, attest.STOP),
    (dict(AGREE, status="PENDING"), attest.STOP),
])
def test_judge_without_an_outcome(state, verdict):
    assert attest.judge(state, "finalized", None, SENDER)[0] == verdict


def test_the_refusal_checks_run_in_the_verifiers_order():
    view = verifier(fee=10)
    assert attest.refusal(view, VERIFIER, "attest", "http://x", "a.com", "s", 0) \
        == "url not allowed"
    assert attest.refusal(view, VERIFIER, "attest_inline", "x" * 16385, "a.com", "s", 0) \
        == "blob too large"
    assert attest.refusal(view, VERIFIER, "attest_inline", "x", "a.com", "s", 9) \
        == "fee not paid"
    assert attest.refusal(view, VERIFIER, "attest_inline", "x", " . ", "s", 10) \
        == "bad domain or selector"
    assert attest.refusal(verifier(key={}), VERIFIER, "attest_inline", "x", "a.com", "s", 0) \
        == "key not registered"
    assert attest.refusal(verifier(key=dict(KEY, retired=True)), VERIFIER, "attest_inline",
                          "x", "a.com", "s", 0) == "key not registered"
    assert attest.refusal(verifier(), VERIFIER, "attest_inline", "x", "Amazon.com.", "sel1",
                          0) is None


def test_an_eq_output_on_a_url_call_rules_a_refusal_out():
    # Call 37 carries a non-deterministic output; the key is gone now, so
    # only the output can say the checks passed at execution.
    found = attest.outcome(verifier(key={}), lambda: [], AGREE,
                           call(method="attest", payload="https://example.com/h"), 0)
    assert found == {"records": [], "reason": None}


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
