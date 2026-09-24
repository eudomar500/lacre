"""tools/chain.py: finding the consensus transaction an L2 receipt created.

The two fixtures are real Bradbury receipts from the probe D2 run of 24
September 2026, recorded read-only:

  receipt_new_transaction.json      call 1, L2 0x0e3bd8c0..., activated at
                                    once: NewTransaction
  receipt_created_transaction.json  call 3, L2 0xf16a26a3..., sent while
                                    call 2 was undecided: CreatedTransaction

send() used to look for NewTransaction only and exit on the second kind,
after the transaction was already on chain and would run.
"""

import http.client
import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest
from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import TimeExhausted

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import chain
from genlayer_py.chains import testnet_bradbury
from genlayer_py.exceptions import GenLayerError

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ABI = testnet_bradbury.consensus_main_contract["abi"]
CONSENSUS_MAIN = "0x0112Bf6e83497965A5fdD6Dad1E447a6E004271D"

CALL_1 = "0x1f64f1c5d1b718e1575150fbb2240ee804c1151e9cb295e10d7277b317097258"
CALL_3 = "0x32b8b4924e34b649bc5cf9d62a72d392b0074f89a1e140c1e5b06d3aed3804fc"


def receipt(name):
    """A recorded receipt, with the byte fields web3 expects as bytes."""
    raw = json.loads((FIXTURES / name).read_text(encoding="ascii"))
    for log in raw["logs"]:
        log["topics"] = [HexBytes(topic) for topic in log["topics"]]
        log["data"] = HexBytes(log["data"])
        for key in ("blockHash", "transactionHash"):
            log[key] = HexBytes(log[key])
    return raw


def without_consensus_logs(raw):
    raw = dict(raw)
    raw["logs"] = [log for log in raw["logs"] if log["address"].lower() != CONSENSUS_MAIN.lower()]
    return raw


def test_an_activated_transaction_is_found_by_new_transaction():
    assert chain.created_transaction(Web3(), ABI, receipt("receipt_new_transaction.json")) \
        == (CALL_1, "NewTransaction")


def test_a_queued_transaction_is_found_by_created_transaction():
    assert chain.created_transaction(Web3(), ABI, receipt("receipt_created_transaction.json")) \
        == (CALL_3, "CreatedTransaction")


def test_the_fixtures_are_one_of_each_kind():
    for name, present, absent in (
            ("receipt_new_transaction.json", "NewTransaction", "CreatedTransaction"),
            ("receipt_created_transaction.json", "CreatedTransaction", "NewTransaction")):
        contract = Web3().eth.contract(abi=ABI)
        raw = receipt(name)
        assert contract.get_event_by_name(present).process_receipt(raw, chain.DISCARD)
        assert not contract.get_event_by_name(absent).process_receipt(raw, chain.DISCARD)


@pytest.mark.parametrize("name", ["receipt_new_transaction.json",
                                  "receipt_created_transaction.json"])
def test_a_receipt_with_neither_event_is_none(name):
    assert chain.created_transaction(Web3(), ABI, without_consensus_logs(receipt(name))) is None


def test_the_other_contracts_logs_are_not_mistaken_for_either_event():
    raw = receipt("receipt_created_transaction.json")
    assert len(raw["logs"]) == 4
    assert len(without_consensus_logs(raw)["logs"]) == 3


# ---- send() end to end, against a stubbed client ---------------------------

class Account:
    address = "0xF27E3A6d7Bf4BfC0A837020FD74E73055aF17D53"

    def sign_transaction(self, transaction):
        class Signed:
            raw_transaction = b"\x02signed"
            hash = HexBytes(receipt_hash)
        return Signed()


receipt_hash = "0x" + "00" * 32


class Eth:
    def __init__(self, recorded):
        self.recorded = recorded

    def get_block(self, _):
        return {"baseFeePerGas": 1}

    def get_transaction_count(self, _):
        return 330

    def wait_for_transaction_receipt(self, _, timeout):
        return self.recorded

    def contract(self, abi):
        return Web3().eth.contract(abi=abi)


class W3:
    def __init__(self, recorded):
        self.eth = Eth(recorded)

    @staticmethod
    def to_wei(value, unit):
        return Web3.to_wei(value, unit)

    @staticmethod
    def to_hex(value):
        return Web3.to_hex(value)


class Client:
    def __init__(self, recorded):
        self.w3 = W3(recorded)
        self.chain = type("Chain", (), {
            "id": 4221,
            "consensus_main_contract": {"address": CONSENSUS_MAIN, "abi": ABI},
        })()


def run_send(monkeypatch, capsys, recorded):
    global receipt_hash
    receipt_hash = recorded["transactionHash"]
    monkeypatch.setattr(chain, "rpc", lambda net, method, params: {"result": receipt_hash})
    result = chain.send(chain.NETWORKS["bradbury"], Client(recorded), Account(), "0x", 1000)
    return result, capsys.readouterr().out


@pytest.mark.parametrize("name,tx_id,event", [
    ("receipt_new_transaction.json", CALL_1, "NewTransaction"),
    ("receipt_created_transaction.json", CALL_3, "CreatedTransaction"),
])
def test_send_returns_the_id_and_says_which_event(monkeypatch, capsys, name, tx_id, event):
    recorded = receipt(name)
    (consensus_id, used), out = run_send(monkeypatch, capsys, recorded)
    assert consensus_id == tx_id
    assert used == recorded["gasUsed"]
    assert "CONSENSUS TX : %s\n" % (tx_id,) in out
    assert "created by   : %s" % (event,) in out
    assert ("queued behind" in out) == (event == "CreatedTransaction")


def test_send_dies_only_when_neither_event_is_there(monkeypatch, capsys):
    recorded = without_consensus_logs(receipt("receipt_created_transaction.json"))
    with pytest.raises(SystemExit) as stopped:
        run_send(monkeypatch, capsys, recorded)
    assert stopped.value.code == 1
    assert "neither NewTransaction nor CreatedTransaction" in capsys.readouterr().err


# ---- a broadcast the node refuses, then accepts ------------------------------
#
# The refusal is the one in ~/probe-d2-clean.log, call 1 of the window of 24
# September 2026. The node put the whole reason, code and delay included, in
# the message; the two error shapes below cover that and a structured error
# carrying the code and the delay as fields.

REFUSAL_MESSAGE = (
    "server returned an error response: error code -32005: transaction gas "
    "rate limit exceeded: node is at capacity, retry in ~1659ms, "
    "data: {\"retryAfterMs\":1659}")
REFUSED_AS_LOGGED = {"code": -32603, "message": REFUSAL_MESSAGE}
REFUSED_STRUCTURED = {"code": -32005,
                      "message": "transaction gas rate limit exceeded: node is at capacity",
                      "data": {"retryAfterMs": 1659}}


class CountingAccount(Account):
    signed = 0

    def sign_transaction(self, transaction):
        CountingAccount.signed += 1
        return Account.sign_transaction(self, transaction)


def scripted_rpc(answers, sent, lookups=None, looked=None):
    """An rpc() that records what was broadcast and answers from a script.

    An answer that is an exception is raised, as rpc() raises RpcUnavailable.
    lookups answer eth_getTransactionByHash in turn; without them a lookup
    fails the test.
    """
    def rpc(net, method, params):
        if method == "eth_getTransactionByHash":
            assert lookups is not None, "the hash was looked up"
            if looked is not None:
                looked.append(params[0])
            answer = lookups.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return {"result": answer}
        assert method == "eth_sendRawTransaction"
        sent.append(params[0])
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return {"error": answer} if isinstance(answer, dict) else {"result": answer}
    return rpc


@pytest.mark.parametrize("refusal", [REFUSED_AS_LOGGED, REFUSED_STRUCTURED])
def test_a_refused_broadcast_is_sent_again_unchanged_and_then_goes_through(
        monkeypatch, capsys, refusal):
    global receipt_hash
    recorded = receipt("receipt_created_transaction.json")
    receipt_hash = recorded["transactionHash"]
    sent, pauses = [], []
    monkeypatch.setattr(chain, "rpc", scripted_rpc([refusal, refusal, receipt_hash], sent))
    monkeypatch.setattr(chain.time, "sleep", pauses.append)
    CountingAccount.signed = 0

    consensus_id, _ = chain.send(chain.NETWORKS["bradbury"], Client(recorded),
                                 CountingAccount(), "0x", 1000)

    assert consensus_id == CALL_3
    assert CountingAccount.signed == 1
    assert len(sent) == 3 and len(set(sent)) == 1
    assert pauses == [pytest.approx(1.659 + chain.RETRY_MARGIN_S)] * 2
    out = capsys.readouterr().out
    assert out.count("retry        : broadcast refused") == 2
    assert "CONSENSUS TX : %s" % (CALL_3,) in out


def test_a_broadcast_refused_every_time_is_looked_up_then_not_sent(monkeypatch, capsys):
    sent, looked = [], []
    monkeypatch.setattr(chain, "rpc", scripted_rpc(
        [REFUSED_AS_LOGGED] * chain.BROADCAST_ATTEMPTS, sent, [None], looked))
    monkeypatch.setattr(chain.time, "sleep", lambda _: None)
    with pytest.raises(SystemExit):
        chain.send(chain.NETWORKS["bradbury"],
                   Client(receipt("receipt_new_transaction.json")), Account(), "0x", 1000)
    assert len(sent) == chain.BROADCAST_ATTEMPTS
    assert looked == [receipt_hash]
    assert ("error: not sent: refused: %s after %d sends; %s is not on chain"
            % (REFUSAL_MESSAGE, chain.BROADCAST_ATTEMPTS, receipt_hash)
            in capsys.readouterr().err)


def test_a_refusal_that_does_not_invite_a_retry_dies_at_once(monkeypatch, capsys):
    sent = []
    monkeypatch.setattr(chain, "rpc", scripted_rpc(
        [{"code": -32000, "message": "insufficient funds for gas * price + value"}], sent))
    with pytest.raises(SystemExit):
        chain.send(chain.NETWORKS["bradbury"],
                   Client(receipt("receipt_new_transaction.json")), Account(), "0x", 1000)
    assert len(sent) == 1
    assert "broadcast refused: insufficient funds" in capsys.readouterr().err


@pytest.mark.parametrize("error,delay", [
    (REFUSED_AS_LOGGED, 1.659),
    (REFUSED_STRUCTURED, 1.659),
    ({"code": -32005, "message": "node is at capacity"}, 0.0),
    ({"code": -32603, "message": "busy, retry in 250ms"}, 0.25),
    ({"code": -32000, "message": "nonce too low"}, None),
    ({"code": -32000, "message": "insufficient funds for gas"}, None),
    ("not a dict", None),
])
def test_the_delay_a_refusal_asks_for(error, delay):
    got = chain.retry_after(error)
    if delay is None:
        assert got is None
    else:
        assert got == pytest.approx(delay)


def test_a_refusal_without_a_delay_backs_off(monkeypatch):
    sent, pauses = [], []
    no_delay = {"code": -32005, "message": "node is at capacity"}
    monkeypatch.setattr(chain, "rpc", scripted_rpc([no_delay, no_delay, no_delay, "0xab"], sent))
    assert chain.broadcast(chain.NETWORKS["bradbury"], "0xraw", "0xab",
                           sleep=pauses.append) == "0xab"
    assert pauses == [1.0, 2.0, 4.0]
    assert sent == ["0xraw"] * 4


# ---- waits that resume after a transient failure ------------------------------

GATEWAY_520 = ("eth_getTransactionReceipt returned invalid JSON: Expecting value: "
               "line 1 column 1 (char 0). Response content: <!DOCTYPE html> "
               "<title>rpc-bradbury.genlayer.com | 520: Web server is returning an "
               "unknown error</title>")
DROPPED = ("Request to https://rpc-bradbury.genlayer.com failed: (\"Connection broken: "
           "InvalidChunkLength(got length b'', 0 bytes read)\")")


class FlakyEth(Eth):
    def __init__(self, recorded, failures):
        Eth.__init__(self, recorded)
        self.failures = list(failures)
        self.asked = []

    def wait_for_transaction_receipt(self, l2_hash, timeout):
        self.asked.append(l2_hash)
        if self.failures:
            raise self.failures.pop(0)
        return self.recorded


@pytest.mark.parametrize("failure", [GenLayerError(DROPPED), GenLayerError(GATEWAY_520),
                                     ConnectionResetError("reset")])
def test_the_wait_for_the_l2_receipt_resumes_on_the_same_hash(monkeypatch, capsys, failure):
    global receipt_hash
    recorded = receipt("receipt_new_transaction.json")
    receipt_hash = recorded["transactionHash"]
    client = Client(recorded)
    client.w3.eth = FlakyEth(recorded, [failure])
    monkeypatch.setattr(chain, "rpc", lambda net, method, params: {"result": receipt_hash})
    monkeypatch.setattr(chain.time, "sleep", lambda _: None)
    consensus_id, _ = chain.send(chain.NETWORKS["bradbury"], client, Account(), "0x", 1000)
    assert consensus_id == CALL_1
    assert client.w3.eth.asked == [receipt_hash, receipt_hash]
    assert "resuming" in capsys.readouterr().out


@pytest.mark.parametrize("error,expected", [
    (GenLayerError(DROPPED), True),
    (GenLayerError(GATEWAY_520), True),
    (OSError("reset"), True),
    (GenLayerError("eth_call failed (code=3): execution reverted"), False),
    (GenLayerError("Transaction 0x.. did not reach desired status"), False),
    (ValueError("bad"), False),
])
def test_what_counts_as_transient(error, expected):
    assert chain.transient(error) is expected


class WaitClient:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.asked = []

    def wait_for_transaction_receipt(self, transaction_hash, **_):
        self.asked.append(transaction_hash)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def test_the_wait_for_acceptance_survives_a_gateway_error_page():
    pauses = []
    client = WaitClient(GenLayerError(GATEWAY_520), {"status_name": "ACCEPTED"})
    assert chain.wait_accepted(client, CALL_1, sleep=pauses.append) == {"status_name": "ACCEPTED"}
    assert client.asked == [CALL_1, CALL_1]
    assert pauses == [chain.WAIT_PAUSE_S]


def test_the_wait_for_acceptance_gives_up_in_the_end():
    client = WaitClient(*[GenLayerError(DROPPED)] * chain.WAIT_ATTEMPTS)
    with pytest.raises(GenLayerError):
        chain.wait_accepted(client, CALL_1, sleep=lambda _: None)
    assert len(client.asked) == chain.WAIT_ATTEMPTS


def test_an_answer_ends_the_wait_at_once():
    client = WaitClient(GenLayerError("Transaction 0x.. not found"))
    with pytest.raises(GenLayerError):
        chain.wait_accepted(client, CALL_1, sleep=lambda _: None)
    assert len(client.asked) == 1


# ---- rpc(): no answer is not an answer -----------------------------------------
#
# From ~/probe-d2-clean.log, call 2 of the third window, 24 September 2026:
# eth_sendRawTransaction was refused once with -32005 (the retry line below,
# as logged), and the send of the same bytes after the pause got
# "urllib.error.HTTPError: HTTP Error 522: <none>" from the gateway, raised
# out of rpc() at "with urllib.request.urlopen(request, timeout=180)". The
# L2 hash, 0xf6bd805c..., was confirmed absent from the chain afterwards and
# the account's next nonce is still 355.

L2_355 = "0xf6bd805c287f718021fadfc45fca4108e6806f7329178a7b91446e7da593dd71"
LOGGED_RETRY = ("retry        : broadcast refused (code -32005), sending the same signed "
                "transaction again in 0.7 s, attempt 2 of 8")
# The refusal behind that line: the code is logged, the 0.2 s delay is what
# 0.7 s minus RETRY_MARGIN_S leaves, and the wording is the -32005 one above.
REFUSED_200MS = {"code": -32005,
                 "message": "transaction gas rate limit exceeded: node is at capacity, "
                            "retry in ~200ms",
                 "data": {"retryAfterMs": 200}}
URL = "https://rpc-bradbury.genlayer.com"


def gateway(code, body=b""):
    """The HTTPError urllib raises for a gateway status, as in the log."""
    return urllib.error.HTTPError(URL, code, "<none>", {}, io.BytesIO(body))


class Response:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return self.body


class Node:
    """urlopen() for rpc(), answering from two scripts.

    An exception is raised as urlopen raises it, bytes are the body as sent,
    and anything else is sent as JSON.
    """

    def __init__(self, sends=(), lookups=()):
        self.sends = list(sends)
        self.lookups = list(lookups)
        self.raw = []
        self.looked = []

    def __call__(self, request, timeout):
        payload = json.loads(request.data)
        if payload["method"] == "eth_getTransactionByHash":
            self.looked.append(payload["params"][0])
            answer = self.lookups.pop(0)
        else:
            self.raw.append(payload["params"][0] if payload["params"] else None)
            answer = self.sends.pop(0)
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, bytes):
            return Response(answer)
        return Response(json.dumps(answer).encode())


def answer(result=None, error=None):
    body = {"jsonrpc": "2.0", "id": 1}
    body.update({"error": error} if error else {"result": result})
    return body


@pytest.fixture
def quiet(monkeypatch):
    pauses = []
    monkeypatch.setattr(chain.time, "sleep", pauses.append)
    return pauses


def use(monkeypatch, node):
    monkeypatch.setattr(chain.urllib.request, "urlopen", node)
    return node


def test_the_logged_522_is_no_answer(monkeypatch):
    use(monkeypatch, Node([gateway(522)]))
    with pytest.raises(chain.RpcUnavailable, match="HTTP 522 from the gateway"):
        chain.rpc(chain.NETWORKS["bradbury"], "eth_sendRawTransaction", ["0xraw"])


@pytest.mark.parametrize("failure", [
    gateway(502), gateway(503), gateway(429),
    urllib.error.URLError(TimeoutError("timed out")),
    TimeoutError("The read operation timed out"),
    http.client.RemoteDisconnected("Remote end closed connection without response"),
    http.client.IncompleteRead(b"", 10),
    ConnectionResetError("reset"),
])
def test_every_kind_of_no_answer_is_rpc_unavailable(monkeypatch, failure):
    use(monkeypatch, Node([failure]))
    with pytest.raises(chain.RpcUnavailable):
        chain.rpc(chain.NETWORKS["bradbury"], "eth_sendRawTransaction", ["0xraw"])


def test_an_html_error_page_with_status_200_is_no_answer(monkeypatch):
    use(monkeypatch, Node([b"<!DOCTYPE html><title>rpc-bradbury.genlayer.com | 520: Web "
                           b"server is returning an unknown error</title>"]))
    with pytest.raises(chain.RpcUnavailable, match="not JSON-RPC"):
        chain.rpc(chain.NETWORKS["bradbury"], "eth_estimateGas", [{}])


def test_a_json_rpc_error_sent_with_a_5xx_status_is_an_answer(monkeypatch):
    body = json.dumps(answer(error=REFUSED_200MS)).encode()
    use(monkeypatch, Node([gateway(503, body)]))
    assert chain.rpc(chain.NETWORKS["bradbury"], "eth_sendRawTransaction",
                     ["0xraw"])["error"] == REFUSED_200MS


def test_a_4xx_that_is_not_json_rpc_is_raised_as_it_is(monkeypatch):
    use(monkeypatch, Node([gateway(403, b"forbidden")]))
    with pytest.raises(urllib.error.HTTPError) as raised:
        chain.rpc(chain.NETWORKS["bradbury"], "eth_chainId", [])
    assert not isinstance(raised.value, chain.RpcUnavailable)


def test_a_read_is_asked_again_after_no_answer(monkeypatch, quiet):
    node = use(monkeypatch, Node([gateway(522), gateway(520), answer("0x10e62b")]))
    out = chain.rpc_read(chain.NETWORKS["bradbury"], "eth_estimateGas", [{}])
    assert out["result"] == "0x10e62b"
    assert len(node.raw) == 3
    assert quiet == [chain.READ_PAUSE_S, chain.READ_PAUSE_S * 2]


def test_a_read_gives_up_in_the_end(monkeypatch, quiet):
    use(monkeypatch, Node([gateway(522)] * chain.READ_ATTEMPTS))
    with pytest.raises(chain.RpcUnavailable):
        chain.rpc_read(chain.NETWORKS["bradbury"], "eth_estimateGas", [{}])


# ---- broadcast(): the same signed bytes after no answer ----------------------------

def test_the_logged_sequence_now_goes_through(monkeypatch, capsys, quiet):
    """-32005, then the 522, then the same bytes are taken: one transaction."""
    global receipt_hash
    recorded = receipt("receipt_created_transaction.json")
    receipt_hash = recorded["transactionHash"]
    node = use(monkeypatch, Node([answer(error=REFUSED_200MS), gateway(522),
                                  answer(receipt_hash)]))
    CountingAccount.signed = 0

    consensus_id, _ = chain.send(chain.NETWORKS["bradbury"], Client(recorded),
                                 CountingAccount(), "0x", 1000)

    assert consensus_id == CALL_3
    assert CountingAccount.signed == 1
    assert len(node.raw) == 3 and len(set(node.raw)) == 1
    assert node.looked == []
    out = capsys.readouterr().out
    assert LOGGED_RETRY + "\n" in out
    assert ("retry        : broadcast got no answer (eth_sendRawTransaction: HTTP 522 from "
            "the gateway), sending the same signed transaction again in 4.0 s, attempt 3 "
            "of 8\n") in out
    assert quiet == [pytest.approx(0.7), 4.0]
    assert "created by   : CreatedTransaction" in out


@pytest.mark.parametrize("message", [
    "already known", "AlreadyKnown", "known transaction: 0xf6bd",
    "transaction already imported", "transaction already in mempool"])
def test_already_known_after_no_answer_is_sent(monkeypatch, capsys, quiet, message):
    node = use(monkeypatch, Node([gateway(522), answer(error={"code": -32000,
                                                             "message": message})]))
    assert chain.broadcast(chain.NETWORKS["bradbury"], "0xraw", L2_355) == L2_355
    assert node.raw == ["0xraw", "0xraw"] and node.looked == []
    assert "the node already has %s" % (L2_355,) in capsys.readouterr().out


def test_nonce_too_low_with_the_hash_on_chain_is_sent(monkeypatch, capsys, quiet):
    node = use(monkeypatch, Node(
        [gateway(522), answer(error={"code": -32000, "message": "nonce too low"})],
        [answer({"hash": L2_355, "nonce": "0x163"})]))
    assert chain.broadcast(chain.NETWORKS["bradbury"], "0xraw", L2_355) == L2_355
    assert node.looked == [L2_355]
    assert "an earlier send got through" in capsys.readouterr().out


def test_nonce_too_low_without_the_hash_dies_at_once(monkeypatch, capsys, quiet):
    node = use(monkeypatch, Node(
        [answer(error={"code": -32000, "message": "nonce too low"})], [answer(None)]))
    with pytest.raises(SystemExit):
        chain.broadcast(chain.NETWORKS["bradbury"], "0xraw", L2_355)
    assert len(node.raw) == 1
    assert ("error: broadcast refused: nonce too low; %s is not on chain, so another "
            "transaction holds this nonce" % (L2_355,)) in capsys.readouterr().err


def test_no_answer_every_time_but_on_chain_is_sent(monkeypatch, capsys, quiet):
    node = use(monkeypatch, Node([gateway(522)] * chain.BROADCAST_ATTEMPTS,
                                 [answer({"hash": L2_355, "blockNumber": None})]))
    assert chain.broadcast(chain.NETWORKS["bradbury"], "0xraw", L2_355) == L2_355
    assert len(node.raw) == chain.BROADCAST_ATTEMPTS and node.looked == [L2_355]
    assert "is on chain; continuing as sent" in capsys.readouterr().out


def test_no_answer_every_time_and_not_on_chain_says_not_sent(monkeypatch, capsys, quiet):
    use(monkeypatch, Node([gateway(522)] * chain.BROADCAST_ATTEMPTS, [answer(None)]))
    with pytest.raises(SystemExit):
        chain.broadcast(chain.NETWORKS["bradbury"], "0xraw", L2_355)
    err = capsys.readouterr().err
    assert err.startswith("error: not sent: no answer (eth_sendRawTransaction: HTTP 522")
    assert "after 8 sends; %s is not on chain" % (L2_355,) in err
    assert quiet[:chain.BROADCAST_ATTEMPTS - 1] == [2.0, 4.0, 8.0, 16.0, 30.0, 30.0, 30.0]


def test_no_answer_and_no_lookup_either_is_outcome_unknown(monkeypatch, capsys, quiet):
    use(monkeypatch, Node([gateway(522)] * chain.BROADCAST_ATTEMPTS,
                          [gateway(522)] * chain.READ_ATTEMPTS))
    with pytest.raises(SystemExit):
        chain.broadcast(chain.NETWORKS["bradbury"], "0xraw", L2_355)
    err = capsys.readouterr().err
    assert err.startswith("error: broadcast outcome unknown: ")
    assert "not sent" not in err


def test_a_refusal_that_no_retry_changes_is_not_looked_up(monkeypatch, capsys, quiet):
    node = use(monkeypatch, Node([gateway(522), answer(error={
        "code": -32000, "message": "insufficient funds for gas * price + value"})]))
    with pytest.raises(SystemExit):
        chain.broadcast(chain.NETWORKS["bradbury"], "0xraw", L2_355)
    assert node.looked == [] and len(node.raw) == 2
    assert "error: broadcast refused: insufficient funds" in capsys.readouterr().err


# ---- send(): the reads before signing, a pinned nonce, a slow L2 receipt -----------

class CountEth(Eth):
    def __init__(self, recorded, counts):
        Eth.__init__(self, recorded)
        self.counts = list(counts)

    def get_transaction_count(self, _):
        answer = self.counts.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def pinned(monkeypatch, capsys, counts, nonce):
    global receipt_hash
    recorded = receipt("receipt_new_transaction.json")
    receipt_hash = recorded["transactionHash"]
    client = Client(recorded)
    client.w3.eth = CountEth(recorded, counts)
    node = use(monkeypatch, Node([answer(receipt_hash)]))
    CountingAccount.signed = 0
    result = chain.send(chain.NETWORKS["bradbury"], client, CountingAccount(), "0x", 1000,
                        nonce=nonce)
    return result, node, capsys.readouterr().out


def test_a_pinned_nonce_the_account_is_at_is_used(monkeypatch, capsys, quiet):
    (consensus_id, _), node, out = pinned(monkeypatch, capsys, [355], 355)
    assert consensus_id == CALL_1 and len(node.raw) == 1
    assert "nonce        : 355\n" in out


def test_a_pinned_nonce_the_account_has_passed_dies_before_signing(monkeypatch, capsys, quiet):
    with pytest.raises(SystemExit):
        pinned(monkeypatch, capsys, [356], 355)
    assert CountingAccount.signed == 0
    assert ("error: nonce 355 is already used (the account is at 356)"
            in capsys.readouterr().err)


def test_the_nonce_read_is_asked_again_after_a_gateway_page(monkeypatch, capsys, quiet):
    (consensus_id, _), _, out = pinned(
        monkeypatch, capsys,
        [GenLayerError("eth_getTransactionCount returned invalid JSON: Expecting value: "
                       "line 1 column 1 (char 0). Response content: <!DOCTYPE html>"), 355],
        None)
    assert consensus_id == CALL_1
    assert "retry        : reading the nonce failed (GenLayerError)" in out


def test_an_l2_receipt_slower_than_the_wait_is_waited_for_again(monkeypatch, capsys, quiet):
    global receipt_hash
    recorded = receipt("receipt_created_transaction.json")
    receipt_hash = recorded["transactionHash"]
    client = Client(recorded)
    client.w3.eth = FlakyEth(recorded, [TimeExhausted("not in 300 s")])
    use(monkeypatch, Node([answer(receipt_hash)]))
    consensus_id, _ = chain.send(chain.NETWORKS["bradbury"], client, Account(), "0x", 1000)
    assert consensus_id == CALL_3
    assert client.w3.eth.asked == [receipt_hash, receipt_hash]


def test_the_estimate_is_asked_again_after_no_answer(monkeypatch, capsys, quiet):
    class Estimating:
        chain = type("Chain", (), {"consensus_main_contract": {"address": CONSENSUS_MAIN}})()

    node = use(monkeypatch, Node([gateway(522), answer("0x10e62b")]))
    gas = chain.estimate(chain.NETWORKS["bradbury"], Estimating(), Account(), "0x", final=False)
    assert gas == 0x10e62b and len(node.raw) == 2
