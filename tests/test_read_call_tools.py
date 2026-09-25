"""tools/read.py without a key, and tools/call.py's wait surviving Bradbury.

The gen_call fixtures are Bradbury answers recorded read-only on 24
September 2026, sent from the zero address with no account:
gen_call_registry_key_count.json (Registry v1 key_count(), 1) and
gen_call_verifier_get_missing.json (Verifier v1.1 get("0"), {}).
"""

import json
import sys
from pathlib import Path

import pytest
import requests
from web3.constants import ADDRESS_ZERO

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import call
import chain
import read
import txstate

FIXTURES = Path(__file__).resolve().parent / "fixtures"
TX_ID = "0xa9d33cede0b3a30e9e4651438ddd2a803f4eed3ed89d663f64f5b5689dcb6a36"


def fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="ascii"))


# ---- read.py ---------------------------------------------------------------

class KeylessClient:
    local_account = None


def run_read(monkeypatch, capsys, name):
    recorded = fixture(name)
    asked = []

    def rpc(net, method, params):
        asked.append((method, params))
        return recorded["response"]

    def no_key(network):
        raise AssertionError("read.py asked for an account")

    monkeypatch.delenv("PROBE_PK", raising=False)
    monkeypatch.setattr(chain, "connect", no_key)
    monkeypatch.setattr(txstate, "connect_readonly",
                        lambda network: (KeylessClient(), chain.NETWORKS[network]))
    monkeypatch.setattr(chain, "rpc", rpc)
    # "str:" keeps a digit string a string, as on the command line.
    monkeypatch.setattr(sys, "argv", ["read.py", recorded["to"], recorded["method"]]
                        + ["str:" + arg for arg in recorded["args"]])
    read.main()
    return capsys.readouterr().out, asked


def test_read_needs_no_key_and_keeps_its_output(monkeypatch, capsys):
    out, asked = run_read(monkeypatch, capsys, "gen_call_registry_key_count.json")
    assert out == ("network      : bradbury (chain id 4221)\n"
                   "contract     : 0x1E1380B71F1C9c622C432B6FD6fa56097B1E4Ddc\n"
                   "method       : key_count()\n"
                   "\n"
                   "1\n")
    [(method, [params])] = asked
    assert method == "gen_call"
    assert params["from"] == ADDRESS_ZERO
    assert params["transaction_hash_variant"] == "latest-nonfinal"


def test_read_of_an_empty_record(monkeypatch, capsys):
    out, _ = run_read(monkeypatch, capsys, "gen_call_verifier_get_missing.json")
    assert out.endswith("method       : get('0',)\n\n(empty)\n")


def test_the_readonly_client_is_built_without_an_account(monkeypatch):
    import genlayer_py

    built = []

    class Client:
        chain = type("Chain", (), {"id": 4221})()

    def create_client(**kwargs):
        built.append(kwargs)
        return Client()

    monkeypatch.delenv("PROBE_PK", raising=False)
    monkeypatch.setattr(genlayer_py, "create_client", create_client)
    client, net = txstate.connect_readonly("bradbury")
    assert isinstance(client, Client) and net is chain.NETWORKS["bradbury"]
    assert [sorted(kwargs) for kwargs in built] == [["chain"]]


# ---- call.py -----------------------------------------------------------------

GATEWAY_522 = requests.HTTPError("522 Server Error: <none> for url: "
                                 "https://rpc-bradbury.genlayer.com/")


def unnamed_status():
    """The KeyError genlayer-py raises on a status number it cannot name."""
    TRANSACTION_STATUS_NUMBER_TO_NAME = {}
    return TRANSACTION_STATUS_NUMBER_TO_NAME["14"]


class WaitingClient:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.asked = []

    def wait_for_transaction_receipt(self, transaction_hash, **_):
        self.asked.append(transaction_hash)
        answer = self.answers.pop(0)
        if callable(answer):
            return answer()
        if isinstance(answer, Exception):
            raise answer
        return answer


def run_call(monkeypatch, capsys, client, stored=None):
    account = type("Account", (), {"address": "0x" + "ab" * 20})()
    monkeypatch.setattr(chain, "connect",
                        lambda network: (account, client, chain.NETWORKS["bradbury"]))
    monkeypatch.setattr(chain, "write_calldata", lambda *args: "0x")
    monkeypatch.setattr(chain, "estimate", lambda *args, **kwargs: 1000)
    monkeypatch.setattr(chain, "send", lambda *args, **kwargs: (TX_ID, 1000))
    monkeypatch.setattr(txstate.time, "sleep", lambda _: None)
    if stored is not None:
        monkeypatch.setattr(txstate, "stored", lambda client, tx_id, sleep=None: stored.pop(0))
    monkeypatch.setattr(sys, "argv", ["call.py", "0x" + "cd" * 20, "set_fee", "0"])
    call.main()
    return capsys.readouterr().out


def accepted():
    return {"status_name": "ACCEPTED", "tx_execution_result_name": "FINISHED_WITH_RETURN",
            "result_name": "AGREE"}


def stored_state(status):
    return {"status": status, "previous": "UNINITIALIZED", "result": "AGREE",
            "execution": "FINISHED_WITH_RETURN", "sender": "", "recipient": "", "value": 0,
            "eq_outputs": b"", "rounds": 1}


def test_call_wait_survives_a_gateway_522(monkeypatch, capsys):
    client = WaitingClient(GATEWAY_522, accepted())
    out = run_call(monkeypatch, capsys, client)
    assert client.asked == [TX_ID, TX_ID]
    assert "retry        : the wait for %s failed (HTTPError)" % (TX_ID,) in out
    assert "status       : ACCEPTED" in out


def test_call_wait_survives_a_status_number_the_sdk_cannot_name(monkeypatch, capsys):
    client = WaitingClient(unnamed_status)
    out = run_call(monkeypatch, capsys, client,
                   stored=[stored_state("PROPOSING"), stored_state("ACCEPTED")])
    assert client.asked == [TX_ID]
    assert "unknown number 14 in genlayer-py's TRANSACTION_STATUS_NUMBER_TO_NAME" in out
    assert "status       : ACCEPTED" in out
    assert "execution    : FINISHED_WITH_RETURN" in out


def test_call_believes_canceled_only_from_the_stored_status(monkeypatch, capsys):
    client = WaitingClient(dict(accepted(), status_name="CANCELED"))
    out = run_call(monkeypatch, capsys, client,
                   stored=[stored_state("PENDING"), stored_state("PENDING"),
                           stored_state("ACCEPTED")])
    assert "the view says CANCELED, the stored status is PENDING" in out
    assert "status       : ACCEPTED" in out


def test_call_wait_raises_on_an_answer(monkeypatch, capsys):
    from genlayer_py.exceptions import GenLayerError

    client = WaitingClient(GenLayerError("Transaction %s not found" % (TX_ID,)))
    with pytest.raises(GenLayerError):
        run_call(monkeypatch, capsys, client)
    assert client.asked == [TX_ID]
