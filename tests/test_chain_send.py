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

import json
import sys
from pathlib import Path

import pytest
from hexbytes import HexBytes
from web3 import Web3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import chain
from genlayer_py.chains import testnet_bradbury

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
