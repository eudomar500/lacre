"""tools/deploy.py: a transient RPC failure after the deploy is on chain.

On 24 September 2026 a deploy that had succeeded died on a gateway 520
while waiting for ACCEPTED and never printed its address. deploy.main is
driven here against a stubbed client whose wait fails that way once; the
signing, the broadcast, the provenance check and deployments.json are all
stubbed out, so nothing is sent and nothing is written.
"""

import sys
from pathlib import Path

import pytest
from genlayer_py.exceptions import GenLayerError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import chain
import deploy
import provenance

CONTRACT = ROOT / "experiments" / "llm-probe-2" / "contracts" / "llm_probe2.py"
TX_ID = "0x25a7ea67ab5353b452130a18dd56b060f7efe7ac27b60fb53f35de16a2c4b3b0"
ADDRESS = "0x4daf20ccdcdC968eF8c8eB0FcA9082cCdb0C30aB"
# What provenance.collect returns for a clean tree; the refusal itself is
# tested in test_deploy_provenance.py, and this tree may well be dirty.
FACTS = {"commit": "c" * 40, "commit_dirty": False, "inlined_modules": {},
         "provenance": provenance.RECORDED_AT_DEPLOY,
         "source_path": "experiments/llm-probe-2/contracts/llm_probe2.py",
         "source_sha256": "0" * 64, "source_size": 1}

GATEWAY_520 = ("eth_getTransactionReceipt returned invalid JSON: Expecting value: "
               "line 1 column 1 (char 0). Response content: <!DOCTYPE html> "
               "<title>rpc-bradbury.genlayer.com | 520: Web server is returning an "
               "unknown error</title>")


class Client:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.asked = []
        eth = type("Eth", (), {"get_balance": staticmethod(lambda address: 10 ** 18)})
        self.w3 = type("W3", (), {"eth": eth})()

    def wait_for_transaction_receipt(self, transaction_hash, **_):
        self.asked.append(transaction_hash)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def run_deploy(monkeypatch, client):
    account = type("Account", (), {"address": "0x" + "ab" * 20})()
    recorded = []
    monkeypatch.setattr(provenance, "collect", lambda *args: (FACTS, []))
    monkeypatch.setattr(chain, "connect",
                        lambda network: (account, client, chain.NETWORKS["bradbury"]))
    monkeypatch.setattr(chain, "deploy_calldata", lambda *args: "0x")
    monkeypatch.setattr(chain, "estimate", lambda *args, **kwargs: 1000)
    monkeypatch.setattr(chain, "send", lambda *args, **kwargs: (TX_ID, 1000))
    monkeypatch.setattr(chain.time, "sleep", lambda _: None)
    monkeypatch.setattr(deploy, "record_deployment", lambda *args: recorded.append(args))
    monkeypatch.setattr(sys, "argv", ["deploy.py", str(CONTRACT)])
    deploy.main()
    return recorded


def accepted():
    return {"status_name": "ACCEPTED", "tx_execution_result_name": "FINISHED_WITH_RETURN",
            "result_name": "AGREE", "tx_data_decoded": {"contract_address": ADDRESS}}


def test_a_gateway_error_page_during_the_wait_does_not_lose_the_address(monkeypatch, capsys):
    client = Client(GenLayerError(GATEWAY_520), accepted())
    recorded = run_deploy(monkeypatch, client)
    out = capsys.readouterr().out
    assert client.asked == [TX_ID, TX_ID]
    assert "CONTRACT     : %s" % (ADDRESS,) in out
    assert "retry        : the wait for %s failed (GenLayerError)" % (TX_ID,) in out
    assert recorded == [("bradbury", "llm_probe2", ADDRESS, TX_ID, FACTS)]


def test_a_dropped_connection_during_the_wait_is_resumed_too(monkeypatch, capsys):
    client = Client(GenLayerError("Request to https://rpc-bradbury.genlayer.com failed: "
                                  "Connection broken"), OSError("reset"), accepted())
    recorded = run_deploy(monkeypatch, client)
    assert client.asked == [TX_ID] * 3
    assert recorded and recorded[0][2] == ADDRESS


def test_an_answer_during_the_wait_is_not_retried(monkeypatch):
    client = Client(GenLayerError("Transaction %s not found" % (TX_ID,)))
    with pytest.raises(GenLayerError):
        run_deploy(monkeypatch, client)
    assert client.asked == [TX_ID]
