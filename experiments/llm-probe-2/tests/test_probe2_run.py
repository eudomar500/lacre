"""run.py's stop rules, send.py's resumable wait and chainread.py, offline.

The send.py outputs below are cut from ~/probe-d2-run.log, the run of 24
September 2026, one per way a call ended there, so the rules are tested on
what actually happened rather than on a guess at it.
"""

import importlib.util
from pathlib import Path

import pytest
from genlayer_py.chains import testnet_bradbury
from genlayer_py.exceptions import GenLayerError

PROBE = Path(__file__).resolve().parents[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


run = load(PROBE / "run.py", "probe2_run_rules")
send = load(PROBE / "send.py", "probe2_send_wait")
chainread = run.chainread

TX_1 = "0x1f64f1c5d1b718e1575150fbb2240ee804c1151e9cb295e10d7277b317097258"
TX_2 = "0xec0ef60c83bff258a457d3b01a8ec484c757bd73a2315357ce40dbbf58d59225"
L2_3 = "0xf16a26a31a962cf317708287d63938acacdbf8493a79eda335467aa31f8e5853"

# Call 1: the clean case, plus the decided line send.py prints now.
CLEAN = """L2 TX HASH   : 0x0e3bd8c04fd074607ef1dd586550783c9c4c6643087bcbb50a948f6ab1a7ab27
L2 status    : 1 (success)
CONSENSUS TX : %s
status       : ACCEPTED
returned     : shipped=1|eta=jueves|inj=0
decided      : ACCEPTED
%s
""" % (TX_1, TX_1)

# Call 2: on chain, then the connection broke while waiting.
BROKEN_WAIT = """L2 TX HASH   : 0xb3a0c7ba83a424553f876d083123a844ddcf924391bc9f4b9cc2be92be0d35b3
CONSENSUS TX : %s
waiting for ACCEPTED (up to 40 minutes) ...
genlayer_py.exceptions.GenLayerError: Request to https://rpc-bradbury.genlayer.com failed
""" % (TX_2,)

# Call 3: on chain, queued, and the old send() did not see the event.
NO_TX_ID = """L2 TX HASH   : %s
L2 status    : 1 (success)
error: L2 succeeded but no NewTransaction event was emitted
""" % (L2_3,)

# Call 23: refused at estimation.
QUEUE_FULL = """ESTIMATE FAILED: code=3 execution reverted
raw data     : '0xd48a82a30000000000000000000000004daf20ccdcdc968ef8c8eb0fca9082ccdb0c30ab0000000000000000000000000000000000000000000000000000000000000014'
"""


# Call 1 of the clean window, ~/probe-d2-clean.log, 24 September 2026, as
# send.py printed it: the hash is computed before the broadcast, and the
# node refused the broadcast. Nothing reached the chain.
REFUSED = """network      : bradbury (chain id 4221)
contract     : 0xfCE48Cc027c65C874d4dB6B38c7E8326A33284FC
method       : extract
label        : 01_shipped
body         : 333 bytes
sender       : 0xF27E3A6d7Bf4BfC0A837020FD74E73055aF17D53
to           : 0x0112Bf6e83497965A5fdD6Dad1E447a6E004271D (ConsensusMain)
calldata     : 1226 hex chars
ESTIMATED GAS: 0x10e62b (1107499)
per-tx cap   : 16777216, this uses 6.6%
gas limit    : 3322497 (3x estimate, 19.8% of cap)
nonce        : 354
L2 TX HASH   : 0x66b3b6353785e12d933cf421c27279266442d357359c0527c8f504bf4dfffe93
L2 explorer  : https://zksync-os-testnet-genlayer.explorer.zksync.dev/tx/0x66b3b6353785e12d933cf421c27279266442d357359c0527c8f504bf4dfffe93
broadcasting ...
error: broadcast refused: server returned an error response: error code -32005: transaction gas rate limit exceeded: node is at capacity, retry in ~1659ms, data: {"retryAfterMs":1659}
"""
REFUSED_L2 = "0x66b3b6353785e12d933cf421c27279266442d357359c0527c8f504bf4dfffe93"

# The same call once tools/chain.py retries the broadcast itself and gets
# through: the refusal is a retry line, not an error.
RETRIED_THEN_SENT = REFUSED.replace(
    "error: broadcast refused: ",
    "retry        : broadcast refused (code -32005), sending the same signed "
    "transaction again in 2.2 s, attempt 2 of 8\n# ") + (
    "waiting for the L2 receipt ...\nL2 status    : 1 (success)\n"
    "CONSENSUS TX : %s\ndecided      : ACCEPTED\n" % (TX_1,))

# Call 1 of the second clean window, ~/probe-d2-clean.log, 24 September 2026,
# as send.py printed it: on chain, then genlayer-py 0.16.3 died decoding a
# status 14 while the stored status was already ACCEPTED.
TX_D2 = "0x7a94e1945a9b7c6acf7e2fa08117b25deb9cefd2019c25aea0709df1f02c4581"
STATUS_14 = """network      : bradbury (chain id 4221)
contract     : 0xfCE48Cc027c65C874d4dB6B38c7E8326A33284FC
method       : extract
label        : 01_shipped
body         : 333 bytes
sender       : 0xF27E3A6d7Bf4BfC0A837020FD74E73055aF17D53
to           : 0x0112Bf6e83497965A5fdD6Dad1E447a6E004271D (ConsensusMain)
calldata     : 1226 hex chars
ESTIMATED GAS: 0x10e62b (1107499)
per-tx cap   : 16777216, this uses 6.6%
gas limit    : 3322497 (3x estimate, 19.8% of cap)
nonce        : 354
L2 TX HASH   : 0x4fd9b0f14a4242d8a5d76ab3e815feea2f95a84301fd99500ce5465e5db3efc8
L2 explorer  : https://zksync-os-testnet-genlayer.explorer.zksync.dev/tx/0x4fd9b0f14a4242d8a5d76ab3e815feea2f95a84301fd99500ce5465e5db3efc8
broadcasting ...
waiting for the L2 receipt ...
L2 status    : 1 (success)
L2 gasUsed   : 1058399 of 3322497
L2 cost      : 2245155021205300 wei
CONSENSUS TX : 0x7a94e1945a9b7c6acf7e2fa08117b25deb9cefd2019c25aea0709df1f02c4581
created by   : NewTransaction
explorer     : https://explorer-bradbury.genlayer.com/tx/0x7a94e1945a9b7c6acf7e2fa08117b25deb9cefd2019c25aea0709df1f02c4581

waiting for a decision (up to 40 minutes per attempt) ...
Traceback (most recent call last):
  File "/home/van/proyectos/lacre/experiments/llm-probe-2/send.py", line 234, in <module>
    main()
  File "/home/van/proyectos/lacre/experiments/llm-probe-2/send.py", line 212, in main
    receipt = wait_for_decision(client, tx_id)
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/van/proyectos/lacre/experiments/llm-probe-2/send.py", line 154, in wait_for_decision
    receipt = client.wait_for_transaction_receipt(
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/van/.local/lib/python3.12/site-packages/genlayer_py/client/genlayer_client.py", line 205, in wait_for_transaction_receipt
    return wait_for_transaction_receipt(
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/van/.local/lib/python3.12/site-packages/genlayer_py/transactions/actions.py", line 80, in wait_for_transaction_receipt
    transaction = self.get_transaction(transaction_hash=transaction_hash)
                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/van/.local/lib/python3.12/site-packages/genlayer_py/client/genlayer_client.py", line 219, in get_transaction
    return get_transaction(self=self, transaction_hash=transaction_hash)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/van/.local/lib/python3.12/site-packages/genlayer_py/transactions/actions.py", line 138, in get_transaction
    decoded_transaction = raw_transaction.decode()
                          ^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/van/.local/lib/python3.12/site-packages/genlayer_py/types/transactions.py", line 516, in decode
    "status_name": TRANSACTION_STATUS_NUMBER_TO_NAME[str(self.status)].value,
                   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^
KeyError: '14'
"""


# ---- run.py: a refused broadcast is not a send ----------------------------------

def test_the_logged_refusal_is_not_sent_and_retryable():
    assert run.classify(REFUSED, 1) == (run.NOT_SENT, None)


def test_a_refusal_the_tool_retried_past_is_a_clean_call():
    assert run.classify(RETRIED_THEN_SENT, 0) == (run.OK, TX_1)


def test_a_broadcast_that_went_through_without_a_tx_id_still_stops():
    verdict, tx_id = run.classify(NO_TX_ID, 1)
    assert verdict == "sent on chain without a consensus tx id"
    assert tx_id is None


def test_a_hash_with_neither_a_refusal_nor_a_receipt_is_not_called_refused():
    """A crash between the hash and the answer: sent or not is unknown."""
    output = REFUSED.split("broadcasting ...")[0] + "broadcasting ...\nTraceback ...\n"
    verdict, _ = run.classify(output, 1)
    assert verdict not in (run.OK, run.NOT_SENT)


class Log:
    def __init__(self):
        self.text = ""

    def write(self, text):
        self.text += text

    def flush(self):
        pass


def scripted_sends(monkeypatch, outputs):
    calls = []

    def fake(command, environment, log):
        calls.append(command)
        code, output = outputs.pop(0)
        log.write(output)
        return code, output

    monkeypatch.setattr(run, "run_send", fake)
    return calls


def test_a_refused_call_is_run_again_in_place_and_goes_on(monkeypatch):
    calls = scripted_sends(monkeypatch, [(1, REFUSED), (0, RETRIED_THEN_SENT)])
    looked_up = []
    monkeypatch.setattr(run, "on_chain", lambda client, l2: looked_up.append(l2) or False)
    pauses, log = [], Log()
    code, output, verdict, tx_id = run.send_call(["send.py"], {}, log, None,
                                                 sleep=pauses.append)
    assert (verdict, tx_id, code) == (run.OK, TX_1, 0)
    # The repeat is the same call, pinned to the refused attempt's nonce.
    assert len(calls) == 2 and calls[1] == calls[0] + ["--nonce", "354"]
    assert looked_up == [REFUSED_L2]
    assert pauses == [run.REFUSED_PAUSE_S]
    assert "not sent, and %s not on chain" % (REFUSED_L2,) in log.text
    assert "with nonce 354 (retry 1 of %d)" % (run.REFUSED_RETRIES,) in log.text


def test_a_call_refused_every_time_stops_after_the_limit(monkeypatch):
    calls = scripted_sends(monkeypatch, [(1, REFUSED)] * (run.REFUSED_RETRIES + 1))
    monkeypatch.setattr(run, "on_chain", lambda client, l2: False)
    pauses = []
    _, _, verdict, tx_id = run.send_call(["send.py"], {}, Log(), None, sleep=pauses.append)
    assert verdict.startswith(run.NOT_SENT) and verdict != run.NOT_SENT
    assert tx_id is None
    assert len(calls) == run.REFUSED_RETRIES + 1
    assert pauses == [run.REFUSED_PAUSE_S * n for n in range(1, run.REFUSED_RETRIES + 1)]


def test_a_refused_hash_found_on_chain_stops_without_a_retry(monkeypatch):
    calls = scripted_sends(monkeypatch, [(1, REFUSED)])
    monkeypatch.setattr(run, "on_chain", lambda client, l2: True)
    _, _, verdict, _ = run.send_call(["send.py"], {}, Log(), None, sleep=lambda _: None)
    assert verdict == "refused broadcast %s is on chain" % (REFUSED_L2,)
    assert len(calls) == 1


def test_every_other_stop_is_not_retried(monkeypatch):
    for output, code in ((QUEUE_FULL, 1), (NO_TX_ID, 1), (BROKEN_WAIT, 1)):
        calls = scripted_sends(monkeypatch, [(code, output)])
        _, _, verdict, _ = run.send_call(["send.py"], {}, Log(), None,
                                         sleep=lambda _: None)
        assert verdict not in (run.OK, run.NOT_SENT)
        assert len(calls) == 1


def test_the_lookup_of_a_refused_hash_is_read_only_and_says_absent():
    from web3.exceptions import TransactionNotFound

    class Eth:
        asked = []

        @classmethod
        def get_transaction(cls, l2):
            cls.asked.append(l2)
            raise TransactionNotFound("not found")

    client = type("Client", (), {"w3": type("W3", (), {"eth": Eth})()})()
    assert run.on_chain(client, REFUSED_L2) is False
    assert Eth.asked == [REFUSED_L2]


# ---- run.py: classify ---------------------------------------------------------

def test_a_clean_decided_call_goes_on():
    assert run.classify(CLEAN, 0) == (run.OK, TX_1)


def test_an_undetermined_call_is_decided_and_goes_on():
    assert run.classify(CLEAN.replace("decided      : ACCEPTED", "decided      : UNDETERMINED"),
                        0) == (run.OK, TX_1)


def test_a_broken_wait_stops_and_keeps_the_tx_id_to_wait_on():
    verdict, tx_id = run.classify(BROKEN_WAIT, 1)
    assert verdict == "send.py exited 1"
    assert tx_id == TX_2


def test_a_send_on_chain_without_a_tx_id_stops():
    assert run.classify(NO_TX_ID, 1) == ("sent on chain without a consensus tx id", None)


def test_a_pending_queue_full_stops():
    verdict, tx_id = run.classify(QUEUE_FULL, 1)
    assert verdict == "pending queue full (PendingQueueFull)"
    assert tx_id is None


def test_a_clean_exit_without_a_decided_line_stops():
    verdict, _ = run.classify(CLEAN.replace("decided      : ACCEPTED\n", ""), 0)
    assert verdict != run.OK


def test_a_clean_exit_on_an_undecided_status_stops():
    verdict, tx_id = run.classify(CLEAN.replace("decided      : ACCEPTED",
                                                "decided      : PENDING"), 0)
    assert "not decided" in verdict
    assert tx_id == TX_1


@pytest.mark.parametrize("status", chainread.DECIDED)
def test_every_decided_status_goes_on(status):
    assert run.classify(CLEAN.replace("decided      : ACCEPTED",
                                      "decided      : " + status), 0)[0] == run.OK


def test_the_status_14_call_from_its_output_alone_stops():
    assert run.classify(STATUS_14, 1) == ("send.py exited 1", TX_D2)


@pytest.mark.parametrize("stored", ["ACCEPTED", "FINALIZED"])
def test_the_status_14_call_stored_accepted_or_finalized_goes_on(stored):
    assert run.classify(STATUS_14, 1, stored) == (run.OK, TX_D2)


@pytest.mark.parametrize("stored", ["UNDETERMINED", "CANCELED", "LEADER_TIMEOUT",
                                    "VALIDATORS_TIMEOUT", "PENDING", "UNKNOWN_14", None])
def test_the_status_14_call_stored_anything_else_still_stops(stored):
    assert run.classify(STATUS_14, 1, stored) == ("send.py exited 1", TX_D2)


def test_an_accepted_status_without_a_tx_id_in_the_output_still_stops():
    output = STATUS_14.replace("CONSENSUS TX : ", "CONSENSUS TX ? ")
    assert run.classify(output, 1, "ACCEPTED") == (
        "sent on chain without a consensus tx id", None)
    assert run.classify(BROKEN_WAIT.replace("CONSENSUS TX : ", "CONSENSUS TX ? "),
                        1, "ACCEPTED") == ("send.py exited 1", None)


def test_the_stored_status_changes_no_other_stop():
    assert run.classify(QUEUE_FULL, 1, "ACCEPTED")[0] == "pending queue full (PendingQueueFull)"
    assert run.classify(NO_TX_ID, 1, "ACCEPTED")[0] == "sent on chain without a consensus tx id"
    assert run.classify(REFUSED, 1, "ACCEPTED") == (run.NOT_SENT, None)
    assert "not decided" in run.classify(
        CLEAN.replace("decided      : ACCEPTED", "decided      : PENDING"), 0, "ACCEPTED")[0]


def run_window(monkeypatch, tmp_path, outputs, stored):
    """run.main over a window of two calls; (log text, what was sent)."""
    calls = scripted_sends(monkeypatch, outputs)
    monkeypatch.setattr(chainread, "connect_readonly", lambda network: (None, None))
    monkeypatch.setattr(chainread, "stored_status", lambda client, tx_id: stored)
    waited = []

    def wait_decided(client, tx_id, log=None, **_):
        waited.append(tx_id)
        log.write("stored status: %s (decided after 0 s of polling)\n" % (stored,))
        return stored

    monkeypatch.setattr(chainread, "wait_decided", wait_decided)
    log_path = tmp_path / "probe.log"
    monkeypatch.setattr(run.sys, "argv", ["run.py", "0x" + "ab" * 20, str(log_path),
                                          "--batch", "2"])
    run.main()
    return log_path.read_text(encoding="utf-8"), calls, waited


def test_a_window_goes_on_after_the_status_14_call_once_it_is_accepted(
        monkeypatch, tmp_path):
    text, calls, waited = run_window(monkeypatch, tmp_path,
                                     [(1, STATUS_14), (0, CLEAN)], "ACCEPTED")
    assert waited == [TX_D2]
    assert len(calls) == 2
    first = text.split("=== end 1 ")[0]
    assert first.index("stored status: ACCEPTED") < first.index(
        "run.py       : decided despite send.py exit 1\n") < first.index(
        "run.py       : verdict ok\n")
    assert "STOPPED" not in text


def test_a_window_stops_after_the_status_14_call_if_it_is_undetermined(
        monkeypatch, tmp_path):
    text, calls, waited = run_window(monkeypatch, tmp_path,
                                     [(1, STATUS_14), (0, CLEAN)], "UNDETERMINED")
    assert waited == [TX_D2]
    assert len(calls) == 1
    assert "decided despite" not in text
    assert "run.py       : STOPPED at call 1: send.py exited 1\n" in text


# ---- run.py: windows and the log ------------------------------------------------

def test_the_default_window_is_the_first_ten():
    calls = run.window(run.plan(), 1, 10)
    assert [entry[0] for entry in calls] == list(range(1, 11))


def test_windows_of_ten_cover_the_plan_once():
    order = run.plan()
    seen = []
    for start in (1, 11, 21, 31):
        seen += [entry[0] for entry in run.window(order, start, 10)]
    assert seen == list(range(1, 41))


def test_a_window_can_resume_mid_plan_and_stops_at_the_end():
    calls = run.window(run.plan(), 35, 10)
    assert [entry[0] for entry in calls] == list(range(35, 41))
    assert {entry[2] for entry in calls} == {"extract_plain"}


def test_the_log_yields_each_tx_id_once():
    log = CLEAN + BROKEN_WAIT + NO_TX_ID + QUEUE_FULL + CLEAN
    assert run.logged_transactions(log) == [TX_1, TX_2]


def test_an_undecided_transaction_in_the_log_is_found(monkeypatch):
    stored = {TX_1: "FINALIZED", TX_2: "PROPOSING"}
    monkeypatch.setattr(chainread, "stored_status", lambda client, tx_id: stored[tx_id])
    known = set()
    assert run.undecided(None, [TX_1, TX_2], known) == (TX_2, "PROPOSING")
    assert known == {TX_1}
    stored[TX_2] = "ACCEPTED"
    assert run.undecided(None, [TX_1, TX_2], known) is None


def test_a_known_decided_transaction_is_not_read_again(monkeypatch):
    def unreachable(client, tx_id):
        raise AssertionError("read again")

    monkeypatch.setattr(chainread, "stored_status", unreachable)
    assert run.undecided(None, [TX_1], {TX_1}) is None


# ---- send.py: the wait for a decision -----------------------------------------------

class WaitClient:
    """A client whose wait answers from a script, one entry per call."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def wait_for_transaction_receipt(self, transaction_hash, **_):
        self.calls.append(transaction_hash)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def test_a_dropped_connection_resumes_on_the_same_tx_id():
    client = WaitClient(GenLayerError("Request to https://rpc failed: broken"),
                        OSError("reset"), {"status_name": "ACCEPTED"})
    pauses = []
    receipt = send.wait_for_decision(client, TX_2, sleep=pauses.append)
    assert receipt["status_name"] == "ACCEPTED"
    assert client.calls == [TX_2, TX_2, TX_2]
    assert pauses == [10.0, 20.0]


def test_the_wait_gives_up_after_the_attempts():
    client = WaitClient(*[OSError("reset")] * 3)
    with pytest.raises(OSError):
        send.wait_for_decision(client, TX_2, attempts=3, sleep=lambda _: None)
    assert len(client.calls) == 3


def test_an_error_that_is_an_answer_is_not_retried():
    client = WaitClient(GenLayerError("Transaction 0x.. not found"))
    with pytest.raises(GenLayerError):
        send.wait_for_decision(client, TX_2, sleep=lambda _: None)
    assert len(client.calls) == 1


def test_a_canceled_view_on_a_pending_transaction_is_not_believed(monkeypatch):
    stored = iter(["PENDING", "PENDING", "ACCEPTED", "ACCEPTED"])
    monkeypatch.setattr(send.chainread, "stored_status", lambda client, tx_id: next(stored))
    client = WaitClient({"status_name": "CANCELED"}, {"status_name": "ACCEPTED"})
    receipt = send.wait_for_decision(client, TX_2, sleep=lambda _: None)
    assert receipt["status_name"] == "ACCEPTED"


def test_a_canceled_view_that_is_stored_canceled_is_final(monkeypatch):
    monkeypatch.setattr(send.chainread, "stored_status", lambda client, tx_id: "CANCELED")
    client = WaitClient({"status_name": "CANCELED"})
    assert send.wait_for_decision(client, TX_2)["status_name"] == "CANCELED"


def sdk_status_14():
    """The KeyError genlayer-py 0.16.3 raised, from its own table."""
    from genlayer_py.types.transactions import TRANSACTION_STATUS_NUMBER_TO_NAME
    try:
        TRANSACTION_STATUS_NUMBER_TO_NAME[str(14)]
    except KeyError as error:
        return error
    raise AssertionError("genlayer-py now names status 14")


class Status14Client(WaitClient):
    """The SDK's wait dies on status 14; ConsensusData still answers."""

    def __init__(self, blob):
        super().__init__()
        self.blob = blob
        self.read = []
        client = self

        class Call:
            def __init__(self, tx_id):
                self.tx_id = tx_id

            def call(self):
                client.read.append(self.tx_id)
                data = [None] * (send.EQ_BLOCKS_OUTPUTS + 1)
                data[send.EQ_BLOCKS_OUTPUTS] = client.blob
                return tuple(data)

        class Functions:
            @staticmethod
            def getTransactionData(tx_id, timestamp):
                return Call(tx_id)

        self.w3 = type("W3", (), {"eth": type("Eth", (), {"contract": staticmethod(
            lambda address, abi: type("C", (), {"functions": Functions})())})})()
        self.chain = type("Chain", (), {"consensus_data_contract": {
            "address": "0x" + "00" * 20, "abi": []}})()

    def wait_for_transaction_receipt(self, transaction_hash, **_):
        self.calls.append(transaction_hash)
        raise sdk_status_14()


def reading_blob(reading):
    import rlp
    from genlayer_py.abi import calldata
    return rlp.encode([bytes([send.RETURN_CODE]) + calldata.encode(reading), send.PADDING])


READING = "shipped=1|eta=jueves|inj=0"


def test_the_unknown_number_is_read_from_the_sdk_error():
    assert send.unknown_number(sdk_status_14()) == ("TRANSACTION_STATUS_NUMBER_TO_NAME", "14")
    assert send.unknown_number(KeyError("14")) == ("a lookup table", "14")
    assert send.unknown_number(KeyError("body")) is None
    assert send.unknown_number(OSError("reset")) is None


def test_status_14_falls_back_on_the_stored_status(monkeypatch, capsys):
    stored = iter(["PROPOSING", "ACCEPTED"])
    monkeypatch.setattr(send.chainread, "stored_status", lambda client, tx_id: next(stored))
    client = Status14Client(reading_blob(READING))
    pauses = []
    receipt = send.wait_for_decision(client, TX_D2, sleep=pauses.append)
    assert receipt == {"status_name": "ACCEPTED"}
    assert client.calls == [TX_D2]
    assert pauses == [20]
    out = capsys.readouterr().out
    assert "unknown number 14 in genlayer-py's TRANSACTION_STATUS_NUMBER_TO_NAME" in out
    assert "stored status: ACCEPTED (decided after 20 s of polling)" in out
    assert send.eq_block_values(send.eq_blocks_outputs(client, TX_D2)) == [READING]


def test_status_14_on_a_transaction_never_decided_still_fails(monkeypatch):
    monkeypatch.setattr(send.chainread, "stored_status", lambda client, tx_id: "PROPOSING")
    with pytest.raises(RuntimeError, match="still PROPOSING"):
        send.wait_for_decision(Status14Client(b""), TX_D2, sleep=lambda _: None)


def test_send_main_survives_status_14_and_prints_the_reading(monkeypatch, capsys):
    client = Status14Client(reading_blob(READING))
    account = type("Account", (), {"address": "0x" + "cd" * 20})()
    net = {"chain_id": 4221, "explorer": "https://explorer.example"}
    monkeypatch.setattr(send.socket, "setdefaulttimeout", lambda seconds: None)
    monkeypatch.setattr(send.chain, "connect", lambda network: (account, client, net))
    monkeypatch.setattr(send.chain, "write_calldata", lambda *args: b"calldata")
    monkeypatch.setattr(send.chain, "estimate", lambda *args, **kwargs: 1)
    monkeypatch.setattr(send.chain, "send", lambda *args, **kwargs: (TX_D2, 1058399))
    monkeypatch.setattr(send.chainread, "stored_status", lambda client, tx_id: "ACCEPTED")
    monkeypatch.setattr(send.sys, "argv", ["send.py", "0x" + "ab" * 20,
                                           "bodies/01_shipped.txt"])
    send.main()
    captured = capsys.readouterr()
    assert captured.out == "%s\nhttps://explorer.example/tx/%s\n" % (TX_D2, TX_D2)
    assert "unknown number 14" in captured.err
    assert "status       : ACCEPTED" in captured.err
    assert "returned     : %s" % (READING,) in captured.err
    assert "decided      : ACCEPTED" in captured.err
    # chain.send, stubbed here, prints the CONSENSUS TX line in a real run.
    assert run.classify("CONSENSUS TX : %s\n" % (TX_D2,) + captured.err, 0) == (run.OK, TX_D2)


# ---- chainread.py ----------------------------------------------------------------

@pytest.mark.parametrize("error,expected", [
    (OSError("reset"), True),
    (ConnectionResetError("reset"), True),
    (TimeoutError("slow"), True),
    (GenLayerError("Request to https://rpc failed: Connection broken"), True),
    (GenLayerError("eth_chainId returned invalid JSON: Expecting value"), True),
    (GenLayerError("eth_call failed (code=3): execution reverted"), False),
    (ValueError("bad"), False),
])
def test_what_counts_as_transient(error, expected):
    assert chainread.transient(error) is expected


def test_the_stored_status_is_read_by_field_name():
    abi = testnet_bradbury.consensus_data_contract["abi"]
    output = chainread.output_names(abi, "getTransactionAllData").index("transaction")
    fields = chainread.fields(abi, "getTransactionAllData", output)
    transaction = [None] * len(fields)
    transaction[fields.index("status")] = 8
    transaction[fields.index("previousStatus")] = 1

    class Call:
        def call(self):
            data = [None, None]
            data[output] = tuple(transaction)
            return tuple(data)

    class Functions:
        @staticmethod
        def getTransactionAllData(tx_id):
            return Call()

    class Client:
        w3 = type("W3", (), {"eth": type("Eth", (), {"contract": staticmethod(
            lambda address, abi: type("C", (), {"functions": Functions})())})})()
        chain = type("Chain", (), {"consensus_data_contract": {
            "address": "0x" + "00" * 20, "abi": abi}})()

    assert chainread.stored_status(Client(), TX_1) == "CANCELED"


def test_waiting_polls_the_stored_status_until_decided(monkeypatch, capsys):
    seen = iter(["PENDING", "PROPOSING", "ACCEPTED"])
    monkeypatch.setattr(chainread, "stored_status", lambda client, tx_id: next(seen))
    assert chainread.wait_decided(None, TX_1, interval=5, sleep=lambda _: None) == "ACCEPTED"
    assert "decided" in capsys.readouterr().err


def test_waiting_gives_up_after_its_budget(monkeypatch):
    monkeypatch.setattr(chainread, "stored_status", lambda client, tx_id: "PROPOSING")
    assert chainread.wait_decided(None, TX_1, interval=10, budget=30,
                                  sleep=lambda _: None) == "PROPOSING"


def test_the_queue_full_selector_is_the_one_in_the_log():
    assert QUEUE_FULL.count(chainread.PENDING_QUEUE_FULL) == 1


# ---- the third window: a gateway 522 during eth_sendRawTransaction ---------------
#
# Call 2 of the window of 20:02, ~/probe-d2-clean.log, 24 September 2026, as
# send.py printed it with the tools/chain.py of that day. The L2 hash is
# absent from the chain and the account's next nonce is 355.

L2_355 = "0xf6bd805c287f718021fadfc45fca4108e6806f7329178a7b91446e7da593dd71"
WINDOW3_522 = """network      : bradbury (chain id 4221)
contract     : 0xfCE48Cc027c65C874d4dB6B38c7E8326A33284FC
method       : extract
label        : 02_pending_trap
body         : 418 bytes
sender       : 0xF27E3A6d7Bf4BfC0A837020FD74E73055aF17D53
to           : 0x0112Bf6e83497965A5fdD6Dad1E447a6E004271D (ConsensusMain)
calldata     : 1418 hex chars
ESTIMATED GAS: 0x11fea1 (1179297)
per-tx cap   : 16777216, this uses 7.0%
gas limit    : 3537891 (3x estimate, 21.1% of cap)
nonce        : 355
L2 TX HASH   : 0xf6bd805c287f718021fadfc45fca4108e6806f7329178a7b91446e7da593dd71
L2 explorer  : https://zksync-os-testnet-genlayer.explorer.zksync.dev/tx/0xf6bd805c287f718021fadfc45fca4108e6806f7329178a7b91446e7da593dd71
broadcasting ...
retry        : broadcast refused (code -32005), sending the same signed transaction again in 0.7 s, attempt 2 of 8
Traceback (most recent call last):
  File "/home/van/proyectos/lacre/experiments/llm-probe-2/send.py", line 277, in <module>
    main()
  File "/home/van/proyectos/lacre/experiments/llm-probe-2/send.py", line 251, in main
    tx_id, l2_gas = chain.send(net, client, account, encoded, gas)
                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/van/proyectos/lacre/tools/chain.py", line 422, in send
    sent = broadcast(net, raw)
           ^^^^^^^^^^^^^^^^^^^
  File "/home/van/proyectos/lacre/tools/chain.py", line 194, in broadcast
    out = rpc(net, "eth_sendRawTransaction", [raw])
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/van/proyectos/lacre/tools/chain.py", line 147, in rpc
    with urllib.request.urlopen(request, timeout=180) as response:
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/urllib/request.py", line 215, in urlopen
    return opener.open(url, data, timeout)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/urllib/request.py", line 521, in open
    response = meth(req, response)
               ^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/urllib/request.py", line 630, in http_response
    response = self.parent.error(
               ^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/urllib/request.py", line 559, in error
    return self._call_chain(*args)
           ^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/urllib/request.py", line 492, in _call_chain
    result = func(*args)
             ^^^^^^^^^^^
  File "/usr/lib/python3.12/urllib/request.py", line 639, in http_error_default
    raise HTTPError(req.full_url, code, msg, hdrs, fp)
urllib.error.HTTPError: HTTP Error 522: <none>
"""

# What the same call prints with today's tools/chain.py, by outcome: the log
# above up to the -32005 retry line, then what broadcast() does after no
# answer. The lines are the ones tools/chain.py prints; the numbers are 522's.
BEFORE_522 = WINDOW3_522.split("Traceback")[0]
NO_ANSWER = ("retry        : broadcast got no answer (eth_sendRawTransaction: HTTP 522 "
             "from the gateway), sending the same signed transaction again in 4.0 s, "
             "attempt 3 of 8\n")
NOT_SENT_355 = BEFORE_522 + NO_ANSWER + (
    "error: not sent: no answer (eth_sendRawTransaction: HTTP 522 from the gateway) "
    "after 8 sends; %s is not on chain\n" % (L2_355,))
UNKNOWN_355 = BEFORE_522 + NO_ANSWER + (
    "error: broadcast outcome unknown: no answer (eth_sendRawTransaction: HTTP 522 from "
    "the gateway) after 8 sends, and %s could not be looked up; it may have been sent\n"
    % (L2_355,))
NONCE_HELD_355 = BEFORE_522 + NO_ANSWER + (
    "error: broadcast refused: nonce too low; %s is not on chain, so another transaction "
    "holds this nonce\n" % (L2_355,))
BROKE_355 = BEFORE_522 + NO_ANSWER + (
    "error: broadcast refused: insufficient funds for gas * price + value\n")
REVERTED_355 = BEFORE_522.replace("retry        : broadcast refused (code -32005), sending "
                                  "the same signed transaction again in 0.7 s, attempt 2 "
                                  "of 8\n", "") + (
    "waiting for the L2 receipt ...\nL2 status    : 0 (REVERTED)\n"
    "L2 gasUsed   : 1058399 of 3537891\nL2 cost      : 2245155021205300 wei\n"
    "error: the L2 transaction reverted; nothing reached consensus\n")
NONCE_MOVED_355 = BEFORE_522.split("gas limit")[0] + (
    "error: nonce 355 is already used (the account is at 356): an earlier send with it "
    "reached the chain; nothing was signed\n")
# The pinned repeat of the call, signed again at a new gas price: a new hash.
L2_OTHER = "0x" + "5e" * 32
NOT_SENT_OTHER = NOT_SENT_355.replace(L2_355, L2_OTHER)


def test_the_logged_522_output_still_stops_on_its_own():
    assert run.classify(WINDOW3_522, 1) == ("send.py exited 1", None)


def test_today_not_sent_is_retryable():
    assert run.classify(NOT_SENT_355, 1) == (run.NOT_SENT, None)


@pytest.mark.parametrize("output,verdict", [
    (UNKNOWN_355, "broadcast outcome unknown, the transaction may be on chain"),
    (NONCE_HELD_355, "broadcast refused: nonce too low; %s is not on chain, so another "
                     "transaction holds this nonce" % (L2_355,)),
    (BROKE_355, "broadcast refused: insufficient funds for gas * price + value"),
    (REVERTED_355, "the L2 transaction reverted; nothing reached consensus"),
    (NONCE_MOVED_355, "nonce 355 is already used (the account is at 356): an earlier "
                      "send with it reached the chain; nothing was signed"),
])
def test_every_other_broadcast_outcome_stops_with_its_own_verdict(output, verdict):
    assert run.classify(output, 1) == (verdict, None)


def test_a_not_sent_call_is_repeated_with_its_nonce(monkeypatch):
    calls = scripted_sends(monkeypatch, [(1, NOT_SENT_355), (0, CLEAN)])
    looked = []
    monkeypatch.setattr(run, "on_chain", lambda client, l2: looked.append(l2) or False)
    _, _, verdict, tx_id = run.send_call(["send.py", "ADDR", "02.txt"], {}, Log(), None,
                                         sleep=lambda _: None)
    assert (verdict, tx_id) == (run.OK, TX_1)
    assert calls == [["send.py", "ADDR", "02.txt"],
                     ["send.py", "ADDR", "02.txt", "--nonce", "355"]]
    assert looked == [L2_355]


def test_every_earlier_attempt_is_looked_up_before_a_retry(monkeypatch):
    scripted_sends(monkeypatch, [(1, NOT_SENT_355), (1, NOT_SENT_OTHER), (0, CLEAN)])
    looked = []
    # The first attempt's hash turns up after the second attempt.
    landed = iter([False, True])
    monkeypatch.setattr(run, "on_chain",
                        lambda client, l2: looked.append(l2) or next(landed))
    _, _, verdict, _ = run.send_call(["send.py"], {}, Log(), None, sleep=lambda _: None)
    assert verdict == "refused broadcast %s is on chain" % (L2_355,)
    assert looked == [L2_355, L2_355]


def test_a_lookup_that_fails_stops_instead_of_retrying(monkeypatch):
    calls = scripted_sends(monkeypatch, [(1, NOT_SENT_355)])

    def unreadable(client, l2):
        raise OSError("gateway 522")

    monkeypatch.setattr(run, "on_chain", unreadable)
    _, _, verdict, _ = run.send_call(["send.py"], {}, Log(), None, sleep=lambda _: None)
    assert verdict == "could not check whether %s is on chain (OSError)" % (L2_355,)
    assert len(calls) == 1


# ---- run.py: the pre-call checks -------------------------------------------------

# The day's log in the order it was written: a refusal, the status 14 call,
# the 522 call.
DAY = ("=== run 1 round 1 method extract body 01_shipped.txt start t\n" + REFUSED
       + "=== end 1 exit 1 at t\n=== run 1 round 1 method extract body 01_shipped.txt "
       "start t\n" + STATUS_14 + "=== end 1 exit 1 at t\n=== run 2 round 1 method "
       "extract body 02_pending_trap.txt start t\n" + WINDOW3_522 + "=== end 2 exit 1 at t\n")


def test_the_days_unaccounted_l2_hashes_are_the_refused_and_the_522():
    assert run.unaccounted_l2(DAY) == [REFUSED_L2, L2_355]
    assert run.logged_transactions(DAY) == [TX_D2]


def test_absent_unaccounted_hashes_do_not_stop_and_are_read_again(monkeypatch):
    asked = []
    monkeypatch.setattr(run, "l2_state", lambda client, l2: asked.append(l2) or "absent")
    settled = set()
    assert run.stray(None, [REFUSED_L2, L2_355], settled) is None
    assert run.stray(None, [REFUSED_L2, L2_355], settled) is None
    assert asked == [REFUSED_L2, L2_355] * 2 and settled == set()


@pytest.mark.parametrize("state", ["pending", "succeeded"])
def test_an_unaccounted_hash_that_reached_the_chain_stops(monkeypatch, state):
    monkeypatch.setattr(chainread, "stored_status", lambda client, tx_id: "FINALIZED")
    monkeypatch.setattr(run, "l2_state",
                        lambda client, l2: state if l2 == L2_355 else "absent")
    assert run.pre_call_check(None, DAY, set(), set()) == (
        "L2 transaction %s is %s, and the log has no consensus tx id for it" % (L2_355, state))


def test_a_reverted_unaccounted_hash_is_settled(monkeypatch):
    monkeypatch.setattr(run, "l2_state", lambda client, l2: "reverted")
    settled = set()
    assert run.stray(None, [L2_355], settled) is None
    assert settled == {L2_355}


def test_accepted_is_read_again_before_every_call_and_finalized_is_not(monkeypatch):
    seen = []
    stored = {TX_1: "FINALIZED", TX_D2: "ACCEPTED"}
    monkeypatch.setattr(chainread, "stored_status",
                        lambda client, tx_id: seen.append(tx_id) or stored[tx_id])
    known = set()
    assert run.undecided(None, [TX_1, TX_D2], known) is None
    assert run.undecided(None, [TX_1, TX_D2], known) is None
    assert seen == [TX_1, TX_D2, TX_D2]
    assert known == {TX_1}


def test_an_appeal_after_acceptance_stops_the_next_call(monkeypatch):
    stored = iter(["ACCEPTED", "APPEAL_COMMITTING"])
    monkeypatch.setattr(chainread, "stored_status", lambda client, tx_id: next(stored))
    known = set()
    assert run.undecided(None, [TX_D2], known) is None
    assert run.undecided(None, [TX_D2], known) == (TX_D2, "APPEAL_COMMITTING")


def test_a_chain_that_cannot_be_read_before_a_call_stops_cleanly(monkeypatch):
    def unreadable(client, tx_id):
        raise OSError("getTransactionAllData: HTTP 522 from the gateway")

    monkeypatch.setattr(chainread, "stored_status", unreadable)
    assert run.pre_call_check(None, DAY, set(), set()) == (
        "the pre-call check could not read the chain (OSError: getTransactionAllData: "
        "HTTP 522 from the gateway)")


def test_the_logged_522_call_stops_and_says_to_resume_at_itself(monkeypatch, tmp_path):
    text, calls, waited = run_window(monkeypatch, tmp_path, [(1, WINDOW3_522)], "ACCEPTED")
    assert len(calls) == 1 and waited == []
    assert "run.py       : STOPPED at call 1: send.py exited 1\n" in text
    assert "resume with  : --start 1, once the cause is understood\n" in text


def test_a_window_repeats_a_not_sent_call_with_its_nonce_and_goes_on(monkeypatch, tmp_path):
    monkeypatch.setattr(run, "on_chain", lambda client, l2: False)
    monkeypatch.setattr(run, "l2_state", lambda client, l2: "absent")
    monkeypatch.setattr(run.time, "sleep", lambda _: None)
    text, calls, _ = run_window(monkeypatch, tmp_path,
                                [(1, NOT_SENT_355), (0, CLEAN), (0, CLEAN)], "ACCEPTED")
    assert len(calls) == 3
    assert calls[1][-2:] == ["--nonce", "355"] and "--nonce" not in calls[2]
    assert "STOPPED" not in text


# ---- send.py: --nonce, a stalled wait, a dropped read of the reading ---------------

@pytest.mark.parametrize("arguments,nonce,rest", [
    (["0xab", "b.txt"], None, ["0xab", "b.txt"]),
    (["0xab", "b.txt", "--nonce", "355"], 355, ["0xab", "b.txt"]),
    (["0xab", "--nonce", "355", "b.txt", "--plain"], 355, ["0xab", "b.txt", "--plain"]),
])
def test_the_nonce_is_taken_out_of_the_arguments(arguments, nonce, rest):
    assert send.take_nonce(arguments) == (nonce, rest)


@pytest.mark.parametrize("arguments", [["0xab", "b.txt", "--nonce"],
                                       ["0xab", "b.txt", "--nonce", "x"]])
def test_a_nonce_that_is_not_a_number_is_refused(arguments):
    with pytest.raises(SystemExit):
        send.take_nonce(arguments)


STALLED = GenLayerError(
    "Transaction %s did not reach desired status 'ACCEPTED' after 240 attempts (polling "
    "every 10000ms for a total of 2400.0s). Last observed status: 'PROPOSING'." % (TX_D2,))


def test_a_wait_the_sdk_gives_up_on_falls_back_on_the_stored_status(monkeypatch, capsys):
    stored = iter(["PROPOSING", "ACCEPTED"])
    monkeypatch.setattr(send.chainread, "stored_status", lambda client, tx_id: next(stored))
    client = WaitClient(STALLED)
    assert send.wait_for_decision(client, TX_D2, sleep=lambda _: None) == {
        "status_name": "ACCEPTED"}
    assert client.calls == [TX_D2]
    assert "genlayer-py stopped polling 0x7a94e194 undecided" in capsys.readouterr().out


def test_a_stall_past_the_stored_budget_too_still_fails(monkeypatch):
    monkeypatch.setattr(send.chainread, "stored_status", lambda client, tx_id: "PROPOSING")
    with pytest.raises(RuntimeError, match="still PROPOSING"):
        send.wait_for_decision(WaitClient(STALLED), TX_D2, sleep=lambda _: None)


class DroppingClient(Status14Client):
    """The reading's read drops once, then answers."""

    def __init__(self, blob):
        super().__init__(blob)
        contract = self.w3.eth.contract(address=None, abi=None)
        dropped = []

        class Call:
            def __init__(self, inner):
                self.inner = inner

            def call(self):
                if not dropped:
                    dropped.append(True)
                    raise GenLayerError("Request to https://rpc-bradbury.genlayer.com "
                                        "failed: Connection broken")
                return self.inner.call()

        class Functions:
            @staticmethod
            def getTransactionData(tx_id, timestamp):
                return Call(contract.functions.getTransactionData(tx_id, timestamp))

        self.w3 = type("W3", (), {"eth": type("Eth", (), {"contract": staticmethod(
            lambda address, abi: type("C", (), {"functions": Functions})())})})()


def test_the_reading_is_read_again_after_a_dropped_connection(capsys):
    client = DroppingClient(reading_blob(READING))
    pauses = []
    blob = send.eq_blocks_outputs(client, TX_D2, sleep=pauses.append)
    assert send.eq_block_values(blob) == [READING]
    assert len(pauses) == 1
    assert "retry        : getTransactionData 0x7a94e194 failed" in capsys.readouterr().out


# ---- chainread.py: which numbering Bradbury uses ----------------------------------------
#
# Read-only on 24 September 2026 from getTransactionAllData: probe D's
# 0x94fe739d... (a leader timeout, appealed) and incident call 16,
# 0x0cf0337e... (four leader rotations, no vote), both status 7 with
# previousStatus 13; incident call 17 and clean call 1, status 7 with
# previousStatus 0. Stored 5, 6 and 8 were seen during the runs, the view's
# 14 on clean call 1, and results 0, 1, 2 and 5.

OBSERVED_STATUS = {5: "ACCEPTED", 6: "UNDETERMINED", 7: "FINALIZED", 8: "CANCELED"}
OBSERVED_RESULT = {0: "IDLE", 1: "AGREE", 2: "DISAGREE", 5: "NO_MAJORITY"}
# genlayer-js 2.0.0-rc.1, transactionsStatusNumberToName.
RC_STATUS = {11: "VALIDATORS_TIMEOUT", 12: "LEADER_TIMEOUT", 13: "LEADER_REVEALING"}


@pytest.mark.parametrize("number,status", sorted(OBSERVED_STATUS.items()))
def test_the_observed_stored_statuses_are_named_as_seen(number, status):
    assert chainread.name(chainread.STATUS, number) == status


@pytest.mark.parametrize("number,result", sorted(OBSERVED_RESULT.items()))
def test_the_observed_results_are_named_as_seen(number, result):
    assert chainread.name(chainread.RESULT, number) == result


def test_an_appealed_leader_timeout_is_13_so_the_rc_numbering_is_not_bradburys():
    assert chainread.name(chainread.STATUS, 13) == "LEADER_TIMEOUT"
    assert chainread.name(chainread.STATUS, 13) != RC_STATUS[13]
    # An appeal is of a decided state, never of a phase in progress.
    assert chainread.name(chainread.STATUS, 13) in chainread.DECIDED
    assert RC_STATUS[13] not in chainread.DECIDED


def test_11_and_12_are_marked_unconfirmed_and_nothing_else_is():
    assert chainread.UNCONFIRMED == (chainread.STATUS[11], chainread.STATUS[12])
    assert chainread.shown(chainread.STATUS[12]) == "VALIDATORS_TIMEOUT (number unconfirmed)"
    for number in list(range(11)) + [13]:
        assert chainread.shown(chainread.STATUS[number]) == chainread.STATUS[number]


def test_the_views_14_stays_unknown():
    assert chainread.name(chainread.STATUS, 14) == "UNKNOWN_14"
    assert chainread.shown("UNKNOWN_14") == "UNKNOWN_14"
