"""Read-only consensus state: stored status, results, waits, and a keyless client.

Shared by call.py, read.py and attest.py. The rules below were learned on
probe D2's run of 24 September 2026, and experiments/llm-probe-2/chainread.py
keeps its own frozen copy of them; nothing here is imported from there.

- The timestamped views (getTransactionData, getTransactionStatus) report a
  queued transaction as CANCELED from 1800 s after it was created while it
  is still stored as PENDING and can still be activated. Only the stored
  status, from getTransactionAllData, is believed.
- genlayer-py 0.16.3 names status and result numbers through tables that do
  not hold every number Bradbury returns: the timestamped view answered with
  a status 14 sixteen times in one run, and the SDK dies on it with a
  KeyError. Numbers are named here with a fallback of UNKNOWN_<n>.
- genlayer-py's provider calls requests with no timeout, so a stalled
  connection would block a wait forever; connect_readonly sets a socket
  timeout, and every read is retried after a transient failure.
- A decided or finalized transaction may not have executed: probe D2 call 36
  finalized with result TIMEOUT and an execution result of
  FINISHED_WITH_RETURN, and wrote nothing. Only a result of AGREE (or
  MAJORITY_AGREE) together with FINISHED_WITH_RETURN means the method ran.
"""

import re
import socket
import time
import traceback

import rlp
from genlayer_py.abi import calldata
from genlayer_py.types import TransactionStatus

import chain
from chain import POLL_INTERVAL_MS, POLL_RETRIES

# A stalled connection must fail and be retried rather than block forever.
# chain.rpc passes its own timeout, so this only reaches the SDK's requests.
SOCKET_TIMEOUT = 120

# genlayer_py.types.transactions for Bradbury's numbering, copied so a new
# SDK does not rename numbers under these tools. 13 is LEADER_TIMEOUT on
# Bradbury (consensus v0.5); see experiments/llm-probe-2/chainread.py.
STATUS = ("UNINITIALIZED", "PENDING", "PROPOSING", "COMMITTING", "REVEALING",
          "ACCEPTED", "UNDETERMINED", "FINALIZED", "CANCELED",
          "APPEAL_REVEALING", "APPEAL_COMMITTING", "READY_TO_FINALIZE",
          "VALIDATORS_TIMEOUT", "LEADER_TIMEOUT")
RESULT = ("IDLE", "AGREE", "DISAGREE", "TIMEOUT", "DETERMINISTIC_VIOLATION",
          "NO_MAJORITY", "MAJORITY_AGREE", "MAJORITY_DISAGREE")
EXECUTION = ("NOT_VOTED", "FINISHED_WITH_RETURN", "FINISHED_WITH_ERROR")

# Stored states in which a transaction will not run again unless appealed.
DECIDED = ("ACCEPTED", "UNDETERMINED", "FINALIZED", "CANCELED", "LEADER_TIMEOUT",
           "VALIDATORS_TIMEOUT")
# Stored states no later event changes.
FINAL = ("FINALIZED", "CANCELED")
APPEAL = ("APPEAL_REVEALING", "APPEAL_COMMITTING")
AGREED = ("AGREE", "MAJORITY_AGREE")

# Every eqBlocksOutputs list ends with this literal; it is not an output.
PADDING = b"padded"
# The first byte of an output is the genvm result code; 0 is a return.
RETURN_CODE = 0


def name(table, number):
    number = int(number)
    return table[number] if 0 <= number < len(table) else "UNKNOWN_%d" % (number,)


def executed(state):
    """Whether a stored state says the method ran and its writes stand."""
    return (state["status"] in ("ACCEPTED", "FINALIZED")
            and state["result"] in AGREED
            and state["execution"] == "FINISHED_WITH_RETURN")


def connect_readonly(network="bradbury"):
    """A client with no account on one network of chain.NETWORKS.

    It can call views and read consensus data and nothing else; PROBE_PK is
    never read.
    """
    from genlayer_py import create_client

    socket.setdefaulttimeout(SOCKET_TIMEOUT)
    net = chain.NETWORKS[network]
    if net["mode"] != "l2":
        chain.die("%s is not an l2 network; these tools read ConsensusData there"
                  % (network,))
    net["chain"].rpc_urls["default"]["http"] = [net["rpc_url"]]
    client = chain.resilient(lambda: create_client(chain=net["chain"]), "connect")
    if int(client.chain.id) != net["chain_id"]:
        chain.die("%s: the SDK chain id is %s, the table says %d"
                  % (network, client.chain.id, net["chain_id"]))
    return client, net


def _function(abi, function):
    for item in abi:
        if item.get("type") == "function" and item.get("name") == function:
            return item
    raise KeyError(function)


def fields(abi, function, output=0):
    """The component names of one tuple output of a function, in order.

    Positions are always taken from the ABI by name: a hard-coded position
    was wrong once already.
    """
    return [component["name"]
            for component in _function(abi, function)["outputs"][output]["components"]]


def consensus_data(client):
    return client.w3.eth.contract(
        address=client.chain.consensus_data_contract["address"],
        abi=client.chain.consensus_data_contract["abi"],
    )


def decode_stored(abi, data):
    """The fields of a getTransactionAllData answer these tools use, by name."""
    transaction = dict(zip(fields(abi, "getTransactionAllData", 0), data[0]))
    return {
        "status": name(STATUS, transaction["status"]),
        "previous": name(STATUS, transaction["previousStatus"]),
        "result": name(RESULT, transaction["result"]),
        "execution": name(EXECUTION, transaction["txExecutionResult"]),
        "sender": str(transaction["sender"]),
        "recipient": str(transaction["recipient"]),
        "value": int(transaction["value"]),
        "eq_outputs": bytes(transaction["eqBlocksOutputs"]),
        "rounds": len(data[1]),
    }


def stored(client, tx_id, sleep=None):
    """The stored state of one consensus transaction, retried when transient.

    getTransactionAllData takes no timestamp, so unlike the other views it
    never reports a queued transaction as CANCELED before it is.
    """
    data = chain.resilient(
        lambda: consensus_data(client).functions.getTransactionAllData(tx_id).call(),
        "getTransactionAllData %s" % (tx_id[:10],), sleep=sleep)
    return decode_stored(client.chain.consensus_data_contract["abi"], data)


def decode_messages(abi, raw):
    """The messages of a getTransactionData answer, by the ABI's field names."""
    for component in _function(abi, "getTransactionData")["outputs"][0]["components"]:
        if component["name"] == "messages":
            keys = [part["name"] for part in component["components"]]
    found = []
    for item in raw:
        message = dict(zip(keys, item))
        found.append({"type": int(message["messageType"]),
                      "recipient": str(message["recipient"]),
                      "value": int(message["value"]),
                      "on_acceptance": bool(message["onAcceptance"])})
    return found


def messages(client, tx_id, sleep=None):
    """The messages a transaction emitted, from the timestamped view.

    Only the messages are taken from that view; its status is never used.
    """
    abi = client.chain.consensus_data_contract["abi"]
    index = fields(abi, "getTransactionData").index("messages")
    data = chain.resilient(
        lambda: consensus_data(client).functions.getTransactionData(
            tx_id, int(time.time())).call(),
        "getTransactionData %s" % (tx_id[:10],), sleep=sleep)
    return decode_messages(abi, data[index])


def eq_block_values(blob):
    """The values the non-deterministic blocks returned, decoded, in order.

    Never raises: a reading that cannot be recovered is no reason to lose the
    transaction it belongs to.
    """
    if not blob:
        return []
    try:
        items = rlp.decode(bytes(blob), strict=False)
    except Exception:
        return []
    values = []
    for item in items:
        if item == PADDING or len(item) < 2 or item[0] != RETURN_CODE:
            continue
        try:
            values.append(str(calldata.decode(item[1:])))
        except Exception:
            continue
    return values


# What genlayer-py raises when its polling budget runs out on a transaction
# that is still undecided.
_NOT_REACHED = "did not reach desired status"


def stalled(error):
    """Whether error is the SDK giving up on an undecided transaction."""
    return type(error).__name__ == "GenLayerError" and _NOT_REACHED in str(error)


def unknown_number(error):
    """(table, number) when error is genlayer-py failing to name a number.

    The SDK's tables are keyed by the number as a string, so a number it does
    not know is a KeyError holding that string. None for any other error.
    """
    if not isinstance(error, KeyError) or not error.args:
        return None
    number = str(error.args[0])
    if not number.isdigit():
        return None
    frames = traceback.extract_tb(error.__traceback__)
    table = re.search(r"[A-Z_]+_NUMBER_TO_NAME", (frames[-1].line or "") if frames else "")
    return (table.group(0) if table else "a lookup table"), number


def as_receipt(state):
    """A receipt in the SDK's shape built from a stored state."""
    return {"status_name": state["status"], "result_name": state["result"],
            "tx_execution_result_name": state["execution"]}


def wait_stored(client, tx_id, statuses=DECIDED, budget=None, interval=20,
                progress=None, sleep=None, clock=None):
    """Poll the stored status until it is in statuses or budget s have passed.

    Returns the last stored state, whatever it is. A progress line is printed
    every progress seconds, if given.
    """
    sleep = sleep or time.sleep
    clock = clock or time.monotonic
    budget = POLL_RETRIES * POLL_INTERVAL_MS // 1000 if budget is None else budget
    started = clock()
    shown = started
    state = stored(client, tx_id, sleep=sleep)
    while state["status"] not in statuses and clock() - started < budget:
        sleep(interval)
        state = stored(client, tx_id, sleep=sleep)
        if progress and clock() - shown >= progress:
            shown = clock()
            print("waiting      : %s is %s after %.0f min"
                  % (tx_id[:10], state["status"], (shown - started) / 60.0))
    print("stored status: %s (%s after %.0f s)"
          % (state["status"], "reached" if state["status"] in statuses else "NOT reached",
             clock() - started))
    return state


def wait_for_decision(client, tx_id, attempts=chain.WAIT_ATTEMPTS, pause=chain.WAIT_PAUSE_S,
                      sleep=None):
    """The receipt once the transaction is decided, surviving what Bradbury does.

    A transient failure (a gateway 5xx or HTML page, a dropped connection)
    resumes the wait on the same tx id, up to attempts times; anything else
    is raised. A CANCELED from the SDK is believed only once the stored
    status says so. A number the SDK has no name for ends its wait for good,
    since every retry decodes the same view again, and running out of polls
    on an undecided transaction ends it too: in both cases the stored status
    is waited on instead, and the receipt returned is built from it.
    RuntimeError if the transaction is still undecided after all that.
    """
    sleep = sleep or time.sleep
    for attempt in range(1, attempts + 1):
        try:
            receipt = client.wait_for_transaction_receipt(
                transaction_hash=tx_id,
                status=TransactionStatus.ACCEPTED,
                interval=POLL_INTERVAL_MS,
                retries=POLL_RETRIES,
            )
            if receipt.get("status_name") != "CANCELED":
                return receipt
            state = stored(client, tx_id, sleep=sleep)
            if state["status"] == "CANCELED":
                return receipt
            print("note         : the view says CANCELED, the stored status is %s; "
                  "waiting on the stored status" % (state["status"],))
            return _decided(client, tx_id, sleep)
        except Exception as error:
            unknown = unknown_number(error)
            if unknown:
                print("note         : unknown number %s in genlayer-py's %s; the SDK "
                      "could not decode %s, waiting on the stored status"
                      % (unknown[1], unknown[0], tx_id[:10]))
                return _decided(client, tx_id, sleep)
            if stalled(error):
                print("note         : genlayer-py stopped polling %s undecided; "
                      "waiting on the stored status" % (tx_id[:10],))
                return _decided(client, tx_id, sleep)
            if not chain.transient(error) or attempt == attempts:
                raise
            wait = min(pause * 2 ** (attempt - 1), 120.0)
            print("retry        : the wait for %s failed (%s), resuming in %.0f s, "
                  "attempt %d of %d" % (tx_id, type(error).__name__, wait,
                                         attempt + 1, attempts))
            sleep(wait)
    raise RuntimeError("no decision on %s after %d attempts" % (tx_id, attempts))


def _decided(client, tx_id, sleep):
    state = wait_stored(client, tx_id, sleep=sleep)
    if state["status"] not in DECIDED:
        raise RuntimeError("no decision on %s: the stored status is still %s"
                           % (tx_id, state["status"]))
    return as_receipt(state)
