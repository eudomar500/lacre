"""Read-only access to ConsensusData for send.py, run.py and collect.py.

No account and no signing: a client built here can call views and read
receipts and nothing else. It lives in this probe rather than in tools/
because the rules it encodes were learned on this probe's run of 24
September 2026 and have not been checked anywhere else.

Two of those rules shape everything below. The timestamped views
(getTransactionData, getTransactionStatus) report a queued transaction as
CANCELED from 1800 s after it was created while it is still stored as
PENDING, and it can still be activated after that; only the stored status
from getTransactionAllData is final. And genlayer-py's provider calls
requests with no timeout and wraps a dropped connection in GenLayerError,
which is not an OSError, so both a hang and a drop need handling here.
"""

import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

# A stalled connection must fail and be retried rather than block forever.
# chain.rpc passes its own timeout, so this only reaches the SDK's requests.
SOCKET_TIMEOUT = 120

# genlayer_py.types.transactions, copied so the tables do not change under
# this probe when the SDK does.
STATUS = ("UNINITIALIZED", "PENDING", "PROPOSING", "COMMITTING", "REVEALING",
          "ACCEPTED", "UNDETERMINED", "FINALIZED", "CANCELED",
          "APPEAL_REVEALING", "APPEAL_COMMITTING", "READY_TO_FINALIZE",
          "VALIDATORS_TIMEOUT", "LEADER_TIMEOUT")
RESULT = ("IDLE", "AGREE", "DISAGREE", "TIMEOUT", "DETERMINISTIC_VIOLATION",
          "NO_MAJORITY", "MAJORITY_AGREE", "MAJORITY_DISAGREE")
VOTE = ("NOT_VOTED", "AGREE", "DISAGREE", "TIMEOUT", "DETERMINISTIC_VIOLATION")

# Which numbering Bradbury's ConsensusData uses, from what it has returned
# (read-only, 24 September 2026). genlayer-js 2.0.0-rc.1 renumbers the end
# of the status enum: 11 VALIDATORS_TIMEOUT, 12 LEADER_TIMEOUT, 13
# LEADER_REVEALING, with no READY_TO_FINALIZE.
# - 5 ACCEPTED, 6 UNDETERMINED, 7 FINALIZED and 8 CANCELED were observed as
#   stored statuses; both numberings agree on 0 to 10.
# - 13 is LEADER_TIMEOUT: the two transactions known to have hit a leader
#   timeout and been appealed, probe D's 0x94fe739d... and incident call 16,
#   0x0cf0337e..., both store previousStatus 13 and status 7, with three
#   rounds; so do incident calls 20 and 35. Every transaction read with
#   previousStatus 0 has one round. An appeal of LEADER_REVEALING, a phase
#   in progress, is not possible, so 2.0-rc's numbering is not the
#   contract's.
# - 11 and 12 have not been seen. Their names here are the SDK's and are
#   UNCONFIRMED; collect.py marks them.
# - 14 came from the timestamped view (call 1 of the clean window, stored 5)
#   and is in neither SDK's table: it stays UNKNOWN_14.
# The result numbers 0, 1, 2 and 5 (IDLE, AGREE, DISAGREE, NO_MAJORITY) were
# observed; 2.0-rc calls 1 and 2 MAJORITY_AGREE and MAJORITY_DISAGREE, the
# same outcomes, and collect.py treats each pair alike.
UNCONFIRMED = ("READY_TO_FINALIZE", "VALIDATORS_TIMEOUT")

# A transaction in one of these stored states will not run again unless it
# is appealed; run.py reads all but FINALIZED and CANCELED again.
DECIDED = ("ACCEPTED", "UNDETERMINED", "FINALIZED", "CANCELED", "LEADER_TIMEOUT",
           "VALIDATORS_TIMEOUT")


def shown(status):
    """A status name as a report prints it, marked if its number is unconfirmed."""
    return "%s (number unconfirmed)" % (status,) if status in UNCONFIRMED else status

# The revert ConsensusMain answers with when a contract already has the
# maximum number of undecided transactions. The name is reconstructed from
# the selector (keccak of "PendingQueueFull(address,uint256)"); no local ABI
# carries it.
PENDING_QUEUE_FULL = "0xd48a82a3"


def name(table, number):
    number = int(number)
    return table[number] if 0 <= number < len(table) else "UNKNOWN_%d" % (number,)


def transient(error):
    """A dropped or refused connection, as opposed to an answer."""
    if isinstance(error, OSError):
        return True
    if type(error).__name__ == "GenLayerError":
        message = str(error)
        return message.startswith("Request to") or "returned invalid JSON" in message
    return False


def retry(fn, what, attempts=6, delay=2.0, sleep=time.sleep, log=None):
    """fn(), again after a growing pause while the failure is transient.

    A revert or any other answer from the node is not transient and is
    raised at once.
    """
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except Exception as error:
            if not transient(error) or attempt == attempts:
                raise
            pause = min(delay * 2 ** (attempt - 1), 120)
            print("retry        : %s failed (%s), attempt %d of %d, waiting %.0f s"
                  % (what, type(error).__name__, attempt, attempts, pause),
                  file=log or sys.stderr)
            sleep(pause)


def _function(abi, function):
    for item in abi:
        if item.get("type") == "function" and item.get("name") == function:
            return item
    raise KeyError(function)


def output_names(abi, function):
    """The names of a function's outputs, in order."""
    return [output["name"] for output in _function(abi, function)["outputs"]]


def fields(abi, function, output=0):
    """The component names of one tuple output of a function, in order.

    Tuple positions are read from the ABI by name everywhere in this probe:
    a hard-coded position was wrong once already.
    """
    return [component["name"]
            for component in _function(abi, function)["outputs"][output]["components"]]


def connect_readonly(network="bradbury"):
    """A client with no account on one network of tools/chain.py's table."""
    import chain
    from genlayer_py import create_client

    socket.setdefaulttimeout(SOCKET_TIMEOUT)
    net = chain.NETWORKS[network]
    if net["mode"] != "l2":
        chain.die("%s is not an l2 network; this reads ConsensusData" % (network,))
    net["chain"].rpc_urls["default"]["http"] = [net["rpc_url"]]
    client = retry(lambda: create_client(chain=net["chain"]), "connect")
    if int(client.chain.id) != net["chain_id"]:
        chain.die("%s: the SDK chain id is %s, the table says %d"
                  % (network, client.chain.id, net["chain_id"]))
    return client, net


def consensus_data(client):
    return client.w3.eth.contract(
        address=client.chain.consensus_data_contract["address"],
        abi=client.chain.consensus_data_contract["abi"],
    )


def stored_status(client, tx_id):
    """The status ConsensusData stores for one transaction, by name.

    getTransactionAllData takes no timestamp, so unlike the other views it
    never reports a queued transaction as CANCELED before it is.
    """
    abi = client.chain.consensus_data_contract["abi"]
    output = output_names(abi, "getTransactionAllData").index("transaction")
    status = fields(abi, "getTransactionAllData", output).index("status")
    data = retry(lambda: consensus_data(client).functions.getTransactionAllData(tx_id).call(),
                 "getTransactionAllData %s" % (tx_id[:10],))
    return name(STATUS, data[output][status])


def wait_decided(client, tx_id, interval=20, budget=3600, sleep=time.sleep, log=None):
    """Poll the stored status until it is decided, or give up after budget s.

    Returns the last status seen, decided or not.
    """
    waited = 0
    status = stored_status(client, tx_id)
    while status not in DECIDED and waited < budget:
        sleep(interval)
        waited += interval
        status = stored_status(client, tx_id)
    print("stored status: %s (%s after %d s of polling)"
          % (status, "decided" if status in DECIDED else "NOT decided", waited),
          file=log or sys.stderr)
    return status
