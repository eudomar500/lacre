#!/usr/bin/env python3
"""Send one body to a deployed llm_probe2 and wait for consensus.

Probe D's send.py, for extract and for the extract_plain control, which
takes the same prompt and agrees on shipped and eta alone; --plain picks it.
The body travels inline, in
the calldata of the write, and the label stored beside the result is the
file's stem. A .txt body is sent as it is; a .json body is an object whose
"body" field is the text, which is how a body with characters outside ASCII
is kept in an ASCII file.

stdout carries the consensus hash and the link to it and nothing else;
everything the plumbing prints goes to stderr, including the "returned     :"
line with the reading read back from eqBlocksOutputs.

The private key is read only from PROBE_PK, by tools/chain.py. It is never
taken from an argument and never printed.

Usage:
    export PROBE_PK=0x<64 hex chars>
    python3 experiments/llm-probe-2/send.py <ADDRESS> bodies/01_shipped.txt
    python3 experiments/llm-probe-2/send.py <ADDRESS> bodies/10_unicode.json
    python3 experiments/llm-probe-2/send.py <ADDRESS> bodies/01_shipped.txt --plain
    python3 experiments/llm-probe-2/send.py <ADDRESS> <body> --network bradbury
    python3 experiments/llm-probe-2/send.py <ADDRESS> <body> --nonce 355

--nonce is what run.py adds when it runs a call again after "not sent": the
repeat must use the nonce of the send it replaces, or not be signed at all.
"""

import contextlib
import json
import re
import socket
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(HERE))

import chain
import chainread
from chain import POLL_INTERVAL_MS, POLL_RETRIES

import rlp
from genlayer_py.abi import calldata
from genlayer_py.types import TransactionStatus

METHODS = {False: "extract", True: "extract_plain"}

# How many times the wait for a decision resumes on the same transaction
# after a dropped connection, and the first pause; each pause doubles, up to
# two minutes. On 24 September one truncated response ended a send whose
# transaction went on to be accepted.
WAIT_ATTEMPTS = 6
WAIT_PAUSE = 10.0

# Field 11 of the V06 tuple ConsensusData.getTransactionData returns. One
# entry per non-deterministic block, holding what that block agreed on;
# genlayer-py 0.16.3 does not carry it into the receipt it builds.
EQ_BLOCKS_OUTPUTS = 11

# Every eqBlocksOutputs list ends with this literal, a deploy included. It is
# a sentinel, not an output.
PADDING = b"padded"

# The first byte of an output is the genvm result code; 0 is a return and the
# rest is that return in calldata. The other codes carry no reading.
RETURN_CODE = 0


def eq_block_values(blob):
    """The values the non-deterministic blocks returned, decoded, in order.

    Never raises: this runs after consensus, and a reading that cannot be
    recovered is no reason to lose the transaction hash.
    """
    if not blob:
        return []
    try:
        items = rlp.decode(bytes(blob), strict=False)
    except Exception:
        return []
    values = []
    for item in items:
        if item == PADDING:
            continue
        if len(item) < 2 or item[0] != RETURN_CODE:
            continue
        try:
            values.append(str(calldata.decode(item[1:])))
        except Exception:
            continue
    return values


def eq_blocks_outputs(client, tx_id, sleep=time.sleep):
    """The raw eqBlocksOutputs of one consensus transaction, or None.

    Asked again after a dropped connection or a gateway page, like every
    other read here; None only once that has failed too.
    """
    try:
        consensus_data = client.w3.eth.contract(
            address=client.chain.consensus_data_contract["address"],
            abi=client.chain.consensus_data_contract["abi"],
        )
        data = chainread.retry(
            lambda: consensus_data.functions.getTransactionData(
                tx_id, int(time.time())).call(),
            "getTransactionData %s" % (tx_id[:10],), sleep=sleep, log=sys.stdout)
        return data[EQ_BLOCKS_OUTPUTS]
    except Exception as error:
        print("note         : eqBlocksOutputs could not be read (%s)"
              % (type(error).__name__,))
        return None


def resolve_body(argument):
    """A body path, taken as given or relative to this probe's directory."""
    path = Path(argument)
    if not path.is_file():
        path = HERE / argument
    if not path.is_file():
        chain.die("%s does not exist" % (argument,))
    return path


def read_body(path):
    """The text to send: the file itself, or the "body" field of a .json."""
    text = path.read_text(encoding="utf-8")
    if path.suffix != ".json":
        return text
    try:
        body = json.loads(text)["body"]
    except (ValueError, KeyError, TypeError):
        chain.die("%s is not an object with a \"body\" string" % (path.name,))
    if not isinstance(body, str):
        chain.die("%s: \"body\" is not a string" % (path.name,))
    return body


def take_method(arguments):
    """(method name, the other arguments), with --plain taken out."""
    plain = "--plain" in arguments
    return METHODS[plain], [argument for argument in arguments if argument != "--plain"]


def take_nonce(arguments):
    """(nonce or None, the other arguments), with --nonce N taken out.

    run.py passes it when it runs a call again after "not sent", so the
    repeat uses the nonce of the send it replaces; see chain.send.
    """
    if "--nonce" not in arguments:
        return None, arguments
    index = arguments.index("--nonce")
    if index + 1 >= len(arguments) or not arguments[index + 1].isdigit():
        chain.die("--nonce needs a number")
    return int(arguments[index + 1]), arguments[:index] + arguments[index + 2:]


# What genlayer-py raises when its polling budget runs out on a transaction
# that is still undecided. On 24 September transactions sat 20 minutes with
# no event, and a queued one was only activated after 80.
_NOT_REACHED = "did not reach desired status"


def stalled(error):
    """Whether error is the SDK giving up on an undecided transaction."""
    return type(error).__name__ == "GenLayerError" and _NOT_REACHED in str(error)


def unknown_number(error):
    """(table, number) when error is genlayer-py failing to name a number.

    The SDK names the numbers of a transaction through tables keyed by the
    number as a string, so a number it does not know is a KeyError holding
    that string. On 24 September Bradbury's timestamped view answered with a
    status 14, which no local source names. None for any other error.
    """
    if not isinstance(error, KeyError) or not error.args:
        return None
    number = str(error.args[0])
    if not number.isdigit():
        return None
    frames = traceback.extract_tb(error.__traceback__)
    table = re.search(r"[A-Z_]+_NUMBER_TO_NAME", (frames[-1].line or "") if frames else "")
    return (table.group(0) if table else "a lookup table"), number


def wait_stored(client, tx_id, sleep=time.sleep):
    """A receipt carrying only the stored status, once that is decided.

    For a transaction genlayer-py cannot decode: getTransactionAllData is
    read by field name and needs no name for the number the SDK choked on.
    """
    stored = chainread.wait_decided(client, tx_id, sleep=sleep, log=sys.stdout,
                                    budget=POLL_RETRIES * POLL_INTERVAL_MS // 1000)
    if stored not in chainread.DECIDED:
        raise RuntimeError("no decision on %s: the stored status is still %s"
                           % (tx_id, stored))
    return {"status_name": stored}


def wait_for_decision(client, tx_id, attempts=WAIT_ATTEMPTS, pause=WAIT_PAUSE,
                      sleep=time.sleep):
    """The SDK receipt once the transaction is decided.

    A transient failure resumes the wait on the same tx id, up to attempts
    times; anything else is raised. The SDK judges "decided" from the
    timestamped view, which calls a queued transaction CANCELED from 30
    minutes after its creation while it is still stored as PENDING and can
    still run, so a CANCELED is only believed once the stored status says so.
    A number the SDK has no name for ends its wait for good, since every
    retry decodes the same view again; the stored status is waited on
    instead, and the receipt returned holds that status alone. So is the
    SDK running out of polls on a transaction that is still undecided: the
    stored status gets one more budget of the same length before this gives
    up, and run.py waits again after that.
    """
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
            stored = chainread.stored_status(client, tx_id)
            if stored == "CANCELED":
                return receipt
            print("note         : the view says CANCELED, the stored status is %s; "
                  "waiting on the stored status" % (stored,))
            chainread.wait_decided(client, tx_id, sleep=sleep, log=sys.stdout,
                                   budget=POLL_RETRIES * POLL_INTERVAL_MS // 1000)
        except Exception as error:
            unknown = unknown_number(error)
            if unknown:
                print("note         : unknown number %s in genlayer-py's %s; the SDK "
                      "could not decode %s, waiting on the stored status"
                      % (unknown[1], unknown[0], tx_id[:10]))
                return wait_stored(client, tx_id, sleep=sleep)
            if stalled(error):
                print("note         : genlayer-py stopped polling %s undecided; "
                      "waiting on the stored status" % (tx_id[:10],))
                return wait_stored(client, tx_id, sleep=sleep)
            if not chainread.transient(error) or attempt == attempts:
                raise
            wait = min(pause * 2 ** (attempt - 1), 120)
            print("retry        : the wait for %s failed (%s), resuming in %.0f s, "
                  "attempt %d of %d" % (tx_id[:10], type(error).__name__, wait,
                                         attempt, attempts))
            sleep(wait)
    raise RuntimeError("no decision on %s after %d attempts" % (tx_id, attempts))


def main():
    # The SDK calls requests without a timeout; a stalled connection has to
    # fail so the wait can resume.
    socket.setdefaulttimeout(chainread.SOCKET_TIMEOUT)
    network, arguments = chain.take_network(sys.argv[1:])
    method, arguments = take_method(arguments)
    nonce, arguments = take_nonce(arguments)
    if len(arguments) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    address, body_argument = arguments

    path = resolve_body(body_argument)
    body = read_body(path)
    label = path.stem

    account, client, net = chain.connect(network)
    print("network      : %s (chain id %d)" % (network, net["chain_id"]),
          file=sys.stderr)
    print("contract     : %s" % (address,), file=sys.stderr)
    print("method       : %s" % (method,), file=sys.stderr)
    print("label        : %s" % (label,), file=sys.stderr)
    print("body         : %d bytes" % (len(body.encode("utf-8")),), file=sys.stderr)
    print("sender       : %s" % (account.address,), file=sys.stderr)

    with contextlib.redirect_stdout(sys.stderr):
        encoded = chain.write_calldata(client, account, address, method, [label, body])
        gas = chain.estimate(net, client, account, encoded, final=False)
        started = time.time()
        tx_id, l2_gas = chain.send(net, client, account, encoded, gas, nonce=nonce)

        print("\nwaiting for a decision (up to %d minutes per attempt) ..."
              % (POLL_RETRIES * POLL_INTERVAL_MS // 60000,))
        receipt = wait_for_decision(client, tx_id)
        elapsed = time.time() - started

        chain.show_receipt(receipt)
        print("L2 gasUsed   : %d" % (l2_gas,))
        print("wall time    : %.0f s to %s" % (elapsed, receipt.get("status_name")))
        # The block's output, so the reading alone: the record id the method
        # returns beside it is on no field of the transaction.
        values = eq_block_values(eq_blocks_outputs(client, tx_id))
        if values:
            for value in values:
                print("returned     : %s" % (value,))
        else:
            print("returned     : no eq block output on this transaction")
        # What run.py checks: the stored status, never the timestamped view.
        print("decided      : %s" % (chainread.stored_status(client, tx_id),))

    print(tx_id)
    print("%s/tx/%s" % (net["explorer"], tx_id))


if __name__ == "__main__":
    main()
