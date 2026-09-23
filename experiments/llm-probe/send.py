#!/usr/bin/env python3
"""Send one body to a deployed llm_probe and wait for consensus.

The body is read from a file and travels inline, in the calldata of the
write. The label stored beside the result is the file's stem, so a record
read back names the body it came from without the body itself ever reaching
storage.

Everything the plumbing prints goes to stderr, because the two things worth
copying into the results table are the consensus hash and the link to it.
stdout carries those two lines and nothing else.

The private key is read only from PROBE_PK, by tools/chain.py, exactly as
tools/call.py reads it. It is never taken from an argument and never printed.

Usage:
    export PROBE_PK=0x<64 hex chars>
    python3 experiments/llm-probe/send.py <ADDRESS> strict bodies/01_shipped.txt
    python3 experiments/llm-probe/send.py <ADDRESS> comparative bodies/01_shipped.txt
    python3 experiments/llm-probe/send.py <ADDRESS> strict <body> --network bradbury
"""

import contextlib
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import chain
from chain import POLL_INTERVAL_MS, POLL_RETRIES

import rlp
from genlayer_py.abi import calldata
from genlayer_py.types import TransactionStatus

METHODS = {"strict": "extract_strict", "comparative": "extract_comparative"}

# Where the reading actually is. Bradbury's ConsensusData.getTransactionData
# answers with the V06 tuple, whose field 11 is eqBlocksOutputs: one entry per
# non-deterministic block, holding what that block agreed on. genlayer-py
# 0.16.3 does not carry that field into the receipt it builds, so it is read
# here from the same contract the SDK reads.
EQ_BLOCKS_OUTPUTS = 11

# Every eqBlocksOutputs list ends with this literal, including on a deploy,
# which runs no non-deterministic block and carries nothing else. It is a
# sentinel, not an output.
PADDING = b"padded"

# The first byte of an output is the genvm result code, the same table
# genlayer_py.utils.jsonifier calls RESULT_CODES. 0 is a return and the rest
# of the bytes are that return in calldata; the other codes carry no reading.
RETURN_CODE = 0


def eq_block_values(blob):
    """The values the non-deterministic blocks returned, decoded, in order.

    Never raises. This runs after consensus has already happened, so a
    reading that cannot be recovered is not a reason to fail a run whose
    transaction hash is the thing worth keeping.
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


def eq_blocks_outputs(client, tx_id):
    """The raw eqBlocksOutputs of one consensus transaction, or None."""
    try:
        consensus_data = client.w3.eth.contract(
            address=client.chain.consensus_data_contract["address"],
            abi=client.chain.consensus_data_contract["abi"],
        )
        data = consensus_data.functions.getTransactionData(
            tx_id, int(time.time())
        ).call()
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


def main():
    network, arguments = chain.take_network(sys.argv[1:])
    if len(arguments) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    address, mode, body_argument = arguments
    if mode not in METHODS:
        chain.die("mode must be strict or comparative, not %r" % (mode,))

    path = resolve_body(body_argument)
    body = path.read_text(encoding="utf-8")
    label = path.stem

    account, client, net = chain.connect(network)
    print("network      : %s (chain id %d)" % (network, net["chain_id"]),
          file=sys.stderr)
    print("contract     : %s" % (address,), file=sys.stderr)
    print("method       : %s" % (METHODS[mode],), file=sys.stderr)
    print("label        : %s" % (label,), file=sys.stderr)
    print("body         : %d bytes" % (len(body.encode("utf-8")),), file=sys.stderr)
    print("sender       : %s" % (account.address,), file=sys.stderr)

    args = [label, body]
    with contextlib.redirect_stdout(sys.stderr):
        encoded = chain.write_calldata(client, account, address, METHODS[mode], args)
        gas = chain.estimate(net, client, account, encoded, final=False)
        started = time.time()
        tx_id, l2_gas = chain.send(net, client, account, encoded, gas)

        print("\nwaiting for ACCEPTED (up to %d minutes) ..."
              % (POLL_RETRIES * POLL_INTERVAL_MS // 60000,))
        receipt = client.wait_for_transaction_receipt(
            transaction_hash=tx_id,
            status=TransactionStatus.ACCEPTED,
            interval=POLL_INTERVAL_MS,
            retries=POLL_RETRIES,
        )
        elapsed = time.time() - started

        chain.show_receipt(receipt)
        print("L2 gasUsed   : %d" % (l2_gas,))
        print("wall time    : %.0f s to %s" % (elapsed, receipt.get("status_name")))
        # The reading, without waiting for the contract to be readable: a
        # freshly deployed one cannot be read back until it FINALIZES, half an
        # hour later. This is the output of the non-deterministic block, so it
        # is the reading alone. The record id the method returns beside it is
        # on no field of the transaction.
        values = eq_block_values(eq_blocks_outputs(client, tx_id))
        if values:
            for value in values:
                print("returned     : %s" % (value,))
        else:
            print("returned     : no eq block output on this transaction")

    print(tx_id)
    print("%s/tx/%s" % (net["explorer"], tx_id))


if __name__ == "__main__":
    main()
