#!/usr/bin/env python3
"""Send one write to a deployed contract and wait for consensus.

Arguments are passed as strings unless they read as an integer or as true or
false; prefix one with "str:" to keep it a string.

--value attaches native value, in wei, to the transaction. It is the value
field of the L2 addTransaction call, which is what the contract reads back as
gl.message.value, and the method has to be payable to accept it.

Usage:
    export PROBE_PK=0x<64 hex chars>
    python3 tools/call.py <CONTRACT_ADDRESS> register_key amazon.com <selector>
    python3 tools/call.py <CONTRACT_ADDRESS> set_version verifier 0x<address>
    python3 tools/call.py <CONTRACT_ADDRESS> pay --value 10000000000000000
    python3 tools/call.py <CONTRACT_ADDRESS> key_count --network studionext
"""

import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import chain
import txstate
from chain import POLL_INTERVAL_MS, POLL_RETRIES


def take_value(arguments):
    """--value <wei>, removed from the argument list. Default 0."""
    value = 0
    rest = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--value":
            index += 1
            if index >= len(arguments):
                chain.die("--value needs an amount in wei")
            argument = "--value=" + arguments[index]
        if argument.startswith("--value="):
            text = argument.split("=", 1)[1]
            if not text.isdigit():
                chain.die("--value takes a whole number of wei, not %r" % (text,))
            value = int(text)
        else:
            rest.append(argument)
        index += 1
    return value, rest


def main():
    # The SDK calls requests without a timeout; a stalled connection has to
    # fail so the wait can resume.
    socket.setdefaulttimeout(txstate.SOCKET_TIMEOUT)
    network, arguments = chain.take_network(sys.argv[1:])
    value, arguments = take_value(arguments)
    if len(arguments) < 2:
        print(__doc__)
        sys.exit(1)
    address, method = arguments[0], arguments[1]
    args = [chain.parse_arg(argument) for argument in arguments[2:]]

    account, client, net = chain.connect(network)
    print("network      : %s (chain id %d)" % (network, net["chain_id"]))
    print("contract     : %s" % (address,))
    print("method       : %s%r" % (method, tuple(args)))
    print("sender       : %s" % (account.address,))
    if value:
        print("value        : %d wei" % (value,))

    encoded = chain.write_calldata(client, account, address, method, args)
    gas = chain.estimate(net, client, account, encoded, final=False, value=value)

    print("\nsubmitting transaction ...")
    started = time.time()
    tx_id, l2_gas = chain.send(net, client, account, encoded, gas, value=value)

    print("\nwaiting for a decision (up to %d minutes per attempt) ..."
          % (POLL_RETRIES * POLL_INTERVAL_MS // 60000,))
    # The transaction is on chain by now; losing the wait loses nothing but
    # the answer, so every failure that can be waited out is.
    try:
        receipt = txstate.wait_for_decision(client, tx_id)
    except RuntimeError as error:
        chain.die("%s; the transaction is on chain, check it at %s/tx/%s"
                  % (error, net["explorer"], tx_id))
    elapsed = time.time() - started

    chain.show_receipt(receipt)
    print("L2 gasUsed   : %d" % (l2_gas,))
    print("wall time    : %.0f s to %s" % (elapsed, receipt.get("status_name")))

    returned = (receipt.get("tx_data_decoded") or {}).get("result")
    if returned is not None:
        print("returned     : %s" % (returned,))
    print("\nread it back with:")
    print("  python3 tools/read.py %s <method> [args...] --network %s"
          % (address, network))


if __name__ == "__main__":
    main()
