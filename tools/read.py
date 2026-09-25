#!/usr/bin/env python3
"""Call one view on a deployed contract.

Views cost no gas and need no key: the client has no account and gen_call
goes out from the zero address. PROBE_PK is never read. A contract that has
not reached FINALIZED yet cannot be read at all.

Arguments follow the same rule as tools/call.py: strings unless they read as
an integer or as true or false, with "str:" to force a string.

Usage:
    python3 tools/read.py <CONTRACT_ADDRESS> get_key amazon.com <selector>
    python3 tools/read.py <CONTRACT_ADDRESS> all_versions
    python3 tools/read.py <CONTRACT_ADDRESS> owner --network studionext
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import chain
import txstate


def show(value, indent=""):
    if isinstance(value, dict):
        if not value:
            print("%s(empty)" % (indent,))
        for key in value:
            print("%s%-18s %s" % (indent, key, value[key]))
    elif isinstance(value, (list, tuple)):
        for item in value:
            show(item, indent)
    else:
        print("%s%s" % (indent, value))


def main():
    network, arguments = chain.take_network(sys.argv[1:])
    if len(arguments) < 2:
        print(__doc__)
        sys.exit(1)
    address, method = arguments[0], arguments[1]
    args = [chain.parse_arg(argument) for argument in arguments[2:]]

    client, net = txstate.connect_readonly(network)
    print("network      : %s (chain id %d)" % (network, net["chain_id"]))
    print("contract     : %s" % (address,))
    print("method       : %s%r" % (method, tuple(args)))

    value = chain.read(net, client, address, method, args)
    if value is chain.UNKNOWN:
        chain.die("gen_call did not return a result for %s" % (method,))
    print()
    show(value)


if __name__ == "__main__":
    main()
