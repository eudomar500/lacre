#!/usr/bin/env python3
"""Deploy a built contract and record where it landed.

The contract is deployed as source and the deploy gas is dominated by the
calldata, so the build script that produced the file is where the size limit
is enforced; this script deploys what it is given and never rebuilds it.

A successful deploy is appended to deployments.json at the repository root,
under the network and the file's stem. Other entries are read back and written
out untouched; re-deploying the same contract on the same network replaces its
own entry, which is the point of the file.

Usage:
    export PROBE_PK=0x<64 hex chars>
    python3 tools/deploy.py contracts/registry/registry.py
    python3 tools/deploy.py contracts/registry/registry.py --network studionext
    python3 tools/deploy.py contracts/registry/registry.py --estimate-only

--estimate-only builds the identical addTransaction calldata and stops at
eth_estimateGas. It sends nothing and needs no funds, so a throwaway key is
enough for it.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import chain
from chain import POLL_INTERVAL_MS, POLL_RETRIES
from genlayer_py.types import TransactionStatus

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENTS = ROOT / "deployments.json"


def record_deployment(network, name, address, consensus_tx):
    try:
        existing = json.loads(DEPLOYMENTS.read_text()) if DEPLOYMENTS.is_file() else {}
    except ValueError:
        chain.die("%s is not valid JSON; it was left alone" % (DEPLOYMENTS.name,))
    if not isinstance(existing, dict):
        chain.die("%s is not an object; it was left alone" % (DEPLOYMENTS.name,))

    existing.setdefault(network, {})[name] = {
        "address": address,
        "consensus_tx": consensus_tx,
        "deployed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    DEPLOYMENTS.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n")
    print("recorded     : %s %s in %s" % (network, name, DEPLOYMENTS.name))


def main():
    network, arguments = chain.take_network(sys.argv[1:])
    estimate_only = "--estimate-only" in arguments
    arguments = [arg for arg in arguments if arg != "--estimate-only"]
    if len(arguments) != 1:
        print(__doc__)
        sys.exit(1)

    path = Path(arguments[0])
    if not path.is_file():
        chain.die("%s does not exist; build it first" % (path,))
    source = path.read_bytes()
    if not source.startswith(b'# { "Depends":'):
        chain.die("%s does not start with a runner Depends comment" % (path,))

    account, client, net = chain.connect(network)
    print("network      : %s (chain id %d)" % (network, net["chain_id"]))
    print("contract     : %s" % (path,))
    print("source size  : %d bytes" % (len(source),))
    print("deployer     : %s" % (account.address,))
    print("rpc          : %s" % (net["rpc_url"],))

    encoded = chain.deploy_calldata(client, account, source)
    gas = chain.estimate(net, client, account, encoded, final=estimate_only)
    if estimate_only:
        return

    balance = client.w3.eth.get_balance(account.address)
    print("balance      : %d wei" % (balance,))
    if balance == 0:
        chain.die(
            "deployer has zero balance; fund it at %s before deploying"
            % (net["faucet"] or "the network's own funding path",)
        )

    print("\nsubmitting deploy transaction ...")
    tx_id, _ = chain.send(net, client, account, encoded, gas)

    print("\nwaiting for ACCEPTED (up to %d minutes) ..."
          % (POLL_RETRIES * POLL_INTERVAL_MS // 60000,))
    receipt = client.wait_for_transaction_receipt(
        transaction_hash=tx_id,
        status=TransactionStatus.ACCEPTED,
        interval=POLL_INTERVAL_MS,
        retries=POLL_RETRIES,
    )

    chain.show_receipt(receipt)
    decoded = receipt.get("tx_data_decoded") or {}
    address = decoded.get("contract_address") or receipt.get("recipient")
    print("CONTRACT     : %s" % (address,))
    if not address:
        chain.die("the receipt carries no contract address; nothing was recorded")

    # The explorer serves contracts and accounts from the same /address path.
    print("explorer     : %s/address/%s" % (net["explorer"], address))
    record_deployment(network, path.stem, address, tx_id)
    print("\nA contract cannot be read until it is FINALIZED; the first write")
    print("after a deploy will report an unknown state and go ahead anyway.")


if __name__ == "__main__":
    main()
