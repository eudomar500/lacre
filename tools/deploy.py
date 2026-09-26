#!/usr/bin/env python3
"""Deploy a built contract and record where it landed.

The contract is deployed as source and the deploy gas is dominated by the
calldata, so the build script that produced the file is where the size limit
is enforced; this script deploys what it is given and never rebuilds it.

A successful deploy is appended to deployments.json at the repository root,
under the network and the file's stem. Other entries are read back and written
out untouched; re-deploying the same contract on the same network replaces its
own entry, which is the point of the file.

Before anything else the working tree is checked, because the entry records
the commit the deployed source came from and that is only true of a clean
tree: an uncommitted change to any tracked file, an untracked file under
contracts/, lacre/ or the source path, a source git does not track, or an
artifact that is not what its build.py produces now, and the deploy is
refused with the list. --allow-dirty deploys anyway, for probes, and the
entry says the commit is dirty. The entry carries the commit, whether it was
dirty, the source path, the SHA-256 and size of the exact bytes sent and the
SHA-256 of every lacre/ module the build inlined; the same facts are printed
first, so they are in the deploy log. tools/verify_deploy.py checks them
against the chain.

Anything after the path is a constructor argument, read the way call.py reads
a method's: a string unless it is an integer or a boolean, with "str:" to
force a string.

Usage:
    export PROBE_PK=0x<64 hex chars>
    python3 tools/deploy.py contracts/registry/registry.py
    python3 tools/deploy.py contracts/verifier/verifier.py 0x<registry address>
    python3 tools/deploy.py contracts/registry/registry.py --network studionext
    python3 tools/deploy.py contracts/registry/registry.py --estimate-only
    python3 tools/deploy.py experiments/value-probe/contracts/value_probe.py --allow-dirty

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
import provenance
from chain import POLL_INTERVAL_MS, POLL_RETRIES

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENTS = ROOT / "deployments.json"


def record_deployment(network, name, address, consensus_tx, facts):
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
        **facts,
    }
    DEPLOYMENTS.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n")
    print("recorded     : %s %s in %s" % (network, name, DEPLOYMENTS.name))


def main():
    network, arguments = chain.take_network(sys.argv[1:])
    estimate_only = "--estimate-only" in arguments
    allow_dirty = "--allow-dirty" in arguments
    arguments = [arg for arg in arguments if arg not in ("--estimate-only", "--allow-dirty")]
    if not arguments:
        print(__doc__)
        sys.exit(1)

    path = Path(arguments[0])
    args = [chain.parse_arg(argument) for argument in arguments[1:]]
    if not path.is_file():
        chain.die("%s does not exist; build it first" % (path,))
    source = path.read_bytes()
    if not source.startswith(b'# { "Depends":'):
        chain.die("%s does not start with a runner Depends comment" % (path,))

    # Before the key is read or the network is touched: a refused deploy
    # must cost nothing and leave nothing behind.
    facts, problems = provenance.collect(ROOT, path, source, allow_dirty)
    print("contract     : %s" % (path,))
    provenance.show(facts)
    for problem in problems:
        print("dirty        : %s" % (problem,))
    if problems and not allow_dirty:
        chain.die("HEAD does not account for what would be deployed; commit it, or "
                  "pass --allow-dirty for a probe and have the entry say so")

    account, client, net = chain.connect(network)
    print("network      : %s (chain id %d)" % (network, net["chain_id"]))
    print("deployer     : %s" % (account.address,))
    print("rpc          : %s" % (net["rpc_url"],))
    if args:
        print("constructor  : %r" % (tuple(args),))

    encoded = chain.deploy_calldata(client, account, source, args)
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

    print("\nwaiting for ACCEPTED (up to %d minutes per attempt) ..."
          % (POLL_RETRIES * POLL_INTERVAL_MS // 60000,))
    # Resumes on the same tx id after a dropped connection or a gateway error
    # page: by now the deploy is on chain, and losing the wait loses the
    # address.
    receipt = chain.wait_accepted(client, tx_id)

    chain.show_receipt(receipt)
    decoded = receipt.get("tx_data_decoded") or {}
    address = decoded.get("contract_address") or receipt.get("recipient")
    print("CONTRACT     : %s" % (address,))
    if not address:
        chain.die("the receipt carries no contract address; nothing was recorded")

    # The explorer serves contracts and accounts from the same /address path.
    print("explorer     : %s/address/%s" % (net["explorer"], address))
    record_deployment(network, path.stem, address, tx_id, facts)
    print("\nA contract cannot be read until it is FINALIZED; the first write")
    print("after a deploy will report an unknown state and go ahead anyway.")


if __name__ == "__main__":
    main()
