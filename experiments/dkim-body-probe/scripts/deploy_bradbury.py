#!/usr/bin/env python3
"""Deploy contracts/body_probe.py to GenLayer Testnet Bradbury (chain id 4221).

The contract is deployed as source; deploy gas is dominated by the calldata,
which is why the build refuses anything over 12 000 bytes. Run
scripts/build_contract.py first: this script deploys the built file and will
not rebuild it for you.

Usage:
    export PROBE_PK=0x<64 hex chars>
    python3 scripts/deploy_bradbury.py
    python3 scripts/deploy_bradbury.py --estimate-only

--estimate-only builds the identical addTransaction calldata and stops at
eth_estimateGas. It sends nothing and needs no funds.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import bradbury
from bradbury import POLL_INTERVAL_MS, POLL_RETRIES
from build_contract import MAX_SOURCE, OUTPUT
from genlayer_py.types import TransactionStatus


def main():
    estimate_only = "--estimate-only" in sys.argv[1:]

    if not OUTPUT.is_file():
        bradbury.die("%s does not exist; run scripts/build_contract.py first" % (OUTPUT,))
    source = OUTPUT.read_bytes()
    if len(source) > MAX_SOURCE:
        bradbury.die(
            "%s is %d bytes, over the %d byte limit; the deploy would exceed the "
            "2^24 gas cap" % (OUTPUT.name, len(source), MAX_SOURCE)
        )

    account, client = bradbury.connect()
    print("contract     : %s" % (OUTPUT,))
    print("source size  : %d bytes" % (len(source),))
    print("deployer     : %s" % (account.address,))
    print("rpc          : %s" % (bradbury.RPC_URL,))
    print("chain id     : %s" % (client.chain.id,))

    encoded = bradbury.deploy_calldata(client, account, source)
    gas = bradbury.estimate(client, account, encoded, final=estimate_only)
    if estimate_only:
        return

    balance = client.w3.eth.get_balance(account.address)
    print("balance      : %d wei" % (balance,))
    if balance == 0:
        bradbury.die(
            "deployer has zero balance; fund it at "
            "https://testnet-faucet.genlayer.foundation before deploying"
        )

    print("\nsubmitting deploy transaction ...")
    tx_id, _ = bradbury.send(client, account, encoded, gas)

    print("\nwaiting for ACCEPTED (up to %d minutes) ..."
          % (POLL_RETRIES * POLL_INTERVAL_MS // 60000,))
    receipt = client.wait_for_transaction_receipt(
        transaction_hash=tx_id,
        status=TransactionStatus.ACCEPTED,
        interval=POLL_INTERVAL_MS,
        retries=POLL_RETRIES,
    )

    bradbury.show_receipt(receipt)
    decoded = receipt.get("tx_data_decoded") or {}
    address = decoded.get("contract_address") or receipt.get("recipient")
    print("CONTRACT     : %s" % (address,))

    if address:
        print("\ncontract     : %s/contract/%s" % (bradbury.EXPLORER, address))
        print("\nnext:")
        print("  python3 scripts/attest_bradbury.py %s <BODY_URL> <BH_CLAIMED>"
              % (address,))


if __name__ == "__main__":
    main()
