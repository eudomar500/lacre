#!/usr/bin/env python3
"""Shared Bradbury plumbing for deploy_bradbury.py and attest_bradbury.py.

The gas handling is the one measured for the WASM deploy probe in
genlayer-p2p-arena: genlayer-py signs the raw eth_estimateGas result with no
margin, and a nested frame five levels deep can run out of gas even when the
top level limit was never reached, because each CALL forwards only 63/64 of
what is left. So every transaction here is signed at three times the estimate,
clamped to the 2^24 per-transaction cap the node enforces, and the L2 hash is
printed before anything is awaited.

The private key is read only from PROBE_PK. It is never read from a file or an
argument, never written anywhere and never printed.
"""

import json
import os
import sys
import urllib.request

from genlayer_py import create_account, create_client
from genlayer_py.abi import calldata
from genlayer_py.abi.transactions import serialize
from genlayer_py.chains import testnet_bradbury
from genlayer_py.contracts.actions import _encode_add_transaction_data
from genlayer_py.contracts.utils import make_calldata_object
from web3.constants import ADDRESS_ZERO
from web3.logs import DISCARD

RPC_URL = testnet_bradbury.rpc_urls["default"]["http"][0]
L2_EXPLORER = "https://zksync-os-testnet-genlayer.explorer.zksync.dev/tx/%s"
EXPLORER = "https://explorer-bradbury.genlayer.com"

# Measured on Bradbury: gas=2^24 is accepted by eth_sendRawTransaction
# validation, 2^24 + 1 is refused with "gas limit too high" (code -32602).
MAX_TX_GAS = 16_777_216
GAS_MULTIPLIER = 3

# Bradbury has been seen to take 20-25 minutes to reach ACCEPTED, through
# leader rotations. genlayer-py defaults to 30 seconds of polling.
POLL_INTERVAL_MS = 10_000
POLL_RETRIES = 240


def die(message):
    print("error: %s" % (message,), file=sys.stderr)
    sys.exit(1)


def rpc(method, params):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(
        RPC_URL,
        data=body,
        # The RPC edge answers 403 to urllib's default User-Agent.
        headers={"Content-Type": "application/json", "User-Agent": "dkim-probe/1.0"},
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.loads(response.read())


def connect():
    private_key = os.environ.get("PROBE_PK")
    if not private_key:
        die("PROBE_PK is not set. export PROBE_PK=0x<64 hex chars>")
    private_key = private_key.strip()
    if not private_key.startswith("0x") or len(private_key) != 66:
        die("PROBE_PK must be a 0x-prefixed 32-byte hex string")
    account = create_account(private_key)
    client = create_client(chain=testnet_bradbury, account=account)
    client.initialize_consensus_smart_contract()
    return account, client


def deploy_calldata(client, account, code):
    """Exactly what genlayer_py.contracts.actions.deploy_contract builds."""
    data = [
        code,
        calldata.encode(make_calldata_object(method=None, args=[], kwargs=None)),
        False,  # leader_only
    ]
    return _encode_add_transaction_data(
        self=client,
        sender_account=account,
        recipient=ADDRESS_ZERO,
        consensus_max_rotations=client.chain.default_consensus_max_rotations,
        data=serialize(data),
    )


def write_calldata(client, account, address, method, args):
    """Exactly what genlayer_py.contracts.actions.write_contract builds."""
    data = [
        calldata.encode(make_calldata_object(method=method, args=args, kwargs=None)),
        False,  # leader_only
    ]
    return _encode_add_transaction_data(
        self=client,
        sender_account=account,
        recipient=address,
        consensus_max_rotations=client.chain.default_consensus_max_rotations,
        data=serialize(data),
    )


def estimate(client, account, encoded, final=True):
    consensus = client.chain.consensus_main_contract["address"]
    print("to           : %s (ConsensusMain)" % (consensus,))
    print("calldata     : %d hex chars" % (len(encoded),))
    out = rpc(
        "eth_estimateGas",
        [{"from": account.address, "to": consensus, "data": encoded, "value": "0x0"}],
    )
    if out.get("error"):
        error = out["error"]
        print("\nESTIMATE FAILED: code=%s %s" % (error.get("code"), error.get("message")))
        print("raw data     : %r" % (error.get("data"),))
        sys.exit(1)
    gas = int(out["result"], 16)
    print("ESTIMATED GAS: %s (%d)" % (out["result"], gas))
    print("per-tx cap   : %d (2^24), this uses %.1f%%" % (MAX_TX_GAS, 100.0 * gas / MAX_TX_GAS))
    if gas > MAX_TX_GAS:
        die(
            "estimated gas %d exceeds the per-transaction cap %d (2^24); "
            "eth_sendRawTransaction would refuse this with 'gas limit too high'"
            % (gas, MAX_TX_GAS)
        )
    if final:
        print("nothing was sent")
    return gas


def send(client, account, encoded, estimated_gas):
    """Sign, broadcast, print the L2 hash, then return the consensus tx id."""
    consensus = client.chain.consensus_main_contract["address"]
    gas = min(estimated_gas * GAS_MULTIPLIER, MAX_TX_GAS)
    if gas < estimated_gas:
        die("estimate %d already exceeds the cap %d" % (estimated_gas, MAX_TX_GAS))

    latest = client.w3.eth.get_block("latest")
    priority = client.w3.to_wei(2, "gwei")
    transaction = {
        "from": account.address,
        "nonce": client.w3.eth.get_transaction_count(account.address),
        "data": encoded,
        "to": consensus,
        "value": 0,
        "maxFeePerGas": latest["baseFeePerGas"] + priority,
        "maxPriorityFeePerGas": priority,
        "chainId": client.chain.id,
        "gas": gas,
    }
    signed = account.sign_transaction(transaction)
    raw = client.w3.to_hex(signed.raw_transaction)
    l2_hash = client.w3.to_hex(signed.hash)

    print("gas limit    : %d (%dx estimate, %.1f%% of cap)"
          % (gas, GAS_MULTIPLIER, 100.0 * gas / MAX_TX_GAS))
    print("nonce        : %d" % (transaction["nonce"],))
    print("L2 TX HASH   : %s" % (l2_hash,))
    print("L2 explorer  : %s" % (L2_EXPLORER % (l2_hash,),))
    print("broadcasting ...")

    out = rpc("eth_sendRawTransaction", [raw])
    if out.get("error"):
        die("broadcast refused: %s" % (out["error"].get("message"),))
    sent = out["result"]
    if sent.lower() != l2_hash.lower():
        print("note         : node returned a different hash: %s" % (sent,))

    print("waiting for the L2 receipt ...")
    receipt = client.w3.eth.wait_for_transaction_receipt(sent, timeout=300)
    used = receipt["gasUsed"]
    price = receipt.get("effectiveGasPrice", 0)
    print("L2 status    : %d (%s)"
          % (receipt["status"], "success" if receipt["status"] == 1 else "REVERTED"))
    print("L2 gasUsed   : %d of %d" % (used, gas))
    print("L2 cost      : %d wei" % (used * price,))
    if receipt["status"] != 1:
        die("the L2 transaction reverted; nothing reached consensus")

    contract = client.w3.eth.contract(abi=client.chain.consensus_main_contract["abi"])
    events = contract.get_event_by_name("NewTransaction").process_receipt(receipt, DISCARD)
    if not events:
        die("L2 succeeded but no NewTransaction event was emitted")
    consensus_id = client.w3.to_hex(events[0]["args"]["txId"])
    print("CONSENSUS TX : %s" % (consensus_id,))
    print("explorer     : %s/tx/%s" % (EXPLORER, consensus_id))
    return consensus_id, used


def show_receipt(receipt):
    print("status       : %s" % (receipt.get("status_name"),))
    print("execution    : %s" % (receipt.get("tx_execution_result_name"),))
    print("result       : %s" % (receipt.get("result_name"),))
    for key in sorted(receipt):
        if "gas" in key.lower():
            print("%-13s: %s" % (key, receipt[key]))
