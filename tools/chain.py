#!/usr/bin/env python3
"""Network table and transaction plumbing: RPC, gas, signing, receipts, reads.

This is the production copy, shared by deploy.py, call.py and read.py. The
probes under experiments/ carry their own frozen copies of the Bradbury half;
nothing here is imported from there and nothing there changes to match this.

NETWORKS below is the source of truth for every endpoint. genlayer-py ships
its own chain objects and the two have disagreed about a host before, so
connect() applies the table to the chain object and refuses to sign if the
ConsensusMain address or the chain id underneath it is not what the table
says. One row per network, one place to fix.

Each row also carries a mode. "l2" is the path these tools implement: sign an
addTransaction calldata against ConsensusMain and follow the L2 receipt.
"studio" networks serve the Studio RPC API instead, which is a different
client, and connect() refuses them until that client is ported here.

The gas rule is the one measured on Bradbury: genlayer-py signs the raw
eth_estimateGas result with no margin, and a nested frame five levels deep can
run out of gas even when the top level limit was never reached, because each
CALL forwards only 63/64 of what is left. So a transaction is signed at
gas_multiplier times the estimate, clamped to max_tx_gas, and the L2 hash is
printed before anything is awaited. Both numbers are per network: Studionet
carries the Bradbury values until someone measures its own.

The private key is read only from PROBE_PK. It is never read from a file or an
argument, never written anywhere and never printed.
"""

import json
import os
import sys
import urllib.request

import eth_utils
from genlayer_py import create_account, create_client
from genlayer_py.abi import calldata
from genlayer_py.abi.transactions import serialize
from genlayer_py.chains import testnet_bradbury
from genlayer_py.contracts.actions import _encode_add_transaction_data
from genlayer_py.contracts.utils import make_calldata_object
from genlayer_py.types import TransactionHashVariant
from web3.constants import ADDRESS_ZERO
from web3.logs import DISCARD

NETWORKS = {
    "bradbury": {
        "mode": "l2",
        "chain": testnet_bradbury,
        "chain_id": 4221,
        "rpc_url": "https://rpc-bradbury.genlayer.com",
        "consensus_main": "0x0112Bf6e83497965A5fdD6Dad1E447a6E004271D",
        "explorer": "https://explorer-bradbury.genlayer.com",
        # Bradbury settles on a zkSync based L2, so a signed transaction has a
        # second life there under its own hash.
        "l2_explorer": "https://zksync-os-testnet-genlayer.explorer.zksync.dev/tx/%s",
        "faucet": "https://testnet-faucet.genlayer.foundation",
        # Measured: gas=2^24 is accepted by eth_sendRawTransaction validation,
        # 2^24 + 1 is refused with "gas limit too high" (code -32602).
        "max_tx_gas": 16_777_216,
        "gas_multiplier": 3,
        "measured": True,
    },
    "studionext": {
        "mode": "studio",
        # genlayer-py ships no 61997 chain, and the Studio path does not use
        # one as written; the client in carnage builds its own.
        "chain": None,
        "chain_id": 61997,
        # Host and explorer as the Studio Next client in carnage uses them;
        # eth_chainId there returns 0xf22d, the 61997 above.
        "rpc_url": "https://studio-next.genlayer.com/api",
        "explorer": "https://explorer-studio-dev.genlayer.com",
        # The Studio serves its own RPC API and exposes no ConsensusMain,
        # which is what the mode above is for.
        "consensus_main": None,
        "l2_explorer": None,
        # UNVERIFIED: the Studio funds an account from its own wallet panel,
        # top right, "Fund Account"; there is no faucet page.
        "faucet": None,
        # UNVERIFIED: the Bradbury numbers, carried until a Studio Next
        # transaction is measured. Nothing here has been signed there.
        "max_tx_gas": 16_777_216,
        "gas_multiplier": 3,
        "measured": False,
    },
}

DEFAULT_NETWORK = "bradbury"

# Bradbury has been seen to take 20-25 minutes to reach ACCEPTED, through
# leader rotations. genlayer-py defaults to 30 seconds of polling.
POLL_INTERVAL_MS = 10_000
POLL_RETRIES = 240

# A view that could not be read, as distinct from any value it might return.
UNKNOWN = object()


def die(message):
    print("error: %s" % (message,), file=sys.stderr)
    sys.exit(1)


def take_network(arguments):
    """Pull --network out of an argument list, leaving the positional ones.

    These tools take positional contract arguments that may start with a dash
    or look like flags, so the one option they share is removed by hand rather
    than handed to argparse.
    """
    known = ", ".join(sorted(NETWORKS))
    name = DEFAULT_NETWORK
    rest = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--network":
            index += 1
            if index >= len(arguments):
                die("--network needs a name, one of: %s" % (known,))
            name = arguments[index]
        elif argument.startswith("--network="):
            name = argument.split("=", 1)[1]
        else:
            rest.append(argument)
        index += 1
    if name not in NETWORKS:
        die("unknown network %r, expected one of: %s" % (name, known))
    return name, rest


def rpc(net, method, params):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(
        net["rpc_url"],
        data=body,
        # The RPC edge answers 403 to urllib's default User-Agent.
        headers={"Content-Type": "application/json", "User-Agent": "lacre/1.0"},
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.loads(response.read())


def connect(name):
    """An account and a client on one network, with the table enforced."""
    net = NETWORKS[name]
    if net["mode"] == "studio":
        die("studio mode is not wired yet; deploy and calls on Studio Next go "
            "through the Studio RPC client used in carnage, to be ported here")
    private_key = os.environ.get("PROBE_PK")
    if not private_key:
        die("PROBE_PK is not set. export PROBE_PK=0x<64 hex chars>")
    private_key = private_key.strip()
    if not private_key.startswith("0x") or len(private_key) != 66:
        die("PROBE_PK must be a 0x-prefixed 32-byte hex string")

    chain = net["chain"]
    chain.rpc_urls["default"]["http"] = [net["rpc_url"]]
    account = create_account(private_key)
    client = create_client(chain=chain, account=account)
    client.initialize_consensus_smart_contract()

    if int(client.chain.id) != net["chain_id"]:
        die("%s: the SDK chain id is %s, the table says %d"
            % (name, client.chain.id, net["chain_id"]))
    configured = client.chain.consensus_main_contract["address"]
    if int(configured, 16) == 0:
        die("%s: the node reports no ConsensusMain contract, so there is "
            "nothing here to sign against; these tools take the L2 path that "
            "Bradbury exposes" % (name,))
    if configured.lower() != net["consensus_main"].lower():
        die("%s: the SDK ConsensusMain is %s, the table says %s; fix the table "
            "or the SDK before signing anything"
            % (name, configured, net["consensus_main"]))
    if not net["measured"]:
        print("note         : %s gas limits are unmeasured, carried from bradbury"
              % (name,))
    return account, client, net


def parse_arg(text):
    """One command line argument as the contract will receive it.

    Everything is a string unless it reads as an integer or a boolean, which
    covers every method these contracts expose. "str:" forces a string for the
    selector that happens to be all digits.
    """
    if text.startswith("str:"):
        return text[4:]
    if text in ("true", "false"):
        return text == "true"
    if text.lstrip("-").isdigit():
        return int(text)
    return text


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


def estimate(net, client, account, encoded, final=True, value=0):
    consensus = client.chain.consensus_main_contract["address"]
    cap = net["max_tx_gas"]
    print("to           : %s (ConsensusMain)" % (consensus,))
    print("calldata     : %d hex chars" % (len(encoded),))
    out = rpc(
        net,
        "eth_estimateGas",
        [{
            "from": account.address,
            "to": consensus,
            "data": encoded,
            # addTransaction is payable: the value on this L2 transaction is
            # what the contract sees as gl.message.value.
            "value": hex(value),
        }],
    )
    if out.get("error"):
        error = out["error"]
        print("\nESTIMATE FAILED: code=%s %s" % (error.get("code"), error.get("message")))
        print("raw data     : %r" % (error.get("data"),))
        sys.exit(1)
    gas = int(out["result"], 16)
    print("ESTIMATED GAS: %s (%d)" % (out["result"], gas))
    print("per-tx cap   : %d, this uses %.1f%%" % (cap, 100.0 * gas / cap))
    if gas > cap:
        die(
            "estimated gas %d exceeds the per-transaction cap %d; "
            "eth_sendRawTransaction would refuse this with 'gas limit too high'"
            % (gas, cap)
        )
    if final:
        print("nothing was sent")
    return gas


def send(net, client, account, encoded, estimated_gas, value=0):
    """Sign, broadcast, print the L2 hash, then return the consensus tx id."""
    consensus = client.chain.consensus_main_contract["address"]
    cap = net["max_tx_gas"]
    multiplier = net["gas_multiplier"]
    gas = min(estimated_gas * multiplier, cap)
    if gas < estimated_gas:
        die("estimate %d already exceeds the cap %d" % (estimated_gas, cap))

    latest = client.w3.eth.get_block("latest")
    priority = client.w3.to_wei(2, "gwei")
    transaction = {
        "from": account.address,
        "nonce": client.w3.eth.get_transaction_count(account.address),
        "data": encoded,
        "to": consensus,
        "value": value,
        "maxFeePerGas": latest["baseFeePerGas"] + priority,
        "maxPriorityFeePerGas": priority,
        "chainId": client.chain.id,
        "gas": gas,
    }
    signed = account.sign_transaction(transaction)
    raw = client.w3.to_hex(signed.raw_transaction)
    l2_hash = client.w3.to_hex(signed.hash)

    print("gas limit    : %d (%dx estimate, %.1f%% of cap)"
          % (gas, multiplier, 100.0 * gas / cap))
    if value:
        print("value        : %d wei" % (value,))
    print("nonce        : %d" % (transaction["nonce"],))
    print("L2 TX HASH   : %s" % (l2_hash,))
    if net["l2_explorer"]:
        print("L2 explorer  : %s" % (net["l2_explorer"] % (l2_hash,),))
    print("broadcasting ...")

    out = rpc(net, "eth_sendRawTransaction", [raw])
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
    print("explorer     : %s/tx/%s" % (net["explorer"], consensus_id))
    return consensus_id, used


def show_receipt(receipt):
    print("status       : %s" % (receipt.get("status_name"),))
    print("execution    : %s" % (receipt.get("tx_execution_result_name"),))
    print("result       : %s" % (receipt.get("result_name"),))
    for key in sorted(receipt):
        if "gas" in key.lower():
            print("%-13s: %s" % (key, receipt[key]))


def gen_call_params(client, address, method, args):
    """Exactly the gen_call params genlayer_py.read_contract builds."""
    data = [
        calldata.encode(make_calldata_object(method=method, args=args, kwargs=None)),
        b"\x00",
    ]
    return {
        "type": "read",
        "to": address,
        "from": client.local_account.address,
        "data": serialize(data),
        "transaction_hash_variant": TransactionHashVariant.LATEST_NONFINAL.value,
    }


def raw_read(net, client, address, method, args):
    """Recover the result genlayer-py could not read, or report why not.

    Bradbury answers gen_call with {"data": "<hex>", "status": {...}, ...},
    while genlayer-py 0.16.3 expects the result to be a bare hex string and
    dies on the concatenation with the body still intact. Repeating the
    identical request raw recovers it: on status.code 0 the payload is decoded
    exactly as read_contract decodes its own hex, and anything else prints the
    whole response and fails the read.
    """
    response = rpc(net, "gen_call", [gen_call_params(client, address, method, args)])
    result = response.get("result")
    status = result.get("status") if isinstance(result, dict) else None
    code = status.get("code") if isinstance(status, dict) else None
    data = result.get("data") if isinstance(result, dict) else None

    if code == 0 and isinstance(data, str):
        # decode_hex strips one 0x, and read_contract always hands it one.
        if not data.startswith("0x"):
            data = "0x" + data
        try:
            return calldata.decode(eth_utils.hexadecimal.decode_hex(data))
        except Exception as error:
            print("%s returned status 0 but its data did not decode: %s"
                  % (method, type(error).__name__))
            print(json.dumps(response, indent=2, default=str))
            return UNKNOWN

    print("%s did not return a readable result. Raw gen_call response:" % (method,))
    print(json.dumps(response, indent=2, default=str))
    return UNKNOWN


def read(net, client, address, method, args):
    """A view call, falling back to the raw RPC on the decoding bug above."""
    try:
        return client.read_contract(address=address, function_name=method, args=args)
    except TypeError:
        return raw_read(net, client, address, method, args)
