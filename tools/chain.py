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

import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

import eth_utils
from genlayer_py import create_account, create_client
from genlayer_py.abi import calldata
from genlayer_py.abi.transactions import serialize
from genlayer_py.chains import testnet_bradbury
from genlayer_py.contracts.actions import _encode_add_transaction_data
from genlayer_py.contracts.utils import make_calldata_object
from genlayer_py.exceptions import GenLayerError
from genlayer_py.types import TransactionHashVariant, TransactionStatus
from web3.constants import ADDRESS_ZERO
from web3.exceptions import TimeExhausted
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


class RpcUnavailable(OSError):
    """The RPC gave no answer: a gateway 5xx or 429, an HTML page instead of
    JSON-RPC, a dropped connection or a timeout.

    Distinct from an answer, even an error answer: after one of these nobody
    knows whether the node saw the request. An OSError, so every transient()
    in these tools treats it as one.
    """


def _json_rpc(raw):
    """The decoded body if it is a JSON-RPC answer, else None."""
    try:
        answer = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if isinstance(answer, dict) and ("result" in answer or "error" in answer):
        return answer
    return None


def rpc(net, method, params):
    """One JSON-RPC request: the answer, or RpcUnavailable if there was none.

    A JSON-RPC body is an answer whatever the HTTP status it came with. On 24
    September eth_sendRawTransaction got "HTTP Error 522: <none>" from the
    gateway, with no body, and that used to end the send with a traceback.
    """
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(
        net["rpc_url"],
        data=body,
        # The RPC edge answers 403 to urllib's default User-Agent.
        headers={"Content-Type": "application/json", "User-Agent": "lacre/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        try:
            answer = _json_rpc(error.read())
        except (OSError, http.client.HTTPException):
            answer = None
        if answer is not None:
            return answer
        if error.code >= 500 or error.code == 429:
            raise RpcUnavailable("%s: HTTP %d from the gateway" % (method, error.code)) from error
        raise
    except (OSError, http.client.HTTPException) as error:
        raise RpcUnavailable("%s: %s: %s" % (method, type(error).__name__, error)) from error
    answer = _json_rpc(raw)
    if answer is None:
        raise RpcUnavailable("%s: the answer is not JSON-RPC: %r" % (method, raw[:80]))
    return answer


# A read retried after RpcUnavailable: this many requests in all, the pause
# doubling from the first, up to thirty seconds.
READ_ATTEMPTS = 6
READ_PAUSE_S = 2.0


def rpc_read(net, method, params, attempts=READ_ATTEMPTS, sleep=None):
    """rpc() for a request that changes nothing, asked again after no answer."""
    sleep = sleep or time.sleep
    for attempt in range(1, attempts + 1):
        try:
            return rpc(net, method, params)
        except RpcUnavailable as error:
            if attempt == attempts:
                raise
            pause = min(READ_PAUSE_S * 2 ** (attempt - 1), 30.0)
            print("retry        : %s, asking again in %.0f s, attempt %d of %d"
                  % (error, pause, attempt + 1, attempts))
            sleep(pause)


# Bradbury refuses a raw transaction when the node is at capacity: error
# -32005, "transaction gas rate limit exceeded: node is at capacity, retry in
# ~1659ms", data {"retryAfterMs":1659}. Nothing reaches the chain, so the same
# signed bytes, same nonce and same hash, are broadcast again after the delay
# the node asks for. They are never signed again.
RATE_LIMITED = -32005
BROADCAST_ATTEMPTS = 8
RETRY_MARGIN_S = 0.5
_RETRY_AFTER_MS = re.compile(r"retryAfterMs\W*(\d+)")
_RETRY_IN_MS = re.compile(r"retry in ~?\s*(\d+)\s*ms")

# How many times a wait resumes on the same hash after a transient RPC
# failure, and the first pause, which doubles up to two minutes.
WAIT_ATTEMPTS = 6
WAIT_PAUSE_S = 10.0


def retry_after(error):
    """Seconds a refused broadcast asks to wait before trying again.

    0.0 when the refusal says to retry without saying when, and None when it
    is not a refusal that invites a retry.
    """
    if not isinstance(error, dict):
        return None
    text = json.dumps(error, sort_keys=True)
    match = _RETRY_AFTER_MS.search(text) or _RETRY_IN_MS.search(text)
    if match:
        return int(match.group(1)) / 1000.0
    if error.get("code") == RATE_LIMITED or str(RATE_LIMITED) in text or "retry in" in text:
        return 0.0
    return None


# Answers that mean the node already holds these exact bytes: an earlier send
# whose answer was lost got through. Geth says "already known", Nethermind
# "AlreadyKnown", others "known transaction" or "already imported".
_ALREADY_KNOWN = re.compile(r"already known|alreadyknown|already imported|known transaction|"
                            r"already in (the )?(mem)?pool", re.I)
# The nonce is spent. By this transaction, if an earlier send got through and
# was mined; by another one otherwise. Only the hash lookup can tell which.
_NONCE_TOO_LOW = re.compile(r"nonce too low|nonce has already been used|noncetoolow", re.I)

# The first pause after no answer at all, doubling up to thirty seconds.
TRANSPORT_PAUSE_S = 2.0


def l2_known(net, l2_hash, sleep=None):
    """Whether the node knows an L2 transaction, mined or pending.

    None when that cannot be found out: the lookup got no answer either.
    Read-only; eth_getTransactionByHash on the locally computed hash.
    """
    try:
        out = rpc_read(net, "eth_getTransactionByHash", [l2_hash], sleep=sleep)
    except RpcUnavailable:
        return None
    if out.get("error"):
        return None
    return out.get("result") is not None


def broadcast(net, raw, l2_hash, attempts=BROADCAST_ATTEMPTS, sleep=None):
    """eth_sendRawTransaction of one signed transaction; the hash it went as.

    The same signed bytes can be sent any number of times and become at most
    one transaction: the node takes them once, then says it already knows
    them, or that their nonce is too low once they are mined. So they are
    sent again, unchanged, after a refusal that asks for a retry (-32005,
    "node is at capacity") and after no answer at all (a gateway 5xx, an HTML
    page, a dropped connection, a timeout), up to attempts sends in all.
    "Already known" is success. A spent nonce is success if l2_hash is known
    to the node, and otherwise dies at once, like every other refusal.

    When the attempts run out the hash is looked up, read-only, before dying:
    if the node knows it, the send went through and this returns. The death
    message says "not sent" only when the lookup says the node does not know
    it, and "outcome unknown" when the lookup got no answer either.
    """
    sleep = sleep or time.sleep
    reason = None
    for attempt in range(1, attempts + 1):
        try:
            out = rpc(net, "eth_sendRawTransaction", [raw])
        except RpcUnavailable as error:
            reason = "no answer (%s)" % (error,)
            pause = min(TRANSPORT_PAUSE_S * 2 ** (attempt - 1), 30.0)
            what = "broadcast got %s" % (reason,)
        else:
            error = out.get("error")
            if not error:
                return out["result"]
            message = str(error.get("message"))
            if _ALREADY_KNOWN.search(json.dumps(error)):
                print("note         : the node already has %s (%s); continuing as sent"
                      % (l2_hash, message))
                return l2_hash
            delay = retry_after(error)
            if delay is None:
                if _NONCE_TOO_LOW.search(json.dumps(error)):
                    if l2_known(net, l2_hash, sleep=sleep):
                        print("note         : %s, and %s is on chain: an earlier send "
                              "got through; continuing as sent" % (message, l2_hash))
                        return l2_hash
                    die("broadcast refused: %s; %s is not on chain, so another "
                        "transaction holds this nonce" % (message, l2_hash))
                die("broadcast refused: %s" % (message,))
            reason = "refused: %s" % (message,)
            pause = delay + RETRY_MARGIN_S if delay else min(2.0 ** (attempt - 1), 30.0)
            what = "broadcast refused (code %s)" % (error.get("code"),)
        if attempt == attempts:
            break
        print("retry        : %s, sending the same signed transaction again in "
              "%.1f s, attempt %d of %d" % (what, pause, attempt + 1, attempts))
        sleep(pause)

    known = l2_known(net, l2_hash, sleep=sleep)
    if known:
        print("note         : the last answer was %s, but %s is on chain; "
              "continuing as sent" % (reason, l2_hash))
        return l2_hash
    if known is None:
        die("broadcast outcome unknown: %s after %d sends, and %s could not be "
            "looked up; it may have been sent" % (reason, attempts, l2_hash))
    die("not sent: %s after %d sends; %s is not on chain" % (reason, attempts, l2_hash))


def transient(error):
    """A dropped connection or an unreadable answer, not an answer.

    genlayer-py wraps both in GenLayerError: "Request to ... failed" for a
    connection that broke, "... returned invalid JSON" for a body that is not
    JSON, such as a gateway's HTML error page. A revert is an answer.
    """
    if isinstance(error, OSError):
        return True
    if isinstance(error, GenLayerError):
        message = str(error)
        return message.startswith("Request to") or "returned invalid JSON" in message
    return False


def resilient(fn, what, attempts=WAIT_ATTEMPTS, pause=WAIT_PAUSE_S, sleep=None, also=()):
    """fn(), called again after a transient failure, up to attempts times.

    For reads, and for waits on a hash that is already known: calling again
    resumes the same wait, it sends nothing. also names more exception
    types to treat as transient here, such as a wait that timed out.
    """
    sleep = sleep or time.sleep
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except Exception as error:
            if not (transient(error) or isinstance(error, also)) or attempt == attempts:
                raise
            wait = min(pause * 2 ** (attempt - 1), 120.0)
            print("retry        : %s failed (%s), resuming in %.0f s, attempt %d of %d"
                  % (what, type(error).__name__, wait, attempt + 1, attempts))
            sleep(wait)


def wait_accepted(client, tx_id, sleep=None):
    """The SDK receipt once a consensus transaction is decided.

    genlayer-py returns on ACCEPTED or on any decided state. A transient RPC
    failure resumes the wait on the same tx id instead of losing it: on 24
    September a deploy that had succeeded died on a gateway 520 here and
    never printed its address.
    """
    return resilient(
        lambda: client.wait_for_transaction_receipt(
            transaction_hash=tx_id,
            status=TransactionStatus.ACCEPTED,
            interval=POLL_INTERVAL_MS,
            retries=POLL_RETRIES,
        ),
        "the wait for %s" % (tx_id,),
        sleep=sleep,
    )


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
    # Both read from the node; nothing is signed or sent yet.
    client = resilient(lambda: create_client(chain=chain, account=account), "connect")
    resilient(client.initialize_consensus_smart_contract, "reading the consensus contracts")

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


def deploy_calldata(client, account, code, args=None):
    """Exactly what genlayer_py.contracts.actions.deploy_contract builds.

    args are the constructor's, encoded the same way a write's are: a
    contract whose __init__ takes an address is deployed with it here.
    """
    data = [
        code,
        calldata.encode(make_calldata_object(method=None, args=args or [], kwargs=None)),
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
    out = rpc_read(
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


def send(net, client, account, encoded, estimated_gas, value=0, nonce=None):
    """Sign, broadcast, print the L2 hash, then return the consensus tx id.

    nonce pins the nonce a send must use, for a send that repeats one whose
    outcome was "not sent": if the account has moved past it, something with
    that nonce reached the chain after all, and this dies before signing
    rather than send the same call a second time under the next nonce.
    """
    consensus = client.chain.consensus_main_contract["address"]
    cap = net["max_tx_gas"]
    multiplier = net["gas_multiplier"]
    gas = min(estimated_gas * multiplier, cap)
    if gas < estimated_gas:
        die("estimate %d already exceeds the cap %d" % (estimated_gas, cap))

    latest = resilient(lambda: client.w3.eth.get_block("latest"), "reading the latest block")
    count = resilient(lambda: client.w3.eth.get_transaction_count(account.address),
                      "reading the nonce")
    if nonce is not None and nonce != count:
        if nonce < count:
            die("nonce %d is already used (the account is at %d): an earlier send "
                "with it reached the chain; nothing was signed" % (nonce, count))
        die("nonce %d is ahead of the account, which is at %d; nothing was signed"
            % (nonce, count))
    priority = client.w3.to_wei(2, "gwei")
    transaction = {
        "from": account.address,
        "nonce": count,
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

    sent = broadcast(net, raw, l2_hash)
    if sent.lower() != l2_hash.lower():
        print("note         : node returned a different hash: %s" % (sent,))

    print("waiting for the L2 receipt ...")
    # A wait that runs out resumes too: the transaction is known to the node
    # and waiting again sends nothing.
    receipt = resilient(
        lambda: client.w3.eth.wait_for_transaction_receipt(sent, timeout=300),
        "the wait for the L2 receipt of %s" % (sent,), also=(TimeExhausted,))
    used = receipt["gasUsed"]
    price = receipt.get("effectiveGasPrice", 0)
    print("L2 status    : %d (%s)"
          % (receipt["status"], "success" if receipt["status"] == 1 else "REVERTED"))
    print("L2 gasUsed   : %d of %d" % (used, gas))
    print("L2 cost      : %d wei" % (used * price,))
    if receipt["status"] != 1:
        die("the L2 transaction reverted; nothing reached consensus")

    found = created_transaction(client.w3, client.chain.consensus_main_contract["abi"],
                                receipt)
    if found is None:
        die("L2 succeeded but emitted neither %s" % (" nor ".join(CREATION_EVENTS),))
    consensus_id, event = found
    print("CONSENSUS TX : %s" % (consensus_id,))
    print("created by   : %s%s" % (
        event, " (queued behind an earlier transaction to the same contract)"
        if event == "CreatedTransaction" else ""))
    print("explorer     : %s/tx/%s" % (net["explorer"], consensus_id))
    return consensus_id, used


# The two events ConsensusMain emits for the transaction an addTransaction
# creates. NewTransaction when it is activated at once; CreatedTransaction,
# with no activator, when the recipient already has an undecided transaction
# and the new one is queued behind it. Measured on Bradbury on 24 September
# 2026. genlayer-py 0.16.3 looks only for the first and gives up on a queued
# transaction that is on chain and will run.
CREATION_EVENTS = ("NewTransaction", "CreatedTransaction")


def created_transaction(w3, abi, receipt):
    """(consensus tx id, event name) for the transaction a receipt created.

    None if the receipt carries neither creation event.
    """
    contract = w3.eth.contract(abi=abi)
    for event in CREATION_EVENTS:
        found = contract.get_event_by_name(event).process_receipt(receipt, DISCARD)
        if found:
            return w3.to_hex(found[0]["args"]["txId"]), event
    return None


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
    response = rpc_read(net, "gen_call", [gen_call_params(client, address, method, args)])
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
