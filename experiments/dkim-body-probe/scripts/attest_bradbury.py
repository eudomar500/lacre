#!/usr/bin/env python3
"""Send one attest_body(body_url, bh_claimed) write to a deployed body probe.

The URL and the bh= tag are the only things that reach calldata. The body
behind that URL is read by the leader and by every validator inside the
non-deterministic block, and only the canonical string is agreed on and
stored: the claimed hash, the computed hash, whether they match, the byte
count, whether an order id was present, the weekday, whether the text says the
order shipped, and a reason.

bh_claimed is the bh= tag of the signature that covers this body, and
make_body.py prints the hash to compare it with before you spend anything.

Usage:
    export PROBE_PK=0x<64 hex chars>
    python3 scripts/attest_bradbury.py <CONTRACT_ADDRESS> <BODY_URL> <BH_CLAIMED>
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import bradbury
import eth_utils
from bradbury import POLL_INTERVAL_MS, POLL_RETRIES
from genlayer_py.abi import calldata
from genlayer_py.abi.transactions import serialize
from genlayer_py.contracts.utils import make_calldata_object
from genlayer_py.types import TransactionHashVariant, TransactionStatus

FIELDS = ("bh_claimed", "bh_computed", "match", "body_bytes", "order_id_found",
          "eta_day", "shipped", "reason")

# A view that could not be read. Distinct from a count of zero, which is a
# perfectly good answer.
UNKNOWN = object()


def gen_call_params(client, address, function_name, args):
    """Exactly the gen_call params genlayer_py.read_contract builds."""
    data = [
        calldata.encode(
            make_calldata_object(method=function_name, args=args, kwargs=None)
        ),
        b"\x00",
    ]
    return {
        "type": "read",
        "to": address,
        "from": client.local_account.address,
        "data": serialize(data),
        "transaction_hash_variant": TransactionHashVariant.LATEST_NONFINAL.value,
    }


def show_rpc_error(client, address, function_name, args):
    """Recover the result genlayer_py could not read, or report why not.

    Bradbury answers gen_call with {"result": {"data": "<hex>", "status":
    {"code": 0, ...}, ...}}, while genlayer_py 0.16.3 expects result to be a
    bare hex string and dies on the concatenation with the body still intact.
    Repeating the identical request raw recovers it: on status.code 0 the
    payload is decoded exactly as read_contract decodes its own hex, and
    anything else prints the whole response and fails the read.
    """
    response = bradbury.rpc(
        "gen_call", [gen_call_params(client, address, function_name, args)]
    )
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
            print("%s(%s) returned status 0 but its data did not decode: %s"
                  % (function_name, ", ".join(repr(arg) for arg in args),
                     type(error).__name__))
            print(json.dumps(response, indent=2, default=str))
            return UNKNOWN

    print("%s(%s) did not return a readable result. Raw gen_call response:"
          % (function_name, ", ".join(repr(arg) for arg in args)))
    print(json.dumps(response, indent=2, default=str))
    return UNKNOWN


def read(client, address, function_name, args):
    """read_contract, returning UNKNOWN instead of raising on an RPC error."""
    try:
        return client.read_contract(
            address=address, function_name=function_name, args=args
        )
    except TypeError:
        return show_rpc_error(client, address, function_name, args)


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    address, body_url, bh_claimed = sys.argv[1], sys.argv[2], sys.argv[3]
    if not body_url.startswith("http://") and not body_url.startswith("https://"):
        bradbury.die("body_url must be http or https")
    bh_claimed = "".join(bh_claimed.split())
    if not bh_claimed:
        bradbury.die("bh_claimed is empty")

    account, client = bradbury.connect()
    print("contract     : %s" % (address,))
    print("body url     : %s" % (body_url,))
    print("bh claimed   : %s" % (bh_claimed,))
    print("sender       : %s" % (account.address,))

    before = read(client, address, "count", [])
    if before is UNKNOWN:
        print("records now  : unknown, going ahead with the write anyway")
    else:
        print("records now  : %s" % (before,))

    encoded = bradbury.write_calldata(
        client, account, address, "attest_body", [body_url, bh_claimed]
    )
    gas = bradbury.estimate(client, account, encoded, final=False)

    print("\nsubmitting attest_body transaction ...")
    started = time.time()
    tx_id, l2_gas = bradbury.send(client, account, encoded, gas)

    print("\nwaiting for ACCEPTED (up to %d minutes) ..."
          % (POLL_RETRIES * POLL_INTERVAL_MS // 60000,))
    receipt = client.wait_for_transaction_receipt(
        transaction_hash=tx_id,
        status=TransactionStatus.ACCEPTED,
        interval=POLL_INTERVAL_MS,
        retries=POLL_RETRIES,
    )
    elapsed = time.time() - started

    bradbury.show_receipt(receipt)
    print("L2 gasUsed   : %d" % (l2_gas,))
    print("wall time    : %.0f s to %s" % (elapsed, receipt.get("status_name")))
    print("\ntear the tunnel down now: the body is personal data. See serve.md")

    after = read(client, address, "count", [])
    if after is UNKNOWN:
        print("the record count could not be read back; the transaction above")
        print("still reached %s. Retry with:" % (receipt.get("status_name"),))
        print("  python3 scripts/read_bradbury.py %s all" % (address,))
        return
    print("records now  : %s" % (after,))
    if before is not UNKNOWN and int(after) <= int(before):
        print("no new record; the write did not reach the deterministic block")
        return

    record_id = int(after) - 1
    record = read(client, address, "get", [record_id])
    if record is UNKNOWN:
        return
    print("\nrecord %d:" % (record_id,))
    for key in FIELDS:
        print("  %-18s %s" % (key, record.get(key)))


if __name__ == "__main__":
    main()
