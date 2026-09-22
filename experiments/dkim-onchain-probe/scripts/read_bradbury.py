#!/usr/bin/env python3
"""Read one stored attestation from a deployed dkim probe on Bradbury.

Both methods are views, so this costs no gas, but genlayer-py still needs a
connected account to fill the `from` field of gen_call.

Usage:
    export PROBE_PK=0x<64 hex chars>
    python3 scripts/read_bradbury.py <CONTRACT_ADDRESS> <RECORD_ID>
    python3 scripts/read_bradbury.py <CONTRACT_ADDRESS> all
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import bradbury
import eth_utils
from genlayer_py.abi import calldata
from genlayer_py.abi.transactions import serialize
from genlayer_py.contracts.utils import make_calldata_object
from genlayer_py.types import TransactionHashVariant

FIELDS = ("id", "domain", "selector", "bh", "message_id_sha256", "key_bits",
          "valid", "reason")

# A view that could not be read, as distinct from any value it might return.
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
    """read_contract, reporting the RPC error body instead of a TypeError."""
    try:
        return client.read_contract(
            address=address, function_name=function_name, args=args
        )
    except TypeError:
        value = show_rpc_error(client, address, function_name, args)
        if value is UNKNOWN:
            bradbury.die("gen_call did not return a result for %s" % (function_name,))
        return value


def show(client, address, record_id):
    record = read(client, address, "get", [record_id])
    print("record %s:" % (record_id,))
    for key in FIELDS:
        print("  %-18s %s" % (key, record.get(key)))


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    address, wanted = sys.argv[1], sys.argv[2]

    _, client = bradbury.connect()
    total = int(read(client, address, "count", []))
    print("contract     : %s" % (address,))
    print("records      : %d" % (total,))

    if wanted == "all":
        for record_id in range(total):
            print()
            show(client, address, record_id)
        return

    if not wanted.isdigit():
        bradbury.die("record id must be a number or 'all'")
    record_id = int(wanted)
    if record_id >= total:
        bradbury.die("record %d does not exist; the contract holds %d" % (record_id, total))
    print()
    show(client, address, record_id)


if __name__ == "__main__":
    main()
