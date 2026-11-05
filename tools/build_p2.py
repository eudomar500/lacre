#!/usr/bin/env python3
"""Build the Bradbury Phase 2 versions of the five contracts: contracts/<name>/<name>_p2.py.

Phase 2 runs Consensus v0.6 with GenVM v0.3.0. Its runner header and a handful of std lib
names changed; nothing else did. Each _p2 file is the built contract (contracts/<name>/<name>.py,
from its own build.py) with the Phase 2 header and those names swapped, every swap counted, so
the logic, the inlined modules and every string are byte for byte the same. The names and the
behaviour behind them were read from the GenVM v0.3.0 std lib:

  from genlayer import *                       import genlayer as gl, with the storage and type
                                               names imported from genlayer.storage and genlayer.types
  @allow_storage                               genlayer.storage.allow (imported under the old name)
  from genlayer.py.public_abi import StorageType   from genlayer.contract import StorageView
  StorageType.LATEST_FINAL                     StorageView.LATEST_FINALIZED  (same value, 1)
  (gl.Contract):                               (gl.contract.Contract):
  gl.get_contract_at(                          gl.contract.get_at(  (same proxy: .view(state=...))
  gl.message_raw                               gl.message.raw

gl.public.view/write/write.payable, gl.vm.UserError, gl.message.sender_address and .value,
gl.eq_principle.strict_eq, gl.nondet.web.get, gl.nondet.exec_prompt and gl.evm.contract_interface
keep their names. StorageView was read from the Phase 2 runner itself (py-genlayer babwp9..., not in
any published GenVM release): gen_getContractSchema of a probe contract listed genlayer.contract, where
StorageType is gone and StorageView is an IntEnum DEFAULT=0, LATEST_FINALIZED=1, LATEST_DECIDED=2, and
get_at(...).view(state=..., catch_vm_error=False) defaults to 2. strict_eq, web.get and exec_prompt still return their value (only .lazy()
defers), and the EVM proxy's emit_transfer still takes value= as a keyword.

The Registry is not built: no other contract here, and nothing that uses Lacre, calls it.

Usage:
    python3 tools/build_p2.py           writes the five _p2 files and prints their size and sha256
    python3 tools/build_p2.py --check   only checks that the _p2 files are what this script writes
"""

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("router", "keycache", "verifier", "extractor", "llmextractor")

P2_HEAD = '# v0.3.0\n# { "Depends": "py-genlayer:babwp9t37jw9g4j2bccgn14g6x7x9s1f7dsmh7emvz735pz4zxa0" }'
OLD_HEAD = '# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }'
IMPORTS = ("import genlayer as gl\n"
           "from genlayer.storage import TreeMap, DynArray, allow as allow_storage\n"
           "from genlayer.types import Address, u256")

# (old, new, how many times old may appear: None for any number, at least once)
SWAPS = (
    ("from genlayer import *", IMPORTS, 1),
    ("from genlayer.py.public_abi import StorageType", "from genlayer.contract import StorageView", None),
    ("StorageType.LATEST_FINAL", "StorageView.LATEST_FINALIZED", None),
    ("(gl.Contract):", "(gl.contract.Contract):", 1),
    ("gl.get_contract_at(", "gl.contract.get_at(", None),
    ("gl.message_raw", "gl.message.raw", None),
)
GONE = ("from genlayer import *", "genlayer.py.", "StorageType", "gl.Contract", "gl.get_contract_at", "gl.message_raw")


def build(name):
    built = (ROOT / "contracts" / name / (name + ".py")).read_text(encoding="ascii")
    first, rest = built.split("\n", 1)
    if first != OLD_HEAD:
        sys.exit("%s: unexpected header %r" % (name, first))
    text = P2_HEAD + "\n" + rest
    for old, new, times in SWAPS:
        n = text.count(old)
        if times is not None and n != times:
            sys.exit("%s: %r appears %d times" % (name, old, n))
        text = text.replace(old, new)
    for old in GONE:
        if old in text:
            sys.exit("%s: %r is still there" % (name, old))
    compile(text, name + "_p2", "exec")
    text.encode("ascii")
    return text


def main():
    check = "--check" in sys.argv
    failed = False
    for name in NAMES:
        text = build(name)
        out = ROOT / "contracts" / name / (name + "_p2.py")
        data = text.encode("ascii")
        if check:
            same = out.is_file() and out.read_bytes() == data
            failed |= not same
            print("%-13s %s" % (name, "same" if same else "DIFFERS"))
            continue
        out.write_bytes(data)
        print("%-30s %6d bytes  sha256 %s" % (out.relative_to(ROOT).as_posix(), len(data), hashlib.sha256(data).hexdigest()))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
