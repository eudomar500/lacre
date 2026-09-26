#!/usr/bin/env python3
"""Drive contracts/router/router.py against a stubbed SDK.

The built contract is executed as written, with a stand-in for the parts of
the runner it touches: storage maps, gl.message and the runner datetime.
Nothing is deployed and no gas is spent. The Router reads nothing from the
network, so unlike the Registry and Verifier runs this one needs no DNS and
can run anywhere.

The delay is driven by moving the runner datetime, which is the only clock
the contract has.

Usage:
    python3 tests/router_stub_run.py [path to a built router.py]
"""

import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "router" / "router.py"

OWNER = "0x1111111111111111111111111111111111111111"
STRANGER = "0x2222222222222222222222222222222222222222"
CACHE_A = "0x3333333333333333333333333333333333333333"
CACHE_B = "0x5555555555555555555555555555555555555555"
CACHE_C = "0x7777777777777777777777777777777777777777"
VERIFIER = "0x6666666666666666666666666666666666666666"
VERIFIER_B = "0x8888888888888888888888888888888888888888"
NEW_OWNER = "0x4444444444444444444444444444444444444444"
ZERO = "0x0000000000000000000000000000000000000000"

# Proposed at T0; the delay is 48 hours, so T0 + 48 h is the first moment a
# change may apply. The first address of a name is not a change and does not
# wait. The spellings differ on purpose: the runner datetime is
# read by position, with or without a fraction or a zone.
T0 = "2026-09-26T10:00:00.250000+00:00"
EARLY = "2026-09-28T09:59:59Z"
DUE = "2026-09-28T10:00:00Z"
T0_UNIX = 1790416800


class Address:
    """The SDK Address, reduced to what the contract touches.

    The real as_hex is EIP-55 checksummed; lower case is enough to compare.
    """

    def __init__(self, value):
        if isinstance(value, Address):
            raw = value._raw
        elif isinstance(value, (bytes, bytearray)):
            raw = bytes(value)
        else:
            text = str(value).strip()
            raw = bytes.fromhex(text[2:] if text.startswith("0x") else text)
        if len(raw) != 20:
            raise ValueError("invalid address")
        self._raw = raw

    @property
    def as_hex(self):
        return "0x" + self._raw.hex()

    def __eq__(self, other):
        return isinstance(other, Address) and self._raw == other._raw

    def __hash__(self):
        return hash(self._raw)

    def __repr__(self):
        return self.as_hex


class TreeMap(dict):
    """Storage map. dict answers get, items, len, del and "in" the same way."""


class UserError(Exception):
    pass


class Message:
    """gl.message, following the sender the harness is acting as."""

    def __init__(self, node):
        self._node = node

    @property
    def sender_address(self):
        return self._node.sender


class Node:
    def __init__(self):
        self.sender = Address(OWNER)
        self.raw = {"datetime": T0}


def build_sdk(node):
    """A genlayer module with the names the contract imports."""
    gl = types.SimpleNamespace(
        Contract=type("Contract", (), {}),
        message=Message(node),
        public=types.SimpleNamespace(write=lambda fn: fn, view=lambda fn: fn),
        vm=types.SimpleNamespace(UserError=UserError),
        message_raw=node.raw,
    )

    sdk = types.ModuleType("genlayer")
    sdk.__all__ = ["gl", "u256", "Address", "TreeMap", "DynArray", "allow_storage"]
    sdk.gl = gl
    sdk.u256 = int
    sdk.Address = Address
    sdk.TreeMap = TreeMap
    sdk.DynArray = list
    sdk.allow_storage = lambda cls: cls
    return sdk


def load_contract(node, path):
    sys.modules["genlayer"] = build_sdk(node)
    module = types.ModuleType("router")
    module.__file__ = str(path)
    exec(compile(path.read_text(encoding="ascii"), str(path), "exec"), module.__dict__)

    contract = module.Contract.__new__(module.Contract)
    for name, annotation in module.Contract.__annotations__.items():
        origin = getattr(annotation, "__origin__", annotation)
        if origin in (TreeMap, list):
            setattr(contract, name, origin())
    contract.__init__()
    return contract, module


class Report:
    def __init__(self):
        self.failed = 0
        self.total = 0

    def check(self, label, condition, detail=""):
        self.total += 1
        print("%-4s %-52s %s" % ("ok" if condition else "FAIL", label, detail))
        if not condition:
            self.failed += 1

    def raises(self, label, fn, expected=None):
        try:
            fn()
        except UserError as error:
            message = error.args[0]
            self.check(label, expected is None or message == "[EXPECTED] " + expected,
                       message)
            return
        self.check(label, False, "no UserError was raised")


def main():
    path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else CONTRACT
    if not path.is_file():
        sys.exit("%s does not exist; run contracts/router/build.py first" % (path,))

    node = Node()
    contract, module = load_contract(node, path)
    print("contract     : %s (%d bytes)" % (path, len(path.read_bytes())))
    print("owner        : %s" % (OWNER,))
    print("delay        : %d s\n" % (module.DELAY,))

    report = Report()
    report.check("the delay is 48 hours", module.DELAY == 48 * 3600)
    report.check("owner() is the deployer", contract.owner() == OWNER)
    report.check("nothing resolves before anything is set",
                 contract.resolve("keycache") == "" and contract.history("keycache") == []
                 and contract.pending("keycache") == {})
    report.check("the Router has no payable and no key method",
                 not any(hasattr(contract, name) for name in (
                     "register_key", "get_key", "set_fee", "withdraw", "fee")))

    # The first address of a name takes effect at once: nobody can be bound
    # to a name that has never resolved, so there is nobody to warn.
    node.sender = Address(STRANGER)
    report.raises("set_version by a stranger raises, first set included",
                  lambda: contract.set_version("keycache", "v1", CACHE_A), "owner only")
    node.sender = Address(OWNER)
    report.check("and set nothing", contract.resolve("keycache") == "")
    stored = contract.set_version("KeyCache", "V1", CACHE_A)
    report.check("the first set_version returns the address", stored == CACHE_A, stored)
    report.check("the first set resolves at once", contract.resolve("keycache") == CACHE_A)
    report.check("with no pending change", contract.pending("keycache") == {})
    report.check("resolve_pinned() returns it under its label",
                 contract.resolve_pinned("keycache", "v1") == CACHE_A)
    report.check("history() records it with the set time",
                 contract.history("keycache")
                 == [{"version": "v1", "address": CACHE_A, "set_at": T0}],
                 str(contract.history("keycache")))
    report.raises("apply_version after a first set has nothing to apply",
                  lambda: contract.apply_version("keycache"), "nothing pending")

    # Every later change records a pending change and changes nothing else.
    stored = contract.set_version("keycache", "V2", CACHE_B)
    pending = contract.pending("keycache")
    report.check("a second set_version returns the proposed address", stored == CACHE_B, stored)
    report.check("the change is pending",
                 pending.get("version") == "v2" and pending.get("address") == CACHE_B,
                 str(pending))
    report.check("proposed_at is the runner datetime", pending.get("proposed_at") == T0)
    report.check("effective_at is the proposal plus 48 hours",
                 pending.get("effective_at") == T0_UNIX + 48 * 3600,
                 str(pending.get("effective_at")))
    report.check("resolve() does not see a pending change",
                 contract.resolve("keycache") == CACHE_A)
    report.check("nor does resolve_pinned()",
                 contract.resolve_pinned("keycache", "v2") == "")
    report.raises("a second proposal for the same name raises",
                  lambda: contract.set_version("keycache", "v3", CACHE_C),
                  "a change is already pending")

    # The first set of another name is immediate even while this one waits.
    contract.set_version("verifier", "1.2", VERIFIER)
    report.check("a first set of a second name is immediate while another waits",
                 contract.resolve("verifier") == VERIFIER
                 and contract.pending("verifier") == {}
                 and contract.history("verifier")
                 == [{"version": "1.2", "address": VERIFIER, "set_at": T0}])
    report.check("and the other name's change is still pending and unapplied",
                 contract.pending("keycache").get("address") == CACHE_B
                 and contract.resolve("keycache") == CACHE_A)
    contract.set_version("verifier", "1.3", VERIFIER_B)
    report.check("the second set of that name waits in turn",
                 contract.resolve("verifier") == VERIFIER
                 and contract.pending("verifier").get("address") == VERIFIER_B)

    # Too early: one second short of the delay.
    node.raw["datetime"] = EARLY
    node.sender = Address(STRANGER)
    report.raises("apply_version one second early raises",
                  lambda: contract.apply_version("keycache"), "the delay has not passed")
    report.check("and nothing moved",
                 contract.resolve("keycache") == CACHE_A and contract.pending("keycache") != {})

    # Due: anyone may apply it.
    node.raw["datetime"] = DUE
    applied = contract.apply_version("keycache")
    report.check("apply_version by a stranger once due takes it", applied == CACHE_B, applied)
    report.check("resolve() returns it", contract.resolve("KEYCACHE") == CACHE_B)
    report.check("resolve_pinned() returns it under its label",
                 contract.resolve_pinned("keycache", "v2") == CACHE_B)
    report.check("the pending change is cleared", contract.pending("keycache") == {})
    report.check("history() records it with the apply time",
                 contract.history("keycache")
                 == [{"version": "v1", "address": CACHE_A, "set_at": T0},
                     {"version": "v2", "address": CACHE_B, "set_at": DUE}],
                 str(contract.history("keycache")))
    report.raises("apply_version with nothing pending raises",
                  lambda: contract.apply_version("keycache"), "nothing pending")

    # Owner only, for proposing and cancelling.
    report.raises("set_version by a stranger raises",
                  lambda: contract.set_version("keycache", "v3", CACHE_C), "owner only")
    node.sender = Address(OWNER)
    contract.set_version("keycache", "v3", CACHE_C)
    node.sender = Address(STRANGER)
    report.raises("cancel_version by a stranger raises",
                  lambda: contract.cancel_version("keycache"), "owner only")
    node.sender = Address(OWNER)
    report.check("cancel_version by the owner returns the name",
                 contract.cancel_version("keycache") == "keycache")
    report.check("a cancelled change is gone", contract.pending("keycache") == {})
    node.raw["datetime"] = "2026-10-05T00:00:00Z"
    report.raises("and can never be applied",
                  lambda: contract.apply_version("keycache"), "nothing pending")
    report.check("resolve() still returns the applied version",
                 contract.resolve("keycache") == CACHE_B)
    report.raises("cancel_version with nothing pending raises",
                  lambda: contract.cancel_version("keycache"), "nothing pending")

    # A later change does not move a pin. The cancelled v3 left no pin, so
    # the label is free again.
    proposed_at = node.raw["datetime"]
    contract.set_version("keycache", "v3", CACHE_C)
    node.raw["datetime"] = "2026-10-07T00:00:00Z"
    contract.apply_version("keycache")
    report.check("a later change moves resolve()", contract.resolve("keycache") == CACHE_C)
    report.check("resolve_pinned() of the earlier labels is unaffected",
                 contract.resolve_pinned("keycache", "v1") == CACHE_A
                 and contract.resolve_pinned("keycache", "v2") == CACHE_B)
    report.check("and the new label resolves to the new address",
                 contract.resolve_pinned("keycache", "v3") == CACHE_C)
    report.check("history() keeps all three, oldest first",
                 [(h["version"], h["address"]) for h in contract.history("keycache")]
                 == [("v1", CACHE_A), ("v2", CACHE_B), ("v3", CACHE_C)])
    report.check("the third one records when it applied, not when proposed",
                 contract.history("keycache")[2]["set_at"] == "2026-10-07T00:00:00Z"
                 and proposed_at != "2026-10-07T00:00:00Z")

    # A label is bound once. Re-using it for the same address is a rollback
    # and allowed; for another address it would move a pin, so it raises.
    report.raises("a label cannot name another address",
                  lambda: contract.set_version("keycache", "v1", CACHE_B),
                  "version label already names another address")
    contract.set_version("keycache", "v1", CACHE_A)
    report.check("a rollback is a change and waits too",
                 contract.resolve("keycache") == CACHE_C
                 and contract.pending("keycache").get("address") == CACHE_A)
    node.raw["datetime"] = "2026-10-09T00:00:00Z"
    contract.apply_version("keycache")
    report.check("rolling back to a label with its own address works",
                 contract.resolve("keycache") == CACHE_A
                 and contract.resolve_pinned("keycache", "v3") == CACHE_C
                 and len(contract.history("keycache")) == 4)

    # Names are independent of each other.
    report.check("a pending change on one name leaves the other alone",
                 contract.resolve("verifier") == VERIFIER
                 and contract.pending("keycache") == {}
                 and contract.pending("verifier")["address"] == VERIFIER_B)
    report.check("history() is per name",
                 len(contract.history("verifier")) == 1
                 and len(contract.history("keycache")) == 4)

    report.raises("a name that is not a name raises",
                  lambda: contract.set_version("not a name", "v1", CACHE_A))
    report.raises("an empty label raises",
                  lambda: contract.set_version("extractor", " ", CACHE_A),
                  "version label is empty or not a name")
    report.raises("a malformed address raises",
                  lambda: contract.set_version("extractor", "v1", "0x1234"),
                  "not a 20 byte hex address")
    report.check("unknown names resolve to nothing",
                 contract.resolve("nothing") == ""
                 and contract.resolve_pinned("nothing", "v1") == ""
                 and contract.resolve_pinned("keycache", "v9") == "")

    # Ownership last: it moves the account the checks above depend on.
    report.check("pending_owner starts empty", contract.pending_owner() == "")
    node.sender = Address(STRANGER)
    report.raises("propose_owner by a stranger raises",
                  lambda: contract.propose_owner(STRANGER), "owner only")
    node.sender = Address(OWNER)
    report.raises("the zero address cannot be proposed",
                  lambda: contract.propose_owner(ZERO))
    report.check("propose_owner stores the candidate",
                 contract.propose_owner(NEW_OWNER) == NEW_OWNER)
    report.check("the owner has not changed yet", contract.owner() == OWNER)
    node.sender = Address(STRANGER)
    report.raises("accept_owner by a stranger raises", contract.accept_owner,
                  "pending owner only")
    node.sender = Address(NEW_OWNER)
    report.check("accept_owner by the pending owner takes it",
                 contract.accept_owner() == NEW_OWNER and contract.owner() == NEW_OWNER)
    report.check("pending_owner is cleared again", contract.pending_owner() == "")
    report.check("the new owner can cancel", contract.cancel_version("verifier") == "verifier")
    node.sender = Address(OWNER)
    report.raises("the old owner cannot propose",
                  lambda: contract.set_version("verifier", "1.3", VERIFIER_B), "owner only")

    print("\n%d checks, %d failed" % (report.total, report.failed))
    sys.exit(1 if report.failed else 0)


if __name__ == "__main__":
    main()
