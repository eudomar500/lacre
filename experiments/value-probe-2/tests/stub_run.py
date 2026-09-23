#!/usr/bin/env python3
"""Drive contracts/value_probe2.py against a stubbed SDK.

The contract is executed as written, with stand-ins for the parts of the
runner it touches: storage, gl.message, the self balance and both outgoing
message paths. Nothing is deployed and no value moves.

The stub models the chain's side of a payment: the value that rides on a call
is credited to the contract by the node, before the body runs, and a transfer
is queued rather than settled, because it executes on finalization.

Both paths are stubbed and recorded separately, because which one the contract
takes is the whole point of this probe: an internal message through
gl.get_contract_at is contract to contract, and an external message through
the EVM interface is what reaches an address on the chain layer. Probe C took
the first one and moved nothing.

Usage:
    python3 experiments/value-probe-2/tests/stub_run.py
"""

import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTRACT = HERE.parent / "contracts" / "value_probe2.py"

OWNER = "0x1111111111111111111111111111111111111111"
STRANGER = "0x2222222222222222222222222222222222222222"
WALLET = "0x3333333333333333333333333333333333333333"
ZERO = "0x0000000000000000000000000000000000000000"

GEN = 10 ** 18
PAYMENT = GEN // 100


class Address:
    """The SDK Address, reduced to what the contract touches.

    The real as_hex is EIP-55 checksummed. Lower case is enough here, and the
    contract lower cases it anyway before using it as a storage key.
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
    """Storage map. dict answers get and item assignment the same way."""


class UserError(Exception):
    pass


class Message:
    """gl.message, following the call the harness is making."""

    def __init__(self, node):
        self._node = node

    @property
    def sender_address(self):
        return self._node.sender

    @property
    def value(self):
        return self._node.value


class Node:
    """The chain's side: who is calling, with what, and what is held."""

    def __init__(self):
        self.sender = Address(OWNER)
        self.value = 0
        self.balance = 0
        self.internal = []
        self.external = []

    def contract_at(self, address):
        """gl.get_contract_at: the internal, contract to contract path."""
        if not isinstance(address, Address):
            raise TypeError("address expected")
        node = self

        class Proxy:
            def emit_transfer(self, *, value, on="finalized"):
                if value <= 0:
                    raise ValueError("value must be greater than 0")
                node.internal.append((address.as_hex, int(value), on))

        return Proxy()

    def evm_interface(self, declaration):
        """gl.evm.contract_interface: the external path, through the ghost.

        The runner builds the proxy from the View and Write classes, so the
        stub checks they are there rather than silently accepting anything.
        """
        for attribute in ("View", "Write"):
            if not isinstance(getattr(declaration, attribute, None), type):
                raise TypeError("%s needs a %s class" % (declaration, attribute))
        node = self

        class Proxy:
            def __init__(self, address):
                if not isinstance(address, Address):
                    raise TypeError("address expected")
                self._address = address

            def emit_transfer(self, **data):
                # Recorded whole: the real one takes value only and would
                # swallow anything else without a word.
                node.external.append((self._address.as_hex, dict(data)))

        return Proxy


class Write:
    def __call__(self, fn):
        return fn

    def payable(self, fn):
        return fn


def build_sdk(node):
    """A genlayer module with the names the contract imports."""
    gl = types.SimpleNamespace(
        Contract=type("Contract", (), {"balance": property(lambda _: node.balance)}),
        message=Message(node),
        public=types.SimpleNamespace(write=Write(), view=lambda fn: fn),
        vm=types.SimpleNamespace(UserError=UserError),
        get_contract_at=node.contract_at,
        evm=types.SimpleNamespace(contract_interface=node.evm_interface),
    )

    sdk = types.ModuleType("genlayer")
    sdk.__all__ = ["gl", "u256", "Address", "TreeMap", "allow_storage"]
    sdk.gl = gl
    sdk.u256 = int
    sdk.Address = Address
    sdk.TreeMap = TreeMap
    sdk.allow_storage = lambda cls: cls
    return sdk


def load_contract(node):
    sys.modules["genlayer"] = build_sdk(node)
    module = types.ModuleType("value_probe")
    module.__file__ = str(CONTRACT)
    exec(compile(CONTRACT.read_text(encoding="ascii"), str(CONTRACT), "exec"),
         module.__dict__)

    contract = module.Contract.__new__(module.Contract)
    for name, annotation in module.Contract.__annotations__.items():
        if getattr(annotation, "__origin__", annotation) is TreeMap:
            setattr(contract, name, TreeMap())
    contract.__init__()
    return contract


def pay(contract, node, sender, wei):
    """One paying call, credited by the node the way the chain credits it."""
    node.sender = Address(sender)
    node.value = wei
    node.balance += wei
    try:
        return contract.pay()
    finally:
        node.value = 0


class Report:
    def __init__(self):
        self.failed = 0
        self.total = 0

    def check(self, label, condition, detail=""):
        self.total += 1
        print("%-4s %-46s %s" % ("ok" if condition else "FAIL", label, detail))
        if not condition:
            self.failed += 1

    def raises(self, label, fn):
        try:
            fn()
        except UserError as error:
            self.check(label, True, error.args[0])
            return
        self.check(label, False, "no UserError was raised")


def main():
    if not CONTRACT.is_file():
        sys.exit("%s does not exist" % (CONTRACT,))

    node = Node()
    contract = load_contract(node)

    print("contract     : %s (%d bytes)"
          % (CONTRACT.name, len(CONTRACT.read_bytes())))
    print("owner        : %s" % (OWNER,))
    print("payment      : %d wei (0.01 GEN)\n" % (PAYMENT,))

    report = Report()
    report.check("owner() is the deployer", contract.owner() == OWNER, contract.owner())
    report.check("nothing is held yet",
                 contract.total() == 0 and contract.self_balance() == 0)

    returned = pay(contract, node, OWNER, PAYMENT)
    report.check("pay() returns the value it received",
                 returned == str(PAYMENT), returned)
    report.check("total() is that value", contract.total() == PAYMENT)
    report.check("paid_by() credits the sender", contract.paid_by(OWNER) == PAYMENT)
    report.check("self_balance() sees the credit",
                 contract.self_balance() == PAYMENT, str(contract.self_balance()))

    pay(contract, node, OWNER, PAYMENT)
    report.check("a second payment accumulates",
                 contract.total() == 2 * PAYMENT
                 and contract.paid_by(OWNER) == 2 * PAYMENT)

    pay(contract, node, STRANGER, PAYMENT)
    report.check("a second sender is kept apart",
                 contract.paid_by(STRANGER) == PAYMENT
                 and contract.paid_by(OWNER) == 2 * PAYMENT)
    report.check("total() is every payment", contract.total() == 3 * PAYMENT)
    report.check("paid_by() ignores the spelling of an address",
                 contract.paid_by(OWNER.upper().replace("0X", "0x")) == 2 * PAYMENT)
    report.check("paid_by() is zero for an address that never paid",
                 contract.paid_by(WALLET) == 0)
    report.raises("paid_by() refuses a malformed address",
                  lambda: contract.paid_by("not an address"))

    node.sender = Address(STRANGER)
    report.raises("withdraw by a stranger raises",
                  lambda: contract.withdraw(WALLET, PAYMENT))
    report.check("and queues nothing",
                 node.external == [] and node.internal == [])

    node.sender = Address(OWNER)
    report.raises("withdraw of more than the balance raises",
                  lambda: contract.withdraw(WALLET, 4 * PAYMENT))
    report.raises("withdraw of zero raises",
                  lambda: contract.withdraw(WALLET, 0))
    report.raises("withdraw to the zero address raises",
                  lambda: contract.withdraw(ZERO, PAYMENT))
    report.check("still nothing queued",
                 node.external == [] and node.internal == [])

    held = contract.self_balance()
    returned = contract.withdraw(WALLET, held)
    report.check("withdraw by the owner returns the amount",
                 returned == str(held), returned)
    report.check("one external transfer is queued to the wallet",
                 node.external == [(WALLET, {"value": held})], str(node.external))
    report.check("it went out through the EVM interface, not an internal message",
                 node.internal == [], str(node.internal))
    report.check("the balance does not move inside the call",
                 contract.self_balance() == held, str(contract.self_balance()))
    report.check("the paid totals are untouched by a withdrawal",
                 contract.total() == 3 * PAYMENT)

    print("\n%d checks, %d failed" % (report.total, report.failed))
    sys.exit(1 if report.failed else 0)


if __name__ == "__main__":
    main()
