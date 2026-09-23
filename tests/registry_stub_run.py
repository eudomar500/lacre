#!/usr/bin/env python3
"""Drive contracts/registry/registry.py against a stubbed SDK.

The built contract is executed as written, with a stand-in for the parts of
the runner it touches: storage maps, gl.message, the equivalence principle and
the web fetch. Nothing is deployed and no gas is spent, so the whole state
machine, including the paths that a testnet run would need a revoked key or a
second sender to reach, is exercised in under a second.

The key record is fetched once over real DNS here, by this harness, and handed
to the contract through the stubbed fetch: the contract itself never reaches
the network. Run it before a deploy, not in CI.

Usage:
    python3 tests/registry_stub_run.py
"""

import json
import sys
import types
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "registry" / "registry.py"

# A live 1024 bit RSA selector, the one the on-chain probe verified against.
DOMAIN = "amazon.com"
SELECTOR = "yg4mwqurec7fkhzutopddd3ytuaqrvuz"
DOH_URL = "https://dns.google/resolve?name=%s._domainkey.%s&type=TXT"

OWNER = "0x1111111111111111111111111111111111111111"
STRANGER = "0x2222222222222222222222222222222222222222"
VERIFIER = "0x3333333333333333333333333333333333333333"
NEW_OWNER = "0x4444444444444444444444444444444444444444"
ZERO = "0x0000000000000000000000000000000000000000"

# Whatever the runner puts in gl.message_raw["datetime"] is stored unmodified,
# so the harness supplies a string and expects exactly it back.
DATETIME = "2026-09-22T16:35:41.123456+00:00"

# A record with p= present but empty: RFC 6376 section 3.6.1, a revoked key.
REVOKED = (
    '{"Status":0,"Answer":[{"name":"sel._domainkey.example.com.","type":16,'
    '"TTL":300,"data":"\\"v=DKIM1; k=rsa; p=\\""}]}'
)


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
    """Storage map. dict answers get, items, len and "in" the same way."""


class UserError(Exception):
    pass


@dataclass
class Response:
    status: int
    body: bytes


class Message:
    """gl.message, following the sender the harness is acting as."""

    def __init__(self, node):
        self._node = node

    @property
    def sender_address(self):
        return self._node.sender


class Node:
    """The validator the contract runs on, and the record of what it asked."""

    def __init__(self):
        self.sender = Address(OWNER)
        self.body = b""
        self.urls = []

    def get(self, url, headers=None):
        self.urls.append(url)
        return Response(status=200, body=self.body)

    def strict_eq(self, fn):
        # Two independent runs, compared exactly, which is what the leader and
        # a validator do. A probe that is not deterministic fails here.
        leader, validator = fn(), fn()
        if leader != validator:
            raise AssertionError("probe is not deterministic")
        return leader


def build_sdk(node):
    """A genlayer module with the names the contract imports."""
    gl = types.SimpleNamespace(
        Contract=type("Contract", (), {}),
        message=Message(node),
        public=types.SimpleNamespace(write=lambda fn: fn, view=lambda fn: fn),
        vm=types.SimpleNamespace(UserError=UserError),
        eq_principle=types.SimpleNamespace(strict_eq=node.strict_eq),
        nondet=types.SimpleNamespace(web=types.SimpleNamespace(get=node.get)),
        message_raw={"datetime": DATETIME},
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
    module = types.ModuleType("registry")
    module.__file__ = str(CONTRACT)
    exec(compile(CONTRACT.read_text(encoding="ascii"), str(CONTRACT), "exec"), module.__dict__)

    contract = module.Contract.__new__(module.Contract)
    for name, annotation in module.Contract.__annotations__.items():
        if getattr(annotation, "__origin__", annotation) is TreeMap:
            setattr(contract, name, TreeMap())
    contract.__init__()
    return contract


def fetch_key_record():
    url = DOH_URL % (SELECTOR, DOMAIN)
    request = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return url, response.read()


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
        sys.exit("%s does not exist; run contracts/registry/build.py first" % (CONTRACT,))

    url, body = fetch_key_record()
    answer = json.loads(body)
    node = Node()
    node.body = body
    contract = load_contract(node)

    print("contract     : %s (%d bytes)" % (CONTRACT.relative_to(ROOT), len(CONTRACT.read_bytes())))
    print("key record   : %s._domainkey.%s" % (SELECTOR, DOMAIN))
    print("doh answer   : %d bytes, Status %s, %d answers"
          % (len(body), answer.get("Status"), len(answer.get("Answer") or [])))
    print("owner        : %s\n" % (OWNER,))

    report = Report()
    report.check("owner() is the deployer", contract.owner() == OWNER, contract.owner())

    stored = contract.set_version("verifier", VERIFIER)
    report.check("set_version stores a pointer", stored == VERIFIER, stored)
    report.check("version() resolves it", contract.version("VERIFIER") == VERIFIER)
    report.check("all_versions() lists it",
                 contract.all_versions() == {"verifier": VERIFIER},
                 str(contract.all_versions()))

    node.sender = Address(STRANGER)
    report.raises("set_version by a stranger raises",
                  lambda: contract.set_version("verifier", STRANGER))

    # Registering is open to anyone: it costs the sender the gas and stores a
    # fact about a public DNS record.
    result = contract.register_key(DOMAIN.upper(), SELECTOR.upper())
    report.check("register_key registers", result == "registered", result)
    # strict_eq runs the probe twice here, once as the leader and once as the
    # validator, so the same URL is fetched once per run.
    report.check("the contract asked the expected resolver",
                 set(node.urls) == {url}, "%d fetches" % (len(node.urls),))

    record = contract.get_key(DOMAIN, SELECTOR)
    report.check("key_bits is 1024", record.get("key_bits") == "1024", str(record.get("key_bits")))
    report.check("e is 65537", record.get("e") == "65537", str(record.get("e")))
    report.check("n_hex is the modulus",
                 len(record.get("n_hex", "")) == 256,
                 record.get("n_hex", "")[:16] + "... (%d hex chars)" % (len(record.get("n_hex", "")),))
    report.check("key_sha256 is a digest of the DER",
                 len(record.get("key_sha256", "")) == 64, record.get("key_sha256"))
    report.check("first_seen is the runner datetime",
                 record.get("first_seen") == DATETIME, record.get("first_seen"))
    report.check("the record is not retired", record.get("retired") is False)
    report.check("has_key and key_count agree",
                 contract.has_key(DOMAIN, SELECTOR) and contract.key_count() == 1)

    fetches = len(node.urls)
    report.check("a second register_key returns exists",
                 contract.register_key(DOMAIN, SELECTOR) == "exists")
    report.check("and does not touch DNS", len(node.urls) == fetches)

    report.raises("retire_key by a stranger raises",
                  lambda: contract.retire_key(DOMAIN, SELECTOR))
    report.check("the record survives the refusal",
                 contract.get_key(DOMAIN, SELECTOR).get("retired") is False)

    node.sender = Address(OWNER)
    report.check("retire_key by the owner returns True",
                 contract.retire_key(DOMAIN, SELECTOR) is True)
    retired = contract.get_key(DOMAIN, SELECTOR)
    report.check("the record is retired and still readable",
                 retired.get("retired") is True and retired.get("key_bits") == "1024")
    report.check("key_count still counts it", contract.key_count() == 1)

    fetches = len(node.urls)
    report.check("registering a retired key returns retired",
                 contract.register_key(DOMAIN, SELECTOR) == "retired")
    report.check("and neither re-reads DNS nor clears the flag",
                 len(node.urls) == fetches
                 and contract.get_key(DOMAIN, SELECTOR).get("retired") is True)

    node.body = REVOKED.encode("ascii")
    result = contract.register_key("example.com", "sel")
    report.check("a revoked key is a reason, not a revert",
                 result == "key revoked or absent", result)
    report.check("and nothing was stored",
                 not contract.has_key("example.com", "sel") and contract.key_count() == 1)

    report.raises("a malformed domain raises",
                  lambda: contract.register_key("not a domain", "sel"))

    # Ownership last: it moves the account the checks above depend on.
    report.check("pending_owner starts empty", contract.pending_owner() == "")
    node.sender = Address(STRANGER)
    report.raises("propose_owner by a stranger raises",
                  lambda: contract.propose_owner(STRANGER))
    node.sender = Address(OWNER)
    report.raises("the zero address cannot be proposed",
                  lambda: contract.propose_owner(ZERO))
    report.check("propose_owner stores the candidate",
                 contract.propose_owner(NEW_OWNER) == NEW_OWNER)
    report.check("pending_owner reports it", contract.pending_owner() == NEW_OWNER)
    report.check("the owner has not changed yet", contract.owner() == OWNER)

    node.sender = Address(STRANGER)
    report.raises("accept_owner by a stranger raises", contract.accept_owner)
    report.check("and the owner still has not changed", contract.owner() == OWNER)
    node.sender = Address(OWNER)
    report.raises("accept_owner by the current owner raises", contract.accept_owner)

    node.sender = Address(NEW_OWNER)
    report.check("accept_owner by the pending owner takes it",
                 contract.accept_owner() == NEW_OWNER)
    report.check("owner() is the new owner", contract.owner() == NEW_OWNER)
    report.check("pending_owner is cleared again", contract.pending_owner() == "")
    report.check("the new owner can write",
                 contract.set_version("extractor", VERIFIER) == VERIFIER)
    node.sender = Address(OWNER)
    report.raises("the old owner cannot",
                  lambda: contract.set_version("extractor", VERIFIER))

    print("\n%d checks, %d failed" % (report.total, report.failed))
    sys.exit(1 if report.failed else 0)


if __name__ == "__main__":
    main()
