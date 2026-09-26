#!/usr/bin/env python3
"""Drive contracts/verifier/verifier.py against a stubbed SDK.

The built contract is executed as written, with a stand-in for the parts of
the runner it touches: storage maps, gl.message and its value, the balance,
the equivalence principle, the web fetch, the cross-contract views on the
Router and the KeyCache, and the external message path. Nothing is deployed, no gas is spent
and no value moves, so the whole state machine, including the paths a testnet
run would need a second sender or a tampered blob to reach, is exercised in
under a second.

The blob is the real one: the harness cuts it out of the sample message with
the probe's own make_blob.py, in memory, and hands it to the contract through
the stubbed fetch. It is never written to a file and never printed, and the
key record behind it is fetched over real DNS here rather than by the
contract. The From, duplicate and expiry rules are driven with blobs signed
on the spot by a throwaway RSA key, so every one of them verifies as RSA and
the verdict under test is the contract's own. Run it before a deploy, not in
CI.

Usage:
    python3 tests/verifier_stub_run.py
"""

import base64
import enum
import hashlib
import random
import sys
import types
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "verifier" / "verifier.py"
PROBE = ROOT / "experiments" / "dkim-probe"
MESSAGE = PROBE / "samples" / "amazon-shipped.eml"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(PROBE))

from lacre import dkimcore, dkimkey

# The signature this repository has measured end to end, on chain and off.
DOMAIN = "amazon.com"
SELECTOR = "yg4mwqurec7fkhzutopddd3ytuaqrvuz"
BH = "s++GIS95947DFm6Pyd1o2v947XK/Et+PaGMB12Y4cL0="
BODY_CANON = "simple"
SIGNED_AT = "1790011067"
DOH_URL = "https://dns.google/resolve?name=%s._domainkey.%s&type=TXT"
BLOB_URL = "https://lacre.in-sidr.xyz/stub-run.txt"

# A second registered selector, so that a blob presented under the wrong
# domain gets past the KeyCache and is refused by the signature instead.
OTHER_DOMAIN = "example.com"
OTHER_SELECTOR = "sel"

# The throwaway signer the rule checks are signed with.
SIGNER = "lacre.test"
SIGNER_SUB = "mail.lacre.test"
SIGNER_SELECTOR = "stub"
SIGNER_T = "1790000000"

ROUTER = "0x7777777777777777777777777777777777777777"
KEYCACHE = "0x8888888888888888888888888888888888888888"
KEYCACHE_B = "0x9999999999999999999999999999999999999999"
OWNER = "0x1111111111111111111111111111111111111111"
STRANGER = "0x2222222222222222222222222222222222222222"
TREASURY = "0x3333333333333333333333333333333333333333"
NEW_OWNER = "0x4444444444444444444444444444444444444444"
AGENT = "0xabcdef0123456789abcdef0123456789abcdef01"
ZERO = "0x0000000000000000000000000000000000000000"

GEN = 10 ** 18
FEE = GEN // 1000

NO_L = "body length limit not supported"

# Whatever the runner puts in gl.message_raw["datetime"] is stored unmodified,
# so the harness supplies a string and expects exactly it back.
DATETIME = "2026-09-22T16:35:41.123456+00:00"


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


class StorageType(enum.IntEnum):
    """genlayer.py.public_abi.StorageType, as the pinned std lib defines it."""

    DEFAULT = 0
    LATEST_FINAL = 1
    LATEST_NON_FINAL = 2


class TreeMap(dict):
    """Storage map. dict answers get, items, len and "in" the same way."""

    def get_or_insert_default(self, key):
        # The one map that uses it holds DynArray[str], whose default is empty.
        return self.setdefault(key, [])


class UserError(Exception):
    pass


@dataclass
class Response:
    status: int
    body: bytes


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


class KeyCache:
    """The KeyCache as the Verifier sees it: one view, one method.

    gl.get_contract_at(addr).view().key_status(...) returns the record as
    calldata decodes it, a plain dict of strings, or {} for an unknown key.
    """

    def __init__(self):
        self.records = {}
        self.calls = []
        self.states = []
        self.broken = False

    def add(self, domain, selector, key, state="active"):
        self.records[(domain, selector)] = {
            "domain": domain,
            "selector": selector,
            "state": state,
            "n_hex": "%x" % (key["n"],),
            "e": str(key["e"]),
            "key_bits": str(key["key_bits"]),
            "key_sha256": key["sha256"],
            "first_seen": DATETIME,
            "activated_at": DATETIME if state != "pending" else "",
            "refreshed_at": "",
        }

    def view(self, *, state=StorageType.LATEST_NON_FINAL):
        self.states.append(state)
        return self

    def key_status(self, domain, selector):
        self.calls.append((domain, selector))
        if self.broken:
            raise RuntimeError("the KeyCache reverted")
        return dict(self.records.get((domain, selector), {}))


class Router:
    """The Router as the Verifier sees it: resolve() and nothing else."""

    def __init__(self, names):
        self.names = dict(names)
        self.states = []
        self.broken = False

    def view(self, *, state=StorageType.LATEST_NON_FINAL):
        self.states.append(state)
        return self

    def resolve(self, name):
        if self.broken:
            raise RuntimeError("the Router reverted")
        return self.names.get(name, "")


class Node:
    """The chain's side: who is calling, with what, and what is served."""

    def __init__(self, router, caches):
        self.sender = Address(OWNER)
        self.value = 0
        self.balance = 0
        self.router = router
        self.caches = caches
        self.blob = b""
        self.status = 200
        self.urls = []
        self.internal = []
        self.external = []

    def get(self, url, headers=None):
        self.urls.append(url)
        return Response(status=self.status, body=self.blob)

    def strict_eq(self, fn):
        # Two independent runs, compared exactly, which is what the leader and
        # a validator do. A probe that is not deterministic fails here.
        leader, validator = fn(), fn()
        if leader != validator:
            raise AssertionError("probe is not deterministic")
        return leader

    def contract_at(self, address):
        """gl.get_contract_at: the internal, contract to contract path."""
        if not isinstance(address, Address):
            raise TypeError("address expected")
        if address == Address(ROUTER):
            return self.router
        for cache, stub in self.caches.items():
            if address == Address(cache):
                return stub
        raise AssertionError("the contract reached an address it should not")

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
        eq_principle=types.SimpleNamespace(strict_eq=node.strict_eq),
        nondet=types.SimpleNamespace(web=types.SimpleNamespace(get=node.get)),
        evm=types.SimpleNamespace(contract_interface=node.evm_interface),
        get_contract_at=node.contract_at,
        message_raw={"datetime": DATETIME},
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


def load_contract(node):
    sys.modules["genlayer"] = build_sdk(node)
    sys.modules["genlayer.py"] = types.ModuleType("genlayer.py")
    public_abi = types.ModuleType("genlayer.py.public_abi")
    public_abi.StorageType = StorageType
    sys.modules["genlayer.py.public_abi"] = public_abi
    module = types.ModuleType("verifier")
    module.__file__ = str(CONTRACT)
    exec(compile(CONTRACT.read_text(encoding="ascii"), str(CONTRACT), "exec"),
         module.__dict__)

    contract = module.Contract.__new__(module.Contract)
    for name, annotation in module.Contract.__annotations__.items():
        if getattr(annotation, "__origin__", annotation) is TreeMap:
            setattr(contract, name, TreeMap())
    contract.__init__(ROUTER)
    return contract


def build_blob():
    """The signed headers, cut out of the sample message in memory.

    Nothing from the message is written or printed: this is the same blob the
    gateway would serve, and it exists only for the length of this run.
    """
    from make_blob import build_blob as cut

    if not MESSAGE.is_file():
        sys.exit("%s is not here; samples are not tracked" % (MESSAGE,))
    return cut(MESSAGE.read_bytes(), DOMAIN)


def fetch_key(domain, selector):
    url = DOH_URL % (selector, domain)
    request = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(request, timeout=20) as response:
        payload = response.read().decode("utf-8", "replace")
    tags = dkimkey.key_tags(dkimkey.txt_from_doh(payload))
    key = dkimkey.key_from_tags(tags)
    key["sha256"] = hashlib.sha256(key["der"]).hexdigest()
    return key


def generate_key(bits=1024, seed=6376):
    """A throwaway RSA key, seeded so a run is reproducible. Test use only."""
    rng = random.Random(seed)

    def prime(size):
        while True:
            candidate = rng.getrandbits(size) | (1 << (size - 1)) | 1
            if all(pow(rng.randrange(2, candidate - 1), candidate - 1, candidate) == 1
                   for _ in range(24)) and candidate % 65537 != 1:
                return candidate

    p, q = prime(bits // 2), prime(bits // 2)
    n, e = p * q, 65537
    return {
        "n": n, "e": e, "d": pow(e, -1, (p - 1) * (q - 1)),
        "key_bits": n.bit_length(), "sha256": hashlib.sha256(b"%x" % (n,)).hexdigest(),
    }


def sign(key, headers, names, extra="", domain=SIGNER):
    """A blob whose DKIM-Signature really verifies against key.

    headers are whole lines in message order; the signature goes on top, the
    way a relay prepends it, and signs names bottom up per RFC 6376 5.4.2.
    """
    head = ("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=%s;"
            " s=%s;%s h=%s; bh=%s; b=" % (domain, SIGNER_SELECTOR, extra,
                                          ":".join(names), BH))
    unsigned = (head + "\r\n" + "".join(line + "\r\n" for line in headers)).encode()
    fields = dkimcore.parse_headers(unsigned)
    digest = dkimcore.DIGESTINFO + dkimcore.sha256(
        dkimcore.signed_data(fields, 0, names))
    size = (key["n"].bit_length() + 7) // 8
    block = b"\x00\x01" + b"\xff" * (size - len(digest) - 3) + b"\x00" + digest
    value = pow(int.from_bytes(block, "big"), key["d"], key["n"]).to_bytes(size, "big")
    return unsigned.replace(b"b=\r\n", b"b=" + base64.b64encode(value) + b"\r\n", 1)


def verifies(key, blob):
    """The RSA verdict alone, before any of the contract's own rules."""
    return dkimcore.verify_headers(blob, key["n"], key["e"])[0]


def unix(text):
    return int(datetime.fromisoformat(text).timestamp())


def call(node, sender, wei, method, *args):
    """One paying call. The value is credited before the call and stays
    credited if it raises: a payable call that reverts inside the contract
    keeps what it carried, measured on Bradbury."""
    node.sender = Address(sender)
    node.value = wei
    node.balance += wei
    try:
        return method(*args)
    finally:
        node.value = 0


def attest(contract, node, sender, wei, url, domain, selector):
    return call(node, sender, wei, contract.attest, url, domain, selector)


class Report:
    def __init__(self):
        self.failed = 0
        self.total = 0

    def check(self, label, condition, detail=""):
        self.total += 1
        print("%-4s %-58s %s" % ("ok" if condition else "FAIL", label, detail))
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
    if not CONTRACT.is_file():
        sys.exit("%s does not exist; run contracts/verifier/build.py first" % (CONTRACT,))

    blob = build_blob()
    key = fetch_key(DOMAIN, SELECTOR)
    signer = generate_key()
    cache = KeyCache()
    cache.add(DOMAIN, SELECTOR, key)
    cache.add(OTHER_DOMAIN, OTHER_SELECTOR, key)
    cache.add(SIGNER, SIGNER_SELECTOR, signer)
    cache.add(SIGNER_SUB, SIGNER_SELECTOR, signer)
    router = Router({"keycache": KEYCACHE})
    other_cache = KeyCache()

    node = Node(router, {KEYCACHE: cache, KEYCACHE_B: other_cache})
    node.blob = blob
    contract = load_contract(node)

    print("contract     : %s (%d bytes)"
          % (CONTRACT.relative_to(ROOT), len(CONTRACT.read_bytes())))
    print("blob         : %d bytes, built in memory from the sample" % (len(blob),))
    print("key          : %s._domainkey.%s, %d bits, e=%d"
          % (SELECTOR, DOMAIN, key["key_bits"], key["e"]))
    print("test signer  : %s._domainkey.%s, %d bits, throwaway"
          % (SIGNER_SELECTOR, SIGNER, signer["key_bits"]))
    print("owner        : %s" % (OWNER,))
    print("fee          : %d wei\n" % (FEE,))

    report = Report()

    def refused(label, reason, send):
        """A deterministic rejection, driven with value and without.

        The refund is the half that exists only when the call carried
        something, so both halves have to be driven to see the rule.
        """
        for wei in (FEE, 0):
            stored, queued = contract.count(), len(node.external)
            answer = send(wei)
            report.check("%s%s" % (label, "" if wei else ", carrying nothing"),
                         answer == reason and contract.last_refusal(STRANGER) == reason,
                         answer)
            report.check("  refunds %s and stores nothing"
                         % ("the %d wei whole" % (wei,) if wei else "nothing",),
                         node.external[queued:] == ([(STRANGER, {"value": wei})]
                                                    if wei else [])
                         and contract.count() == stored,
                         str(node.external[queued:]))
    report.check("owner() is the deployer", contract.owner() == OWNER, contract.owner())
    report.check("router() is the constructor argument",
                 contract.router() == ROUTER.lower(), contract.router())
    report.check("treasury() starts as the owner", contract.treasury() == OWNER)
    report.check("fee() starts at zero and nothing is stored",
                 contract.fee() == 0 and contract.count() == 0)
    report.check("the removed methods are gone",
                 not any(hasattr(contract, name) for name in (
                     "check", "latest_by_bh", "fees_collected", "set_treasury",
                     "registry")))
    report.check("records_of and last_refusal start empty",
                 contract.records_of(STRANGER) == [] and contract.last_refusal(STRANGER) == "")

    # The happy path, free, the way the contract is deployed.
    first = attest(contract, node, STRANGER, 0, BLOB_URL, DOMAIN.upper(), SELECTOR)
    record = contract.get(first)
    report.check("attest returns the first id", first == "0", first)
    report.check("the record is valid", record.get("valid") is True,
                 record.get("reason"))
    report.check("bh is the one the signature claims", record.get("bh") == BH,
                 record.get("bh"))
    report.check("body_canon is the c= body mode",
                 record.get("body_canon") == BODY_CANON, record.get("body_canon"))
    report.check("the domain and selector are lowercased",
                 record.get("domain") == DOMAIN and record.get("selector") == SELECTOR)
    report.check("key_bits and key_sha256 come from the Registry",
                 record.get("key_bits") == "1024"
                 and record.get("key_sha256") == key["sha256"],
                 record.get("key_sha256", "")[:16] + "...")
    report.check("the Message-ID is present only as a digest",
                 len(record.get("message_id_sha256", "")) == 64)
    report.check("the From domain is recorded, not the address",
                 record.get("from_domain") == DOMAIN, record.get("from_domain"))
    report.check("the real blob is aligned", record.get("aligned") is True)
    report.check("signed_at is the t= value",
                 record.get("signed_at") == SIGNED_AT, record.get("signed_at"))
    report.check("source is url", record.get("source") == "url")
    report.check("the requester is the sender",
                 record.get("requester") == STRANGER, record.get("requester"))
    report.check("attested_at is the runner datetime",
                 record.get("attested_at") == DATETIME)
    report.check("fee_paid is what rode on the call",
                 record.get("fee_paid") == "0")
    report.check("the record carries the schema version",
                 record.get("schema_version") == "2", str(record.get("schema_version")))
    report.check("records_of lists it for its requester",
                 contract.records_of(STRANGER) == ["0"] and contract.records_of(OWNER) == [],
                 str(contract.records_of(STRANGER)))
    report.check("records_of reads any spelling of the address",
                 contract.records_of("0x" + STRANGER[2:].upper()) == ["0"])
    report.check("records_of of a malformed address is empty",
                 contract.records_of("not an address") == [])
    report.check("the contract fetched the URL it was given",
                 set(node.urls) == {BLOB_URL}, "%d fetches" % (len(node.urls),))
    report.check("it found the KeyCache through the Router",
                 router.states == [StorageType.LATEST_FINAL], str(router.states))
    report.check("and read the key from it, not from DNS",
                 cache.calls == [(DOMAIN, SELECTOR)], str(cache.calls))
    report.check("from finalized KeyCache state",
                 cache.states == [StorageType.LATEST_FINAL], str(cache.states))
    report.check("count() is one", contract.count() == 1)

    report.check("check_for() accepts the record for its requester",
                 contract.check_for(first, DOMAIN, 1024, STRANGER) is True)
    report.check("check_for() refuses a different requester",
                 contract.check_for(first, DOMAIN, 1024, OWNER) is False)
    report.check("check_for() refuses a stronger key than the record has",
                 contract.check_for(first, DOMAIN, 2048, STRANGER) is False)
    report.check("check_for() refuses another domain",
                 contract.check_for(first, OTHER_DOMAIN, 1024, STRANGER) is False)
    report.check("check_for() refuses an id that does not exist",
                 contract.check_for("404", DOMAIN, 1024, STRANGER) is False)
    report.check("get() of an unknown id is empty", contract.get("404") == {})

    # The same blob, presented as evidence for a domain it was not signed for.
    mismatch = attest(contract, node, STRANGER, 0, BLOB_URL,
                      OTHER_DOMAIN, OTHER_SELECTOR)
    record = contract.get(mismatch)
    report.check("a blob under the wrong domain is not valid",
                 record.get("valid") is False)
    report.check("and says so",
                 record.get("reason") == "signature does not match domain or selector",
                 record.get("reason"))
    report.check("check_for() refuses it",
                 contract.check_for(mismatch, OTHER_DOMAIN, 0, STRANGER) is False)

    # One byte of a signed header, which is what a forgery looks like.
    tampered = blob.replace(b"Date: Mon", b"Date: Tue", 1)
    if tampered == blob:
        sys.exit("the tamper did not change the blob; the sample has moved")
    node.blob = tampered
    forged = attest(contract, node, STRANGER, 0, BLOB_URL, DOMAIN, SELECTOR)
    record = contract.get(forged)
    report.check("a tampered blob is stored, not reverted", record != {})
    report.check("it is not valid", record.get("valid") is False,
                 record.get("reason"))
    report.check("the same message keeps the same Message-ID digest",
                 record.get("message_id_sha256") == contract.get(first).get(
                     "message_id_sha256"))
    report.check("check_for() refuses it",
                 contract.check_for(forged, DOMAIN, 1024, STRANGER) is False)
    node.blob = blob

    # A URL the gateway no longer serves: an answer, not a failed write.
    node.status = 404
    missing = attest(contract, node, STRANGER, 0, BLOB_URL, DOMAIN, SELECTOR)
    record = contract.get(missing)
    report.check("an unserved blob is a stored reason",
                 record.get("valid") is False and record.get("reason") == "blob HTTP 404",
                 record.get("reason"))
    report.check("with no bh", record.get("bh") == "")
    node.status = 200

    # A blob that is served but carries no signature at all.
    node.blob = b"Subject: nothing is signed here\r\n"
    bare = attest(contract, node, STRANGER, 0, BLOB_URL, DOMAIN, SELECTOR)
    record = contract.get(bare)
    report.check("a blob with no signature is a stored reason",
                 record.get("reason") == "no DKIM-Signature in the blob",
                 record.get("reason"))
    report.check("with no body_canon to apply", record.get("body_canon") == "")

    # A served blob over the cap is a stored reason, not a revert.
    node.blob = blob + b"X-Pad: " + b"x" * 16384 + b"\r\n"
    large = attest(contract, node, STRANGER, 0, BLOB_URL, DOMAIN, SELECTOR)
    record = contract.get(large)
    report.check("a fetched blob over 16384 bytes is a stored reason",
                 record.get("valid") is False and record.get("reason") == "blob too large",
                 record.get("reason"))
    node.blob = blob

    # The URL is checked before anything else, so nothing is fetched or stored.
    fetches = len(node.urls)
    long_url = "https://lacre.in-sidr.xyz/" + "a" * (513 - len("https://lacre.in-sidr.xyz/"))
    refused("a URL without https is refused", "url not allowed",
            lambda wei: attest(contract, node, STRANGER, wei,
                               "http://lacre.in-sidr.xyz/stub-run.txt",
                               DOMAIN, SELECTOR))
    refused("a URL over 512 characters is refused", "url not allowed",
            lambda wei: attest(contract, node, STRANGER, wei, long_url,
                               DOMAIN, SELECTOR))
    report.check("and none of them fetched anything", len(node.urls) == fetches)
    edge = attest(contract, node, STRANGER, 0, long_url[:512], DOMAIN, SELECTOR)
    report.check("a URL of exactly 512 characters is accepted",
                 contract.get(edge).get("valid") is True)

    # Signed with a throwaway key: every blob below verifies as RSA, so each
    # verdict is the contract's own rule and not a broken signature.
    base = ["Date: Mon, 21 Sep 2026 10:00:00 +0000",
            "From: Test <alerts@%s>" % (SIGNER,),
            "To: someone@example.org",
            "Subject: stub"]
    signed_names = ["from", "to", "subject", "date"]

    def run(label, headers, names=signed_names, extra=" t=%s;" % (SIGNER_T,),
            domain=SIGNER, above=b""):
        signed = sign(signer, headers, names, extra, domain)
        node.blob = above + signed
        record = contract.get(attest(contract, node, STRANGER, 0, BLOB_URL,
                                     domain, SIGNER_SELECTOR))
        node.blob = blob
        return verifies(signer, signed), record

    rsa, record = run("aligned", base)
    aligned_id = str(contract.count() - 1)
    report.check("a synthetic signed blob is valid and aligned",
                 rsa and record.get("valid") is True and record.get("aligned") is True,
                 record.get("reason"))
    report.check("its signed_at is its own t=", record.get("signed_at") == SIGNER_T)
    report.check("check_for() accepts it",
                 contract.check_for(aligned_id, SIGNER, 1024, STRANGER) is True)

    rsa, record = run("sub", [base[0], "From: <x@mail.%s>" % (SIGNER,)] + base[2:])
    report.check("a From subdomain of d= is aligned (relaxed)",
                 rsa and record.get("valid") is True and record.get("aligned") is True,
                 record.get("from_domain"))

    rsa, record = run("parent", base, domain=SIGNER_SUB)
    parent_id = str(contract.count() - 1)
    report.check("d= a subdomain of the From domain is aligned",
                 rsa and record.get("valid") is True and record.get("aligned") is True,
                 "d=%s from=%s" % (SIGNER_SUB, record.get("from_domain")))
    report.check("check_for() accepts it",
                 contract.check_for(parent_id, SIGNER_SUB, 1024, STRANGER) is True)
    rsa, record = run("parent other", [base[0], "From: <x@%s>" % (OTHER_DOMAIN,)] + base[2:],
                      domain=SIGNER_SUB)
    report.check("d= a subdomain of an unrelated From is not aligned",
                 rsa and record.get("aligned") is False, record.get("from_domain"))
    rsa, record = run("sibling", [base[0], "From: <x@news.%s>" % (SIGNER,)] + base[2:],
                      domain=SIGNER_SUB)
    report.check("sibling subdomains of one parent are not aligned",
                 rsa and record.get("aligned") is False, record.get("from_domain"))

    # Several signatures: the one for the call's domain and selector is used.
    decoy = sign(signer, base, signed_names, "", "decoy.example").split(b"\r\n", 1)[0] + b"\r\n"
    rsa, record = run("second", base, above=decoy)
    report.check("with a decoy signature on top, the matching second one is verified",
                 rsa and record.get("valid") is True and record.get("aligned") is True,
                 record.get("reason"))
    report.check("and its tags are the ones recorded",
                 record.get("signed_at") == SIGNER_T and record.get("from_domain") == SIGNER)
    node.blob = decoy + blob
    record = contract.get(attest(contract, node, STRANGER, 0, BLOB_URL, DOMAIN, SELECTOR))
    node.blob = blob
    report.check("the real blob under a decoy signature still verifies",
                 record.get("valid") is True and record.get("bh") == BH, record.get("reason"))
    other = sign(signer, base, signed_names, "", "other.example").split(b"\r\n", 1)[0]
    node.blob = decoy + other + b"\r\n" + sign(signer, base, signed_names, "", "third.example")
    record = contract.get(attest(contract, node, STRANGER, 0, BLOB_URL, SIGNER, SIGNER_SELECTOR))
    node.blob = blob
    report.check("three signatures, none for the call, is a stored reason",
                 record.get("valid") is False
                 and record.get("reason") == "signature does not match domain or selector",
                 record.get("reason"))
    report.check("with nothing taken from any of them",
                 record.get("bh") == "" and record.get("from_domain") == "")

    rsa, record = run("other", [base[0], "From: Bank <x@%s>" % (OTHER_DOMAIN,)] + base[2:])
    other_id = str(contract.count() - 1)
    report.check("a From domain other than d= verifies but is not aligned",
                 rsa and record.get("valid") is True and record.get("aligned") is False,
                 record.get("from_domain"))
    report.check("check_for() refuses the misaligned record",
                 contract.check_for(other_id, SIGNER, 1024, STRANGER) is False)

    rsa, record = run("lookalike", [base[0], "From: <x@evil%s>" % (SIGNER,)] + base[2:])
    report.check("a From that only ends in the d= text is not aligned",
                 rsa and record.get("aligned") is False, record.get("from_domain"))

    rsa, record = run("quoted", [base[0], 'From: "x@%s" <x@%s>' % (SIGNER, OTHER_DOMAIN)]
                      + base[2:])
    report.check("an address in the display name does not count",
                 rsa and record.get("aligned") is False, record.get("from_domain"))

    rsa, record = run("unsigned from", base, ["to", "subject", "date"])
    report.check("From absent from h= is invalid",
                 rsa and record.get("valid") is False
                 and record.get("reason") == "from not signed", record.get("reason"))

    # An extra copy above the signed one: RSA still verifies, the reader sees
    # the top one, so the contract has to refuse it.
    rsa, record = run("dup from", [base[0], "From: <ceo@%s>" % (OTHER_DOMAIN,)] + base[1:])
    report.check("a duplicated From verifies as RSA but is invalid",
                 rsa and record.get("valid") is False
                 and record.get("reason") == "duplicate signed header", record.get("reason"))
    rsa, record = run("dup subject", base[:3] + ["Subject: urgent"] + base[3:])
    report.check("a duplicated Subject is invalid too",
                 rsa and record.get("reason") == "duplicate signed header",
                 record.get("reason"))
    rsa, record = run("oversigned", base, signed_names + ["from"])
    report.check("h= naming From twice over one From is still valid",
                 rsa and record.get("valid") is True, record.get("reason"))

    now = unix(DATETIME)
    rsa, record = run("expired", base, extra=" t=%s; x=%d;" % (SIGNER_T, now - 60))
    report.check("an x= in the past is invalid",
                 rsa and record.get("valid") is False
                 and record.get("reason") == "signature expired", record.get("reason"))
    rsa, record = run("current", base, extra=" t=%s; x=%d;" % (SIGNER_T, now + 60))
    report.check("an x= in the future is valid", rsa and record.get("valid") is True,
                 record.get("reason"))
    rsa, record = run("no t", base, extra="")
    report.check("signed_at is 0 when t= is absent",
                 rsa and record.get("signed_at") == "0", record.get("signed_at"))

    # Inline: the same verdict, no fetch, the blob rides in calldata.
    fetches, stored = len(node.urls), contract.count()
    inline = call(node, AGENT, 0, contract.attest_inline,
                  blob.decode("ascii"), DOMAIN, SELECTOR)
    record = contract.get(inline)
    report.check("attest_inline of the real blob is valid and aligned",
                 record.get("valid") is True and record.get("aligned") is True,
                 record.get("reason"))
    report.check("its source is inline", record.get("source") == "inline")
    report.check("it records what attest records",
                 all(record.get(k) == contract.get(first).get(k) for k in (
                     "bh", "body_canon", "message_id_sha256", "from_domain", "signed_at")))
    report.check("and fetched nothing", len(node.urls) == fetches)
    report.check("check_for() accepts it for its requester",
                 contract.check_for(inline, DOMAIN, 1024, AGENT) is True)
    report.check("check_for() compares addresses, not their spelling",
                 contract.check_for(inline, DOMAIN, 1024, "0x" + AGENT[2:].upper()) is True)
    report.check("check_for() refuses the requester of another record",
                 contract.check_for(inline, DOMAIN, 1024, STRANGER) is False)
    report.check("check_for() returns False for a malformed requester",
                 all(contract.check_for(inline, DOMAIN, 1024, bad) is False
                     for bad in ("not an address", "0x1234", "", AGENT + "00")))
    refused("attest_inline of a blob over 16384 bytes is refused", "blob too large",
            lambda wei: call(node, STRANGER, wei, contract.attest_inline,
                             "x" * 16385, DOMAIN, SELECTOR))
    report.check("and the run stored only the inline record",
                 contract.count() == stored + 1)

    # A key the KeyCache does not hold, and one in each state that is not
    # active: each is refused with its own reason.
    fetches = len(node.urls)
    refused("an unregistered key is refused", "key not registered",
            lambda wei: attest(contract, node, STRANGER, wei, BLOB_URL,
                               "notregistered.example", SELECTOR))
    for state in ("pending", "rotated", "retired"):
        cache.add(OTHER_DOMAIN, OTHER_SELECTOR, key, state=state)
        refused("a %s key is refused" % (state,), "key " + state,
                lambda wei: attest(contract, node, STRANGER, wei, BLOB_URL,
                                   OTHER_DOMAIN, OTHER_SELECTOR))
    cache.add(OTHER_DOMAIN, OTHER_SELECTOR, key, state="unheard of")
    refused("a state the Verifier does not know is not registered", "key not registered",
            lambda wei: attest(contract, node, STRANGER, wei, BLOB_URL,
                               OTHER_DOMAIN, OTHER_SELECTOR))
    cache.add(OTHER_DOMAIN, OTHER_SELECTOR, key)
    report.check("and none of them fetched anything", len(node.urls) == fetches)

    # The Router and the KeyCache are read on every call, and any failure to
    # read them is a refusal with a refund, never a revert.
    router.names = {}
    refused("a Router that resolves no keycache is refused", "router resolves no keycache",
            lambda wei: attest(contract, node, STRANGER, wei, BLOB_URL, DOMAIN, SELECTOR))
    router.names = {"keycache": KEYCACHE}
    router.broken = True
    refused("a Router that cannot be read is refused", "router unreadable",
            lambda wei: attest(contract, node, STRANGER, wei, BLOB_URL, DOMAIN, SELECTOR))
    router.broken = False
    cache.broken = True
    refused("a KeyCache that cannot be read is refused", "keycache unreadable",
            lambda wei: attest(contract, node, STRANGER, wei, BLOB_URL, DOMAIN, SELECTOR))
    cache.broken = False
    router.names = {"keycache": "not an address"}
    refused("a Router naming something that is not an address is refused",
            "keycache unreadable",
            lambda wei: attest(contract, node, STRANGER, wei, BLOB_URL, DOMAIN, SELECTOR))
    report.check("and none of them fetched anything", len(node.urls) == fetches)

    # The KeyCache moves behind the Router with no new Verifier: the next
    # call reads the new one, which does not hold this key yet.
    router.names = {"keycache": KEYCACHE_B}
    refused("after the Router moves, the new KeyCache is read", "key not registered",
            lambda wei: attest(contract, node, STRANGER, wei, BLOB_URL, DOMAIN, SELECTOR))
    other_cache.add(DOMAIN, SELECTOR, key)
    moved = attest(contract, node, STRANGER, 0, BLOB_URL, DOMAIN, SELECTOR)
    report.check("and a key registered there attests",
                 contract.get(moved).get("valid") is True
                 and other_cache.calls[-1] == (DOMAIN, SELECTOR), moved)
    router.names = {"keycache": KEYCACHE}

    # l= is refused with a refund, on the agreed verdict, by URL and inline.
    stored, queued = contract.count(), len(node.external)
    limited = sign(signer, base, signed_names, " t=%s; l=0;" % (SIGNER_T,))
    report.check("the l= blob verifies as RSA", verifies(signer, limited))
    node.blob = limited
    refused("a signature with l= is refused", NO_L,
            lambda wei: attest(contract, node, STRANGER, wei, BLOB_URL,
                               SIGNER, SIGNER_SELECTOR))
    node.blob = blob
    refused("a signature with l= is refused inline too", NO_L,
            lambda wei: call(node, STRANGER, wei, contract.attest_inline,
                             limited.decode("ascii"), SIGNER, SIGNER_SELECTOR))
    report.check("the URL path fetched before refusing",
                 len(node.urls) > fetches, "%d fetches" % (len(node.urls) - fetches,))
    report.check("no l= record was written", contract.count() == stored)
    decoy_l = sign(signer, base, signed_names, " l=0;", "decoy.example").split(b"\r\n", 1)[0]
    rsa, record = run("l on another signature", base, above=decoy_l + b"\r\n")
    report.check("l= on a signature that is not the selected one is ignored",
                 rsa and record.get("valid") is True, record.get("reason"))

    # last_refusal is per requester and keeps the last refusal only; a
    # recorded call does not clear it.
    report.check("last_refusal keeps the latest reason", contract.last_refusal(STRANGER) == NO_L)
    report.check("and is empty for a requester never refused",
                 contract.last_refusal(AGENT) == ""
                 and contract.last_refusal("not an address") == "")
    report.check("records_of lists every id the requester wrote, in order",
                 contract.records_of(STRANGER)
                 == [str(i) for i in range(contract.count()) if i != int(inline)],
                 "%d ids" % (len(contract.records_of(STRANGER)),))
    report.check("and the inline one under its own requester",
                 contract.records_of(AGENT) == [inline])

    # normalize() empties a name it cannot use, and an empty name is not a
    # lookup worth making, so these are refused before the Registry is read.
    reads, fetches = len(router.states), len(node.urls)
    refused("a domain over 253 characters is refused", "bad domain or selector",
            lambda wei: attest(contract, node, STRANGER, wei, BLOB_URL,
                               "a" * 254, SELECTOR))
    refused("a selector over 63 characters is refused", "bad domain or selector",
            lambda wei: attest(contract, node, STRANGER, wei, BLOB_URL,
                               DOMAIN, "s" * 64))
    refused("an empty domain is refused", "bad domain or selector",
            lambda wei: attest(contract, node, STRANGER, wei, BLOB_URL,
                               "   ", SELECTOR))
    report.check("and none of them read the Router or fetched anything",
                 len(router.states) == reads and len(node.urls) == fetches)
    report.check("a domain of exactly 253 characters still reaches the KeyCache",
                 attest(contract, node, STRANGER, 0, BLOB_URL, "a" * 253,
                        SELECTOR) == "key not registered")
    report.check("every Router and KeyCache read asked for finalized state",
                 set(router.states + cache.states + other_cache.states)
                 == {StorageType.LATEST_FINAL},
                 "%d reads" % (len(router.states + cache.states + other_cache.states),))

    # The fee.
    node.sender = Address(STRANGER)
    report.raises("set_fee by a stranger raises", lambda: contract.set_fee(FEE))
    node.sender = Address(OWNER)
    report.raises("a negative fee raises", lambda: contract.set_fee(-1))
    report.check("set_fee by the owner takes", contract.set_fee(FEE) == str(FEE))
    report.check("fee() reports it", contract.fee() == FEE)

    stored, queued = contract.count(), len(node.external)
    fetched, reads = len(node.urls), len(router.states)
    short = attest(contract, node, STRANGER, FEE - 1, BLOB_URL, DOMAIN, SELECTOR)
    report.check("attest under the fee answers instead of reverting",
                 short == "fee not paid" and contract.last_refusal(STRANGER) == short, short)
    report.check("the whole underpayment is queued back to the sender",
                 node.external[queued:] == [(STRANGER, {"value": FEE - 1})],
                 str(node.external[queued:]))
    short = call(node, STRANGER, FEE - 1, contract.attest_inline,
                 blob.decode("ascii"), DOMAIN, SELECTOR)
    report.check("attest_inline under the fee answers the same way",
                 short == "fee not paid", short)
    report.check("and refunds its sender too",
                 node.external[queued:] == [(STRANGER, {"value": FEE - 1})] * 2,
                 "%d queued" % (len(node.external) - queued,))
    report.check("neither one stored a record", contract.count() == stored)
    report.check("and neither one read the Router or fetched the blob",
                 len(router.states) == reads and len(node.urls) == fetched)
    short = call(node, STRANGER, 0, contract.attest_inline,
                 blob.decode("ascii"), DOMAIN, SELECTOR)
    report.check("a call carrying nothing is refused with nothing to refund",
                 short == "fee not paid" and len(node.external) == queued + 2,
                 short)
    report.check("and stored nothing either", contract.count() == stored)
    refunds = list(node.external)

    paid = attest(contract, node, STRANGER, FEE, BLOB_URL, DOMAIN, SELECTOR)
    report.check("attest at the fee goes through",
                 contract.get(paid).get("valid") is True)
    report.check("fee_paid is recorded on the record",
                 contract.get(paid).get("fee_paid") == str(FEE))
    over = call(node, STRANGER, 2 * FEE, contract.attest_inline,
                blob.decode("ascii"), DOMAIN, SELECTOR)
    report.check("more than the fee is accepted and recorded whole",
                 contract.get(over).get("fee_paid") == str(2 * FEE))

    # The treasury moves in two steps, like ownership.
    report.check("pending_treasury starts empty", contract.pending_treasury() == "")
    node.sender = Address(STRANGER)
    report.raises("propose_treasury by a stranger raises",
                  lambda: contract.propose_treasury(STRANGER), "owner only")
    report.raises("withdraw by a stranger raises", lambda: contract.withdraw(FEE),
                  "owner only")
    report.check("and queues nothing",
                 node.external == refunds and node.internal == [])

    node.sender = Address(OWNER)
    report.raises("the zero address cannot be proposed as treasury",
                  lambda: contract.propose_treasury(ZERO))
    report.check("propose_treasury by the owner stores the candidate",
                 contract.propose_treasury(TREASURY) == TREASURY)
    report.check("pending_treasury reports it", contract.pending_treasury() == TREASURY)
    report.check("the treasury has not moved yet", contract.treasury() == OWNER)

    node.sender = Address(STRANGER)
    report.raises("accept_treasury by a stranger raises", contract.accept_treasury,
                  "pending treasury only")
    node.sender = Address(OWNER)
    report.raises("accept_treasury by the owner raises", contract.accept_treasury,
                  "pending treasury only")
    report.check("the treasury still has not moved", contract.treasury() == OWNER)
    node.sender = Address(TREASURY)
    report.check("accept_treasury by the proposed address takes it",
                 contract.accept_treasury() == TREASURY)
    report.check("treasury() is the new address", contract.treasury() == TREASURY)
    report.check("pending_treasury is cleared again", contract.pending_treasury() == "")
    report.raises("a second accept_treasury raises", contract.accept_treasury,
                  "pending treasury only")
    report.raises("the treasury cannot withdraw", lambda: contract.withdraw(FEE),
                  "owner only")

    node.sender = Address(OWNER)
    report.raises("withdraw of zero raises", lambda: contract.withdraw(0))
    report.raises("withdraw of more than the balance raises",
                  lambda: contract.withdraw(node.balance + 1))
    report.check("still nothing queued", node.external == refunds)

    held = node.balance
    report.check("withdraw by the owner returns the amount",
                 contract.withdraw(held) == str(held))
    report.check("one external transfer is queued to the treasury",
                 node.external == refunds + [(TREASURY, {"value": held})],
                 str(node.external[len(refunds):]))
    report.check("it went out through the EVM interface, not an internal message",
                 node.internal == [])
    report.check("the balance does not move inside the call", node.balance == held)

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
    report.raises("accept_owner by a stranger raises", contract.accept_owner,
                  "pending owner only")
    node.sender = Address(OWNER)
    report.raises("accept_owner by the current owner raises", contract.accept_owner)
    node.sender = Address(NEW_OWNER)
    report.check("accept_owner by the pending owner takes it",
                 contract.accept_owner() == NEW_OWNER)
    report.check("owner() is the new owner", contract.owner() == NEW_OWNER)
    report.check("pending_owner is cleared again", contract.pending_owner() == "")
    report.check("the new owner can set the fee", contract.set_fee(0) == "0")
    node.sender = Address(OWNER)
    report.raises("the old owner cannot", lambda: contract.set_fee(FEE))

    print("\n%d checks, %d failed" % (report.total, report.failed))
    sys.exit(1 if report.failed else 0)


if __name__ == "__main__":
    main()
