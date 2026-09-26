#!/usr/bin/env python3
"""Drive contracts/keycache/keycache.py against a stubbed SDK.

The built contract is executed as written, with a stand-in for the parts of
the runner it touches: storage maps, gl.message, the runner datetime, the
equivalence principle and the web fetch. Nothing is deployed and no gas is
spent, so the whole state machine, the quarantine included, is exercised in
under a second: the 24 hour wait is a change to the runner datetime.

The key record is fetched once from each of the two resolvers over real DNS
here, by this harness, and handed to the contract through the stubbed fetch:
the contract itself never reaches the network. Run it before a deploy, not in
CI.

Usage:
    python3 tests/keycache_stub_run.py [path to a built keycache.py]
"""

import base64
import json
import sys
import types
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "keycache" / "keycache.py"

# A live 1024 bit RSA selector, the one the on-chain probe verified against.
DOMAIN = "amazon.com"
SELECTOR = "yg4mwqurec7fkhzutopddd3ytuaqrvuz"
RESOLVERS = {
    "dns.google": "https://dns.google/resolve?name=%s._domainkey.%s&type=TXT",
    "cloudflare-dns.com": "https://cloudflare-dns.com/dns-query?name=%s._domainkey.%s&type=TXT",
}

OWNER = "0x1111111111111111111111111111111111111111"
STRANGER = "0x2222222222222222222222222222222222222222"
NEW_OWNER = "0x4444444444444444444444444444444444444444"
ZERO = "0x0000000000000000000000000000000000000000"

# Whatever the runner puts in gl.message_raw["datetime"] is stored unmodified,
# so the harness supplies a string and expects exactly it back. EARLY is one
# second short of the 24 hour quarantine, DUE is exactly on it: the fraction
# of a second is not read.
DATETIME = "2026-09-26T10:00:00.123456+00:00"
EARLY = "2026-09-27T09:59:59Z"
DUE = "2026-09-27T10:00:00Z"
RETRY = "2026-09-27T18:00:00Z"
LATER = "2026-09-28T12:00:00Z"

REVOKED = (
    '{"Status":0,"Answer":[{"name":"sel._domainkey.example.com.","type":16,'
    '"TTL":300,"data":"\\"v=DKIM1; k=rsa; p=\\""}]}'
)
NXDOMAIN = '{"Status":3,"Answer":[]}'
SERVFAIL = '{"Status":2}'


class Address:
    """The SDK Address, reduced to what the contract touches."""

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


class TreeMap(dict):
    """Storage map. dict answers get, items, len, del and "in" the same way."""


class UserError(Exception):
    pass


@dataclass
class Response:
    status: int
    body: bytes


class Message:
    def __init__(self, node):
        self._node = node

    @property
    def sender_address(self):
        return self._node.sender


class Node:
    """The validator the contract runs on, and the record of what it asked."""

    def __init__(self):
        self.sender = Address(OWNER)
        self.bodies = {}
        self.down = set()
        self.urls = []
        self.raw = {"datetime": DATETIME}

    def answer(self, body, **by_host):
        """The same answer from every resolver, unless a host is named."""
        self.bodies = {host: by_host.get(host.split(".")[0].split("-")[0], body) for host in RESOLVERS}
        self.down = set()

    def get(self, url, headers=None):
        self.urls.append(url)
        host = url.split("/")[2]
        if host in self.down:
            raise ConnectionError(host)
        body = self.bodies[host]
        return Response(status=200, body=body if isinstance(body, bytes) else body.encode())

    def strict_eq(self, fn):
        leader, validator = fn(), fn()
        if leader != validator:
            raise AssertionError("probe is not deterministic")
        return leader


def build_sdk(node):
    gl = types.SimpleNamespace(
        Contract=type("Contract", (), {}),
        message=Message(node),
        public=types.SimpleNamespace(write=lambda fn: fn, view=lambda fn: fn),
        vm=types.SimpleNamespace(UserError=UserError),
        eq_principle=types.SimpleNamespace(strict_eq=node.strict_eq),
        nondet=types.SimpleNamespace(web=types.SimpleNamespace(get=node.get)),
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
    module = types.ModuleType("keycache")
    module.__file__ = str(path)
    exec(compile(path.read_text(encoding="ascii"), str(path), "exec"), module.__dict__)

    contract = module.Contract.__new__(module.Contract)
    for name, annotation in module.Contract.__annotations__.items():
        origin = getattr(annotation, "__origin__", annotation)
        if origin in (TreeMap, list):
            setattr(contract, name, origin())
    contract.__init__()
    return contract, module


def fetch_key_record(url):
    request = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read()


def doh_answer(p, chunk=None):
    txt = "v=DKIM1; k=rsa; p=" + p
    if chunk:
        txt = " ".join('\\"%s\\"' % (txt[at:at + chunk],) for at in range(0, len(txt), chunk))
    return '{"Status":0,"Answer":[{"name":"x.","type":16,"TTL":60,"data":"%s"}]}' % (txt,)


def published_p(body):
    data = json.loads(body)["Answer"][-1]["data"].replace('"', "").replace(" ", "")
    return data.split("p=", 1)[1].split(";")[0]


def other_key(p):
    """The same key with one modulus byte flipped: still a valid SPKI."""
    der = bytearray(base64.b64decode(p))
    der[40] ^= 0x01
    return base64.b64encode(bytes(der)).decode("ascii")


class Report:
    def __init__(self):
        self.failed = 0
        self.total = 0

    def check(self, label, condition, detail=""):
        self.total += 1
        print("%-4s %-54s %s" % ("ok" if condition else "FAIL", label, detail))
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
        sys.exit("%s does not exist; run contracts/keycache/build.py first" % (path,))

    urls = {host: url % (SELECTOR, DOMAIN) for host, url in RESOLVERS.items()}
    live = {host: fetch_key_record(url) for host, url in urls.items()}
    node = Node()
    node.bodies = dict(live)
    contract, module = load_contract(node, path)

    print("contract     : %s (%d bytes)" % (path, len(path.read_bytes())))
    print("key record   : %s._domainkey.%s" % (SELECTOR, DOMAIN))
    for host, body in live.items():
        answer = json.loads(body)
        print("resolver     : %s, %d bytes, Status %s, %d answers"
              % (host, len(body), answer.get("Status"), len(answer.get("Answer") or [])))
    print("quarantine   : %d s\n" % (module.QUARANTINE,))

    report = Report()
    report.check("the quarantine is 24 hours", module.QUARANTINE == 24 * 3600)
    report.check("owner() is the deployer", contract.owner() == OWNER)
    report.check("it starts empty", contract.key_count() == 0)
    report.check("the version router and the v1 get_key are not here",
                 not any(hasattr(contract, name) for name in (
                     "set_version", "version", "all_versions", "versions_of", "get_key")))

    # Registration stores the key as pending, read from both resolvers.
    node.sender = Address(STRANGER)
    result = contract.register_key(DOMAIN.upper(), SELECTOR.upper())
    report.check("register_key stores the key as pending", result == "pending", result)
    report.check("the contract asked both resolvers",
                 sorted(node.urls) == sorted(list(urls.values()) * 2),
                 "%d fetches" % (len(node.urls),))
    status = contract.key_status(DOMAIN, SELECTOR)
    report.check("key_status says pending", status.get("state") == "pending")
    report.check("key_bits is 1024 and e is 65537",
                 status.get("key_bits") == "1024" and status.get("e") == "65537")
    report.check("n_hex is the modulus", len(status.get("n_hex", "")) == 256)
    report.check("key_sha256 is a digest of the DER", len(status.get("key_sha256", "")) == 64)
    report.check("first_seen is the runner datetime", status.get("first_seen") == DATETIME)
    report.check("activated_at and refreshed_at are empty",
                 status.get("activated_at") == "" and status.get("refreshed_at") == "")
    report.check("key_status carries every field the Verifier reads",
                 set(status) == {"domain", "selector", "state", "n_hex", "e", "key_bits",
                                 "key_sha256", "first_seen", "activated_at", "refreshed_at"},
                 ", ".join(sorted(status)))
    report.check("has_key and key_count count a pending key",
                 contract.has_key(DOMAIN, SELECTOR) and contract.key_count() == 1)

    fetches = len(node.urls)
    report.check("registering again returns pending and reads nothing",
                 contract.register_key(DOMAIN, SELECTOR) == "pending" and len(node.urls) == fetches)
    report.check("refresh_key leaves a pending key to confirm_key",
                 contract.refresh_key(DOMAIN, SELECTOR) == "pending" and len(node.urls) == fetches)

    # Too early, by one second.
    node.raw["datetime"] = EARLY
    report.raises("confirm_key one second early raises",
                  lambda: contract.confirm_key(DOMAIN, SELECTOR),
                  "the quarantine has not passed")
    report.check("and reads nothing and changes nothing",
                 len(node.urls) == fetches
                 and contract.key_status(DOMAIN, SELECTOR)["state"] == "pending")

    # Due, same key on both resolvers: activated, by anyone.
    node.raw["datetime"] = DUE
    result = contract.confirm_key(DOMAIN, SELECTOR)
    status = contract.key_status(DOMAIN, SELECTOR)
    report.check("confirm_key with the same key activates it", result == "active", result)
    report.check("it re-read both resolvers", len(node.urls) == fetches + 4)
    report.check("activated_at and refreshed_at are the confirm time",
                 status["state"] == "active" and status["activated_at"] == DUE
                 and status["refreshed_at"] == DUE)
    report.check("first_seen is unchanged", status["first_seen"] == DATETIME)
    report.raises("confirming an active key raises",
                  lambda: contract.confirm_key(DOMAIN, SELECTOR), "no pending key")
    report.check("registering an active key returns exists",
                 contract.register_key(DOMAIN, SELECTOR) == "exists")
    report.raises("confirming an unknown key raises",
                  lambda: contract.confirm_key("nowhere.example", "sel"), "no pending key")

    p = published_p(live["dns.google"])

    # The key changed during the quarantine: discarded, failure recorded.
    node.raw["datetime"] = DATETIME
    node.answer(doh_answer(p))
    contract.register_key("swap.example", "sel")
    node.answer(doh_answer(other_key(p)))
    node.raw["datetime"] = DUE
    result = contract.confirm_key("swap.example", "sel")
    report.check("a key that changed in the window is discarded",
                 result == "key changed during quarantine"
                 and not contract.has_key("swap.example", "sel"), result)
    report.check("and the failure is recorded with its time",
                 contract.last_failure("swap.example", "sel")
                 == DUE + " key changed during quarantine",
                 contract.last_failure("swap.example", "sel"))
    report.check("key_status of a discarded key is empty",
                 contract.key_status("swap.example", "sel") == {})
    node.raw["datetime"] = LATER
    report.check("it can be registered again, and waits again",
                 contract.register_key("swap.example", "sel") == "pending"
                 and contract.key_status("swap.example", "sel")["first_seen"] == LATER)

    # A key that disappeared, or resolvers that disagree, at confirm time:
    # both answered, so the answer counts and the key is discarded.
    node.raw["datetime"] = DATETIME
    node.answer(doh_answer(p))
    contract.register_key("gone.example", "sel")
    contract.register_key("outage.example", "sel")
    contract.register_key("split.example", "sel")
    contract.register_key("mixed.example", "sel")
    contract.register_key("turned.example", "sel")
    node.raw["datetime"] = DUE
    node.answer(NXDOMAIN)
    result = contract.confirm_key("gone.example", "sel")
    report.check("a key revoked in the window is discarded",
                 result == "key revoked or absent" and not contract.has_key("gone.example", "sel"),
                 result)
    node.answer(doh_answer(p), cloudflare=doh_answer(other_key(p)))
    result = contract.confirm_key("split.example", "sel")
    report.check("resolvers that disagree at confirm time discard it",
                 result == "resolvers disagree" and not contract.has_key("split.example", "sel"),
                 result)

    # A resolver that cannot be read says nothing about the key: it stays
    # pending, the attempt is recorded, and confirm_key can be called again.
    node.answer(doh_answer(p))
    node.down = {"cloudflare-dns.com"}
    before = contract.key_status("outage.example", "sel")
    result = contract.confirm_key("outage.example", "sel")
    report.check("a resolver down at confirm time keeps the key pending",
                 result == "resolver unavailable: cloudflare-dns.com"
                 and contract.key_status("outage.example", "sel") == before
                 and before["state"] == "pending", result)
    report.check("the quarantine clock does not restart",
                 contract.key_status("outage.example", "sel")["first_seen"] == DATETIME)
    report.check("and the attempt is recorded with its time",
                 contract.last_failure("outage.example", "sel")
                 == DUE + " resolver unavailable: cloudflare-dns.com",
                 contract.last_failure("outage.example", "sel"))
    node.raw["datetime"] = RETRY
    node.answer(doh_answer(p))
    node.down = {"dns.google", "cloudflare-dns.com"}
    result = contract.confirm_key("outage.example", "sel")
    report.check("both resolvers down: still pending, attempt recorded",
                 result == "resolver unavailable: dns.google, cloudflare-dns.com"
                 and contract.key_status("outage.example", "sel")["state"] == "pending"
                 and contract.last_failure("outage.example", "sel")
                 == RETRY + " resolver unavailable: dns.google, cloudflare-dns.com", result)
    node.answer(NXDOMAIN)
    node.down = {"dns.google"}
    result = contract.confirm_key("mixed.example", "sel")
    report.check("one resolver down and one absent is an outage, kept",
                 result == "resolver unavailable: dns.google"
                 and contract.key_status("mixed.example", "sel")["state"] == "pending", result)
    node.raw["datetime"] = LATER
    node.answer(doh_answer(p))
    fetches = len(node.urls)
    result = contract.confirm_key("outage.example", "sel")
    status = contract.key_status("outage.example", "sel")
    report.check("a retry after the outage activates the key",
                 result == "active" and status["state"] == "active", result)
    report.check("it read both resolvers again", len(node.urls) == fetches + 4)
    report.check("activated at the retry, first_seen kept",
                 status["activated_at"] == LATER and status["refreshed_at"] == LATER
                 and status["first_seen"] == DATETIME)
    report.check("last_failure keeps the outage it recovered from",
                 contract.last_failure("outage.example", "sel")
                 == RETRY + " resolver unavailable: dns.google, cloudflare-dns.com")
    node.raw["datetime"] = DUE
    node.down = {"dns.google"}
    contract.confirm_key("turned.example", "sel")
    node.raw["datetime"] = LATER
    node.answer(doh_answer(other_key(p)))
    result = contract.confirm_key("turned.example", "sel")
    report.check("a retry that finds another key discards it",
                 result == "key changed during quarantine"
                 and not contract.has_key("turned.example", "sel")
                 and contract.last_failure("turned.example", "sel")
                 == LATER + " key changed during quarantine", result)

    # Registration failures store nothing and are readable after the fact.
    node.raw["datetime"] = LATER
    node.answer(REVOKED)
    result = contract.register_key("example.com", "sel")
    report.check("a revoked key is a reason, not a revert",
                 result == "key revoked or absent" and not contract.has_key("example.com", "sel"),
                 result)
    report.check("last_failure reports it",
                 contract.last_failure("example.com", "sel") == LATER + " key revoked or absent")
    node.answer(doh_answer(p), dns=SERVFAIL)
    result = contract.register_key("example.com", "half")
    report.check("a SERVFAIL is unavailable, not absent",
                 result == "resolver unavailable: dns.google", result)
    node.answer(doh_answer(p), cloudflare=doh_answer(p, chunk=37))
    report.check("the same key chunked differently agrees",
                 contract.register_key("example.com", "chunked") == "pending")
    report.check("last_failure of a name that never failed is empty",
                 contract.last_failure("example.com", "chunked") == "")

    # Refresh on an active record of its own.
    node.raw["datetime"] = DATETIME
    node.answer(doh_answer(p))
    contract.register_key("refresh.example", "sel")
    node.raw["datetime"] = DUE
    contract.confirm_key("refresh.example", "sel")
    node.raw["datetime"] = LATER
    report.check("refresh unchanged",
                 contract.refresh_key("refresh.example", "sel") == "unchanged"
                 and contract.key_status("refresh.example", "sel")["refreshed_at"] == LATER)
    before = contract.key_status("refresh.example", "sel")
    node.down = {"dns.google"}
    node.raw["datetime"] = "2026-09-29T00:00:00Z"
    result = contract.refresh_key("refresh.example", "sel")
    report.check("refresh with a resolver down changes nothing",
                 result == "resolver unavailable: dns.google"
                 and contract.key_status("refresh.example", "sel") == before, result)
    report.check("but the failure is readable",
                 contract.last_failure("refresh.example", "sel")
                 == "2026-09-29T00:00:00Z resolver unavailable: dns.google")

    node.answer(doh_answer(other_key(p)))
    node.sender = Address(STRANGER)
    result = contract.refresh_key("refresh.example", "sel")
    after = contract.key_status("refresh.example", "sel")
    report.check("refresh marks a rotation without overwriting",
                 result == "rotated under same selector" and after["state"] == "rotated"
                 and after["key_sha256"] == before["key_sha256"]
                 and after["n_hex"] == before["n_hex"], result)
    node.answer(doh_answer(p))
    report.check("the state stays rotated when the old key returns",
                 contract.refresh_key("refresh.example", "sel") == "unchanged"
                 and contract.key_status("refresh.example", "sel")["state"] == "rotated")
    report.check("registering a rotated key returns exists",
                 contract.register_key("refresh.example", "sel") == "exists")

    node.answer(REVOKED)
    result = contract.refresh_key("refresh.example", "sel")
    report.check("refresh retires on empty p=",
                 result == "retired by refresh"
                 and contract.key_status("refresh.example", "sel")["state"] == "retired", result)
    node.answer(doh_answer(p))
    fetches = len(node.urls)
    report.check("a retired record is not refreshed",
                 contract.refresh_key("refresh.example", "sel") == "retired"
                 and len(node.urls) == fetches)
    report.check("nor registered again",
                 contract.register_key("refresh.example", "sel") == "retired"
                 and len(node.urls) == fetches)
    report.check("refresh of an unknown key stores nothing",
                 contract.refresh_key("nowhere.example", "sel") == "not registered"
                 and not contract.has_key("nowhere.example", "sel"))

    # retire_key is the owner's, and works on a pending key too, which
    # then can never be confirmed.
    report.raises("retire_key by a stranger raises",
                  lambda: contract.retire_key(DOMAIN, SELECTOR), "owner only")
    node.sender = Address(OWNER)
    report.check("retire_key by the owner returns True",
                 contract.retire_key(DOMAIN, SELECTOR) is True
                 and contract.key_status(DOMAIN, SELECTOR)["state"] == "retired")
    report.check("a retired record stays readable",
                 contract.key_status(DOMAIN, SELECTOR)["key_bits"] == "1024")
    report.check("retiring a pending key works",
                 contract.retire_key("swap.example", "sel") is True)
    node.raw["datetime"] = "2026-10-05T00:00:00Z"
    report.raises("and it can never be confirmed",
                  lambda: contract.confirm_key("swap.example", "sel"), "no pending key")
    report.raises("retire_key of an unknown key raises",
                  lambda: contract.retire_key("nowhere.example", "sel"), "no such key")
    report.raises("a malformed domain raises",
                  lambda: contract.register_key("not a domain", "sel"))

    # Ownership last: it moves the account the checks above depend on.
    report.check("pending_owner starts empty", contract.pending_owner() == "")
    report.raises("the zero address cannot be proposed",
                  lambda: contract.propose_owner(ZERO))
    report.check("propose_owner stores the candidate",
                 contract.propose_owner(NEW_OWNER) == NEW_OWNER
                 and contract.owner() == OWNER)
    node.sender = Address(STRANGER)
    report.raises("accept_owner by a stranger raises", contract.accept_owner,
                  "pending owner only")
    node.sender = Address(NEW_OWNER)
    report.check("accept_owner by the pending owner takes it",
                 contract.accept_owner() == NEW_OWNER and contract.owner() == NEW_OWNER
                 and contract.pending_owner() == "")
    node.sender = Address(OWNER)
    report.raises("the old owner cannot retire",
                  lambda: contract.retire_key("example.com", "chunked"), "owner only")

    print("\n%d checks, %d failed" % (report.total, report.failed))
    sys.exit(1 if report.failed else 0)


if __name__ == "__main__":
    main()
