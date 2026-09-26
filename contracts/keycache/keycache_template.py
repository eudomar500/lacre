# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

# build.py splices lacre/dkimkey.py in at the marker below and writes
# keycache.py: edit dkimkey.py or this template, never the built file. What
# this contract stores and why a key waits before it can be used is in
# docs/keycache.md.

from genlayer import *
from dataclasses import dataclass
import hashlib

# @@DKIMKEY@@

# Both have to publish the same key before it is stored, so one resolver
# that is wrong, stale or captured cannot write a key on its own.
RESOLVERS = (
    "https://dns.google/resolve?name=%s&type=TXT",
    "https://cloudflare-dns.com/dns-query?name=%s&type=TXT",
)
ABSENT = "key revoked or absent"
# A resolver that gave no answer at all: no response, not HTTP 200, or an
# rcode other than NOERROR and NXDOMAIN. It says nothing about the key.
UNAVAILABLE = "resolver unavailable: "

# A new key is not usable until both resolvers have returned it on two reads
# at least this far apart. A DNS takeover then has to be in place at both
# reads instead of one, and the owner has the window to retire it.
QUARANTINE = 24 * 3600

PENDING = "pending"
ACTIVE = "active"
ROTATED = "rotated"
RETIRED = "retired"

# A DNS name is 253 characters, one label is 63. Longer is a caller mistake.
MAX_DOMAIN = 253
MAX_LABEL = 63
MAX_REASON = 96
NAME_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-._"

# An unset Address field reads back as twenty zero bytes.
ZERO_ADDRESS = Address(bytes(20))


def normalize(value, limit):
    """A domain or a selector as it is keyed, or "" if it is not a name."""
    text = str(value).strip().lower().strip(".")
    if not text or len(text) > limit:
        return ""
    for char in text:
        if char not in NAME_CHARS:
            return ""
    return text


def record_key(domain, selector):
    return "%s._domainkey.%s" % (selector, domain)


def lookup_key(domain, selector):
    return record_key(normalize(domain, MAX_DOMAIN), normalize(selector, MAX_LABEL))


def failure(reason):
    # Four empty fields and the reason, so a failure parses like a success.
    return "||||" + str(reason).replace("|", " ")[:MAX_REASON]


def published(url):
    """The DER under p=, b"" if there is no key, None if there is no answer."""
    try:
        response = gl.nondet.web.get(url, headers={"accept": "application/dns-json"})
        body = (response.body or b"").decode("utf-8", "replace")
    except Exception:
        return None
    # Only NOERROR and NXDOMAIN say anything about the record. A SERVFAIL
    # read as "gone" would let a flaky upstream retire a key on refresh.
    rcode = re.search(r'"Status"\s*:\s*(\d+)', body)
    if getattr(response, "status", 0) != 200 or not rcode or rcode.group(1) not in ("0", "3"):
        return None
    try:
        tags = key_tags(txt_from_doh(body))
    except ValueError:
        return b""
    return key_der(tags) if tags.get("p") else b""


def fetch_key(domain, selector):
    """The canonical string the validators have to agree on. Never raises.

    A resolver failure or a revoked key is a reason rather than an exception,
    so the two sides compare answers instead of disagreeing about the network.
    """
    found, down = [], []
    for url in RESOLVERS:
        try:
            der = published(url % record_key(domain, selector))
        except Exception as error:
            return failure("key unusable: " + type(error).__name__)
        if der is None:
            down.append(url.split("/")[2])
        found.append(der)
    if down:
        return failure(UNAVAILABLE + ", ".join(down))
    # The DER, not the TXT string: resolvers chunk and quote a long record
    # differently while publishing the same key.
    der = found[0]
    if der != found[1]:
        return failure("resolvers disagree")
    if not der:
        return failure(ABSENT)
    try:
        n, e = decode_spki(der)
    except Exception as error:
        return failure("key unusable: " + type(error).__name__)
    return "%x|%d|%d|%s|" % (n, e, n.bit_length(), hashlib.sha256(der).hexdigest())


def agree(domain, selector):
    def probe() -> str:
        return fetch_key(domain, selector)

    # strict_eq compares the two returns for exact equality, so consensus
    # rides on the canonical string, not on the bytes the resolvers sent.
    parts = str(gl.eq_principle.strict_eq(probe)).split("|")
    if len(parts) != 5:
        raise gl.vm.UserError("[EXPECTED] malformed key string")
    return parts


def unix_time(text):
    # By position, so either "T" or " " may separate date and time. The
    # Verifier carries the same function; tests/test_verifier_time.py checks
    # every copy against the standard library.
    y, m, d = int(text[:4]), int(text[5:7]), int(text[8:10])
    y -= m < 3
    days = 365 * y + y // 4 - y // 100 + y // 400 + (153 * ((m + 9) % 12) + 2) // 5 + d - 719469
    zone = text[19:].lstrip("0123456789.")
    offset = 0
    if zone[:1] in ("+", "-"):
        digits = zone[1:].replace(":", "")
        offset = (int(digits[:2]) * 60 + int(digits[2:4] or 0)) * (60 if zone[0] == "+" else -60)
    return days * 86400 + int(text[11:13]) * 3600 + int(text[14:16]) * 60 + int(text[17:19]) - offset


def now():
    # The runner's own transaction datetime, stored unmodified: what every
    # validator sees here has to be the same string.
    return str(gl.message_raw["datetime"])


def as_address(value):
    try:
        return Address(str(value).strip())
    except Exception:
        raise gl.vm.UserError("[EXPECTED] not a 20 byte hex address")


def require_owner(owner):
    # Raising in the deterministic block is the access check: an unauthorized
    # write leaves no record.
    if gl.message.sender_address != owner:
        raise gl.vm.UserError("[EXPECTED] owner only")


@allow_storage
@dataclass
class KeyRecord:
    domain: str
    selector: str
    state: str
    n_hex: str
    e: u256
    key_bits: u256
    key_sha256: str
    first_seen: str
    activated_at: str
    refreshed_at: str


class Contract(gl.Contract):
    owner_address: Address
    pending_owner_address: Address
    keys: TreeMap[str, KeyRecord]
    # The last lookup that failed for a name, with its datetime. The return
    # value of a write cannot be read from the chain, so the outcome of every
    # write that stores nothing has to be readable here instead.
    failures: TreeMap[str, str]

    def __init__(self):
        self.owner_address = gl.message.sender_address
        self.pending_owner_address = ZERO_ADDRESS

    def _failed(self, key, reason):
        self.failures[key] = now() + " " + reason
        return reason

    @gl.public.write
    def register_key(self, domain: str, selector: str) -> str:
        name = normalize(domain, MAX_DOMAIN)
        label = normalize(selector, MAX_LABEL)
        if not name or not label:
            raise gl.vm.UserError("[EXPECTED] domain or selector is not a name")

        key = record_key(name, label)
        held = self.keys.get(key)
        if held is not None:
            # A published key does not change under its selector and
            # retirement is terminal, so no path re-reads DNS here. A rotated
            # key arrives under a new selector.
            return "exists" if held.state in (ACTIVE, ROTATED) else held.state

        parts = agree(name, label)
        if parts[4]:
            # A key that cannot be read is an answer, not a failed write.
            return self._failed(key, parts[4])

        self.keys[key] = KeyRecord(
            domain=name,
            selector=label,
            state=PENDING,
            n_hex=parts[0],
            e=u256(int(parts[1]) if parts[1].isdigit() else 0),
            key_bits=u256(int(parts[2]) if parts[2].isdigit() else 0),
            key_sha256=parts[3],
            first_seen=now(),
            activated_at="",
            refreshed_at="",
        )
        return PENDING

    @gl.public.write
    def confirm_key(self, domain: str, selector: str) -> str:
        key = lookup_key(domain, selector)
        held = self.keys.get(key)
        if held is None or held.state != PENDING:
            raise gl.vm.UserError("[EXPECTED] no pending key")
        if unix_time(now()) < unix_time(held.first_seen) + QUARANTINE:
            raise gl.vm.UserError("[EXPECTED] the quarantine has not passed")
        parts = agree(held.domain, held.selector)
        if parts[4].startswith(UNAVAILABLE):
            # A resolver that did not answer says nothing about the key, so
            # the key stays pending with its first_seen, and confirm_key can
            # be called again. It still activates only on an answer from both.
            return self._failed(key, parts[4])
        if parts[4] or parts[3] != held.key_sha256:
            # Both resolvers answered and the key is not the one first read:
            # changed, gone, disagreeing or unusable. A key that changed is a
            # reason to refuse it, so it is dropped rather than kept pending,
            # and activation always rests on two matching reads a full window
            # apart.
            del self.keys[key]
            return self._failed(key, parts[4] or "key changed during quarantine")
        held.state = ACTIVE
        held.activated_at = now()
        held.refreshed_at = held.activated_at
        return ACTIVE

    @gl.public.write
    def refresh_key(self, domain: str, selector: str) -> str:
        key = lookup_key(domain, selector)
        held = self.keys.get(key)
        if held is None:
            return "not registered"
        if held.state in (PENDING, RETIRED):
            # A pending key is settled by confirm_key, and retirement is
            # terminal; neither is re-read here.
            return held.state
        parts = agree(held.domain, held.selector)
        if parts[4] == ABSENT:
            # An empty p= is the publisher revoking the key, RFC 6376 3.6.1.
            held.state = RETIRED
            held.refreshed_at = now()
            return "retired by refresh"
        if parts[4]:
            return self._failed(key, parts[4])
        held.refreshed_at = now()
        if parts[3] == held.key_sha256:
            # A rotated key stays rotated if the old one comes back.
            return "unchanged"
        # The record keeps the key attestations were checked against; the
        # state tells the Verifier DNS now publishes another one here.
        held.state = ROTATED
        return "rotated under same selector"

    @gl.public.write
    def retire_key(self, domain: str, selector: str) -> bool:
        require_owner(self.owner_address)
        held = self.keys.get(lookup_key(domain, selector))
        if held is None:
            raise gl.vm.UserError("[EXPECTED] no such key")
        # The record stays readable: a consumer has to be able to tell a key
        # that was withdrawn from one that was never registered.
        held.state = RETIRED
        return True

    @gl.public.view
    def key_status(self, domain: str, selector: str) -> dict:
        held = self.keys.get(lookup_key(domain, selector))
        if held is None:
            return {}
        return {
            "domain": held.domain,
            "selector": held.selector,
            "state": held.state,
            "n_hex": held.n_hex,
            "e": str(held.e),
            "key_bits": str(held.key_bits),
            "key_sha256": held.key_sha256,
            "first_seen": held.first_seen,
            "activated_at": held.activated_at,
            "refreshed_at": held.refreshed_at,
        }

    @gl.public.view
    def last_failure(self, domain: str, selector: str) -> str:
        return self.failures.get(lookup_key(domain, selector), "")

    @gl.public.view
    def has_key(self, domain: str, selector: str) -> bool:
        return lookup_key(domain, selector) in self.keys

    @gl.public.view
    def key_count(self) -> int:
        return len(self.keys)

    @gl.public.view
    def owner(self) -> str:
        return self.owner_address.as_hex

    @gl.public.view
    def pending_owner(self) -> str:
        pending = self.pending_owner_address
        return "" if pending == ZERO_ADDRESS else pending.as_hex

    @gl.public.write
    def propose_owner(self, address: str) -> str:
        require_owner(self.owner_address)
        candidate = as_address(address)
        if candidate == ZERO_ADDRESS:
            raise gl.vm.UserError("[EXPECTED] the zero address cannot be proposed")
        self.pending_owner_address = candidate
        return candidate.as_hex

    @gl.public.write
    def accept_owner(self) -> str:
        # The owner is the only account that can retire a compromised key, so
        # a typo in propose_owner has to be survivable.
        pending = self.pending_owner_address
        if pending == ZERO_ADDRESS or gl.message.sender_address != pending:
            raise gl.vm.UserError("[EXPECTED] pending owner only")
        self.owner_address = pending
        self.pending_owner_address = ZERO_ADDRESS
        return pending.as_hex
