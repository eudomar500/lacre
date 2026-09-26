# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }


from genlayer import *
from dataclasses import dataclass
import hashlib

"""DKIM key records: a DNS over HTTPS answer in, an RSA public key out.

The key half of the probe's verifier, with no network and no SDK import, so
the contract build splices it in whole and the tests drive it directly.
"""
import base64
import re


_OBJECT = re.compile(r"\{[^{}]*\}")


_TXT = re.compile(r'"type"\s*:\s*16\b')


_DATA = re.compile(r'"data"\s*:\s*"((?:[^"\\]|\\.)*)"')


_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


RSA_OID = bytes.fromhex("06092a864886f70d010101")  # rsaEncryption, RFC 8017 A.1


KEY_TAGS = ("v", "k", "p", "h", "t")


def txt_from_doh(payload):
    chunks = []
    for obj in _OBJECT.findall(payload):
        found = _DATA.search(obj) if _TXT.search(obj) else None
        if found:
            data = found.group(1).replace('\\"', '"').replace("\\\\", "\\")
            quoted = _QUOTED.findall(data)
            chunks.append("".join(quoted) if quoted else data)
    if not chunks:
        raise ValueError("no TXT record in the answer")
    return "".join(chunks)


def key_tags(txt):
    """The RFC 6376 3.6.1 tags, with whitespace folded out of each value."""
    tags = {}
    for spec in txt.split(";"):
        name, sep, value = spec.partition("=")
        if sep and name.strip() in KEY_TAGS:
            tags[name.strip()] = "".join(value.split())
    return tags


def key_der(tags):
    if tags.get("v", "DKIM1") != "DKIM1" or tags.get("k", "rsa") != "rsa":
        raise ValueError("unsupported key record")
    p = tags.get("p", "")
    if not p:
        raise ValueError("key revoked (empty p=)")
    return base64.b64decode(p + "=" * (-len(p) % 4))


def read_tlv(der, at):
    if at + 2 > len(der):
        raise ValueError("truncated DER")
    tag, size, at = der[at], der[at + 1], at + 2
    if size & 0x80:
        count = size & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported DER length")
        size = int.from_bytes(der[at:at + count], "big")
        at += count
    if at + size > len(der):
        raise ValueError("truncated DER")
    return tag, der[at:at + size], at + size


def rsa_key(der):
    tag, n, at = read_tlv(der, 0)
    tag2, e, _ = read_tlv(der, at)
    if tag != 0x02 or tag2 != 0x02:
        raise ValueError("RSAPublicKey is not two INTEGERs")
    return int.from_bytes(n, "big"), int.from_bytes(e, "big")


def decode_spki(der):
    tag, outer, _ = read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("key is not a DER SEQUENCE")
    tag, first, at = read_tlv(outer, 0)
    if tag == 0x02:
        return rsa_key(outer)  # a few records still carry a bare PKCS#1 key
    if tag != 0x30 or RSA_OID not in first:
        raise ValueError("algorithm is not rsaEncryption")
    tag, bits, _ = read_tlv(outer, at)
    if tag != 0x03 or not bits or bits[0] != 0:
        raise ValueError("bad subjectPublicKey")
    tag, key, _ = read_tlv(bits, 1)
    if tag != 0x30:
        raise ValueError("subjectPublicKey is not an RSAPublicKey")
    return rsa_key(key)

RESOLVERS = (
    "https://dns.google/resolve?name=%s&type=TXT",
    "https://cloudflare-dns.com/dns-query?name=%s&type=TXT",
)
ABSENT = "key revoked or absent"
UNAVAILABLE = "resolver unavailable: "

QUARANTINE = 24 * 3600

PENDING = "pending"
ACTIVE = "active"
ROTATED = "rotated"
RETIRED = "retired"

MAX_DOMAIN = 253
MAX_LABEL = 63
MAX_REASON = 96
NAME_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-._"

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
    return "||||" + str(reason).replace("|", " ")[:MAX_REASON]


def published(url):
    """The DER under p=, b"" if there is no key, None if there is no answer."""
    try:
        response = gl.nondet.web.get(url, headers={"accept": "application/dns-json"})
        body = (response.body or b"").decode("utf-8", "replace")
    except Exception:
        return None
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

    parts = str(gl.eq_principle.strict_eq(probe)).split("|")
    if len(parts) != 5:
        raise gl.vm.UserError("[EXPECTED] malformed key string")
    return parts


def unix_time(text):
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
    return str(gl.message_raw["datetime"])


def as_address(value):
    try:
        return Address(str(value).strip())
    except Exception:
        raise gl.vm.UserError("[EXPECTED] not a 20 byte hex address")


def require_owner(owner):
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
            return "exists" if held.state in (ACTIVE, ROTATED) else held.state

        parts = agree(name, label)
        if parts[4]:
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
            return self._failed(key, parts[4])
        if parts[4] or parts[3] != held.key_sha256:
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
            return held.state
        parts = agree(held.domain, held.selector)
        if parts[4] == ABSENT:
            held.state = RETIRED
            held.refreshed_at = now()
            return "retired by refresh"
        if parts[4]:
            return self._failed(key, parts[4])
        held.refreshed_at = now()
        if parts[3] == held.key_sha256:
            return "unchanged"
        held.state = ROTATED
        return "rotated under same selector"

    @gl.public.write
    def retire_key(self, domain: str, selector: str) -> bool:
        require_owner(self.owner_address)
        held = self.keys.get(lookup_key(domain, selector))
        if held is None:
            raise gl.vm.UserError("[EXPECTED] no such key")
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
        pending = self.pending_owner_address
        if pending == ZERO_ADDRESS or gl.message.sender_address != pending:
            raise gl.vm.UserError("[EXPECTED] pending owner only")
        self.owner_address = pending
        self.pending_owner_address = ZERO_ADDRESS
        return pending.as_hex
