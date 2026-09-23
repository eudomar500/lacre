# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

# build.py splices lacre/dkimkey.py in at the marker below and writes
# registry.py: edit dkimkey.py, never the built file. What this contract
# stores, and why it is the one address that does not move, is in
# docs/registry.md.

from genlayer import *
from dataclasses import dataclass
import hashlib

# @@DKIMKEY@@

DOH_URL = "https://dns.google/resolve?name=%s._domainkey.%s&type=TXT"

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


def fetch_key(domain, selector):
    """The canonical string the validators have to agree on. Never raises.

    A refused fetch or a revoked key is a reason rather than an exception, so
    the two sides compare answers instead of disagreeing about the network.
    """
    try:
        response = gl.nondet.web.get(
            DOH_URL % (selector, domain), headers={"accept": "application/dns-json"}
        )
    except Exception as error:
        return failure("DoH fetch failed: " + type(error).__name__)

    # Response.status is the field the pinned runner returns; getattr keeps a
    # renamed one from raising inside the block that must not raise.
    status = int(getattr(response, "status", 0) or 0)
    if status != 200:
        return failure("DoH HTTP %d" % (status,))

    try:
        tags = key_tags(txt_from_doh((response.body or b"").decode("utf-8", "replace")))
    except Exception as error:
        return failure("no key record: " + type(error).__name__)
    if not tags.get("p", ""):
        return failure("key revoked or absent")

    try:
        key = key_from_tags(tags)
    except Exception as error:
        return failure("key unusable: " + type(error).__name__)
    return "%x|%d|%d|%s|" % (
        key["n"],
        key["e"],
        key["key_bits"],
        hashlib.sha256(key["der"]).hexdigest(),
    )


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
    n_hex: str
    e: u256
    key_bits: u256
    key_sha256: str
    first_seen: str
    retired: bool


class Contract(gl.Contract):
    owner_address: Address
    pending_owner_address: Address
    versions: TreeMap[str, Address]
    keys: TreeMap[str, KeyRecord]

    def __init__(self):
        self.owner_address = gl.message.sender_address
        self.pending_owner_address = ZERO_ADDRESS

    @gl.public.write
    def set_version(self, name: str, address: str) -> str:
        require_owner(self.owner_address)
        label = normalize(name, MAX_LABEL)
        if not label:
            raise gl.vm.UserError("[EXPECTED] version name is empty or not a name")
        pointer = as_address(address)
        self.versions[label] = pointer
        return pointer.as_hex

    @gl.public.view
    def version(self, name: str) -> str:
        pointer = self.versions.get(normalize(name, MAX_LABEL))
        return "" if pointer is None else pointer.as_hex

    @gl.public.view
    def all_versions(self) -> dict:
        return {name: pointer.as_hex for name, pointer in self.versions.items()}

    @gl.public.view
    def owner(self) -> str:
        return self.owner_address.as_hex

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
        # a typo in propose_owner has to be survivable: the pointer moves only
        # when the new owner proves it can sign.
        pending = self.pending_owner_address
        if pending == ZERO_ADDRESS or gl.message.sender_address != pending:
            raise gl.vm.UserError("[EXPECTED] pending owner only")
        self.owner_address = pending
        self.pending_owner_address = ZERO_ADDRESS
        return pending.as_hex

    @gl.public.view
    def pending_owner(self) -> str:
        pending = self.pending_owner_address
        return "" if pending == ZERO_ADDRESS else pending.as_hex

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
            # retirement is terminal, so neither path re-reads DNS. A rotated
            # key arrives under a new selector.
            return "retired" if held.retired else "exists"

        def probe() -> str:
            return fetch_key(name, label)

        # strict_eq compares the two returns for exact equality, so consensus
        # rides on the canonical string, not on the bytes the resolver sent.
        agreed = str(gl.eq_principle.strict_eq(probe))
        parts = agreed.split("|")
        if len(parts) != 5:
            raise gl.vm.UserError("[EXPECTED] malformed key string")
        if parts[4]:
            # A key that cannot be read is an answer, not a failed write.
            return parts[4]

        self.keys[key] = KeyRecord(
            domain=name,
            selector=label,
            n_hex=parts[0],
            e=u256(int(parts[1]) if parts[1].isdigit() else 0),
            key_bits=u256(int(parts[2]) if parts[2].isdigit() else 0),
            key_sha256=parts[3],
            # The runner's own transaction datetime, stored unmodified: what
            # every validator sees here has to be the same string.
            first_seen=str(gl.message_raw["datetime"]),
            retired=False,
        )
        return "registered"

    @gl.public.write
    def retire_key(self, domain: str, selector: str) -> bool:
        require_owner(self.owner_address)
        held = self.keys.get(lookup_key(domain, selector))
        if held is None:
            raise gl.vm.UserError("[EXPECTED] no such key")
        # The record stays readable: a consumer has to be able to tell a key
        # that was withdrawn from one that was never registered.
        held.retired = True
        return True

    @gl.public.view
    def get_key(self, domain: str, selector: str) -> dict:
        held = self.keys.get(lookup_key(domain, selector))
        if held is None:
            return {}
        return {
            "domain": str(held.domain),
            "selector": str(held.selector),
            "n_hex": str(held.n_hex),
            "e": str(held.e),
            "key_bits": str(held.key_bits),
            "key_sha256": str(held.key_sha256),
            "first_seen": str(held.first_seen),
            "retired": bool(held.retired),
        }

    @gl.public.view
    def has_key(self, domain: str, selector: str) -> bool:
        return lookup_key(domain, selector) in self.keys

    @gl.public.view
    def key_count(self) -> int:
        return len(self.keys)
