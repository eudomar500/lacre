# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

# build.py strips the comments and writes router.py: edit this file, never the
# built one. The Router is kept small on purpose, so that it is the contract
# least likely to need a new deployment; why, and what it does not do, is in
# docs/router.md.

from genlayer import *
from dataclasses import dataclass

# A change proposed now takes effect no sooner than this, so a consumer that
# re-resolves a name can see the change coming and react before it applies.
DELAY = 48 * 3600

MAX_LABEL = 63
NAME_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-._"

# An unset Address field reads back as twenty zero bytes.
ZERO_ADDRESS = Address(bytes(20))


def normalize(value):
    """A name or a version label as it is keyed, or "" if it is not one."""
    text = str(value).strip().lower().strip(".")
    if not text or len(text) > MAX_LABEL:
        return ""
    for char in text:
        if char not in NAME_CHARS:
            return ""
    return text


def name_of(value):
    name = normalize(value)
    if not name:
        raise gl.vm.UserError("[EXPECTED] name is empty or not a name")
    return name


def unix_time(text):
    # The runner datetime is a string and the contract cannot import
    # datetime, so it is read by position; the Verifier carries the same
    # function and tests/test_verifier_time.py checks every copy.
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
    # Stored unmodified: every validator sees the same string here.
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
class Version:
    name: str
    label: str
    address: Address
    set_at: str


@allow_storage
@dataclass
class Change:
    label: str
    address: Address
    proposed_at: str


def make_current(router, name, label, address):
    router.current[name] = address
    router.pinned[name + "/" + label] = address
    router.versions.append(Version(name, label, address, now()))


class Contract(gl.Contract):
    owner_address: Address
    pending_owner_address: Address
    current: TreeMap[str, Address]
    # "<name>/<label>" to the address that label was applied with. A label
    # never moves to another address, which is what makes a pin safe.
    pinned: TreeMap[str, Address]
    changes: TreeMap[str, Change]
    versions: DynArray[Version]

    def __init__(self):
        self.owner_address = gl.message.sender_address
        self.pending_owner_address = ZERO_ADDRESS

    @gl.public.view
    def resolve(self, name: str) -> str:
        pointer = self.current.get(normalize(name))
        return "" if pointer is None else pointer.as_hex

    @gl.public.view
    def resolve_pinned(self, name: str, version: str) -> str:
        pointer = self.pinned.get(normalize(name) + "/" + normalize(version))
        return "" if pointer is None else pointer.as_hex

    @gl.public.view
    def history(self, name: str) -> list:
        name = normalize(name)
        return [
            {"version": v.label, "address": v.address.as_hex, "set_at": v.set_at}
            for v in self.versions
            if v.name == name
        ]

    @gl.public.view
    def pending(self, name: str) -> dict:
        change = self.changes.get(normalize(name))
        if change is None:
            return {}
        return {
            "version": change.label,
            "address": change.address.as_hex,
            "proposed_at": change.proposed_at,
            "effective_at": unix_time(change.proposed_at) + DELAY,
        }

    @gl.public.write
    def set_version(self, name: str, version_label: str, address: str) -> str:
        require_owner(self.owner_address)
        name = name_of(name)
        label = normalize(version_label)
        if not label:
            raise gl.vm.UserError("[EXPECTED] version label is empty or not a name")
        pointer = as_address(address)
        if name in self.changes:
            # One change at a time: replacing a pending one would let the
            # owner swap the target late in the announced window.
            raise gl.vm.UserError("[EXPECTED] a change is already pending")
        held = self.pinned.get(name + "/" + label)
        if held is not None and held != pointer:
            raise gl.vm.UserError("[EXPECTED] version label already names another address")
        if name not in self.current:
            # The delay protects a consumer bound to a name from being moved
            # without notice. Nobody can be bound to a name that has never
            # resolved, so its first address takes effect at once.
            make_current(self, name, label, pointer)
        else:
            self.changes[name] = Change(label, pointer, now())
        return pointer.as_hex

    @gl.public.write
    def apply_version(self, name: str) -> str:
        # Open to anyone: once announced and waited out, a change must not
        # depend on the owner coming back to finish it.
        name = normalize(name)
        change = self.changes.get(name)
        if change is None:
            raise gl.vm.UserError("[EXPECTED] nothing pending")
        if unix_time(now()) < unix_time(change.proposed_at) + DELAY:
            raise gl.vm.UserError("[EXPECTED] the delay has not passed")
        make_current(self, name, change.label, change.address)
        del self.changes[name]
        return change.address.as_hex

    @gl.public.write
    def cancel_version(self, name: str) -> str:
        require_owner(self.owner_address)
        name = normalize(name)
        if name not in self.changes:
            raise gl.vm.UserError("[EXPECTED] nothing pending")
        del self.changes[name]
        return name

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
        # A typo in propose_owner has to be survivable: ownership moves only
        # when the new owner proves it can sign.
        pending = self.pending_owner_address
        if pending == ZERO_ADDRESS or gl.message.sender_address != pending:
            raise gl.vm.UserError("[EXPECTED] pending owner only")
        self.owner_address = pending
        self.pending_owner_address = ZERO_ADDRESS
        return pending.as_hex
