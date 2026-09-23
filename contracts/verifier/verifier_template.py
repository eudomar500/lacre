# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

# Edit this template, not verifier.py. Design notes: docs/verifier.md.

from genlayer import *
from genlayer.py.public_abi import StorageType
from dataclasses import dataclass

# @@DKIMCORE@@

MAX_DOMAIN = 253
MAX_LABEL = 63
MAX_FIELD = 255
MAX_REASON = 96
MAX_BLOB = 16384
MAX_URL = 512

ZERO_ADDRESS = Address(bytes(20))


# Empty on purpose: the only way to hand value to a chain-layer address.
@gl.evm.contract_interface
class _Recipient:
    class View:
        pass

    class Write:
        pass


def normalize(value, limit):
    text = str(value).strip().lower().strip(".")
    return text if len(text) <= limit else ""


def scrub(value, limit):
    return str(value).replace("|", " ").replace("\r", " ").replace("\n", " ")[:limit]


def canonical(bh, body_canon, mid_hash, ok, reason, sender="", aligned=False, signed=0):
    return "%s|%s|%s|%d|%s|%s|%d|%d" % (
        scrub(bh, MAX_FIELD), scrub(body_canon, MAX_LABEL), scrub(mid_hash, 64),
        1 if ok else 0, scrub(reason, MAX_REASON), scrub(sender, MAX_DOMAIN),
        1 if aligned else 0, signed)


def failure(reason):
    return canonical("", "", "", False, reason)


def from_domain(value):
    # Quoted display names may carry "@" or "<"; anything else ambiguous
    # yields no domain, which reads as not aligned.
    text = re.sub(r'"(?:[^"\\]|\\.)*"', "", value.decode("latin-1"))
    addr = text.rpartition("<")[2].partition(">")[0] if "<" in text else text
    if "@" not in addr or text.count("@") > 1 or text.count("<") > 1:
        return ""
    return addr.rpartition("@")[2].strip().lower().strip(".")


def unix_time(text):
    # By position, so either "T" or " " may separate date and time.
    y, m, d = int(text[:4]), int(text[5:7]), int(text[8:10])
    y -= m < 3
    days = 365 * y + y // 4 - y // 100 + y // 400 + (153 * ((m + 9) % 12) + 2) // 5 + d - 719469
    zone = text[19:].lstrip("0123456789.")
    offset = 0
    if zone[:1] in ("+", "-"):
        digits = zone[1:].replace(":", "")
        offset = (int(digits[:2]) * 60 + int(digits[2:4] or 0)) * (60 if zone[0] == "+" else -60)
    return days * 86400 + int(text[11:13]) * 3600 + int(text[14:16]) * 60 + int(text[17:19]) - offset


def body_mode(tags):
    return tags.get("c", "").partition("/")[2].strip().lower() or "simple"


def attest_once(url, blob, domain, selector, n, e, now):
    # Never raises: a failure here must be a stored record, not a revert.
    try:
        if url:
            try:
                response = gl.nondet.web.get(url, headers={"accept": "text/plain"})
            except Exception as error:
                return failure("blob fetch failed: " + type(error).__name__)
            status = int(getattr(response, "status", 0) or 0)
            if status != 200:
                return failure("blob HTTP %d" % (status,))
            blob = response.body or b""
            if len(blob) > MAX_BLOB:
                return failure("blob too large")
        return attest_blob(blob, domain, selector, n, e, now)
    except Exception as error:
        return failure("probe failed: " + type(error).__name__)


def attest_blob(blob, domain, selector, n, e, now):
    fields = parse_headers(blob)
    if find_signature(fields)[0] < 0:
        return failure("no DKIM-Signature in the blob")
    for index, (name, value) in enumerate(fields):
        tags = parse_tags(value.decode("latin-1"))
        if field_name(name) == b"dkim-signature" and (
            tags.get("d", "").lower() == domain and tags.get("s", "").lower() == selector
        ):
            break
    else:
        return failure("signature does not match domain or selector")
    # verify_headers checks the first signature, so the chosen one is moved
    # to the top; signed_data never reads the signature's own position.
    fields = [fields[index]] + fields[:index] + fields[index + 1:]
    ok, info = verify_headers(b"".join(name + b":" + value + b"\r\n" for name, value in fields), n, e)
    identifier = info["message_id"]
    reason = info["reason"]
    signer = info["domain"].lower()
    names = [name.strip().lower() for name in tags.get("h", "").split(":") if name.strip()]
    present = [field_name(name).decode("latin-1") for name, _ in fields[1:]]
    signed = tags.get("t", "")
    froms = [value for name, value in fields if field_name(name) == b"from"]
    sender = from_domain(froms[0]) if len(froms) == 1 else ""
    # First failing rule wins; each overrides the RSA verdict.
    for bad, why in (
        ("from" not in names, "from not signed"),
        # An unsigned copy above the signed one is what a reader displays.
        (any(present.count(name) > names.count(name) for name in names),
         "duplicate signed header"),
        # A malformed x= reads as 0, so it fails closed.
        ("x" in tags and as_number(tags["x"]) < unix_time(now), "signature expired")):
        if bad:
            ok, reason = False, why
            break
    return canonical(
        info["bh"], body_mode(tags),
        sha256(identifier.encode("utf-8")).hex() if identifier else "",
        ok, reason, sender,
        sender != "" and (sender == signer or sender.endswith("." + signer)
                          or signer.endswith("." + sender)),
        as_number(signed) if len(signed) < 20 else 0)


def as_address(value):
    try:
        return Address(str(value).strip())
    except Exception:
        raise gl.vm.UserError("[EXPECTED] not a 20 byte hex address")


def as_number(value):
    text = str(value).strip()
    return int(text) if text.isascii() and text.isdigit() else 0


def proposed(value):
    candidate = as_address(value)
    if candidate == ZERO_ADDRESS:
        raise gl.vm.UserError("[EXPECTED] the zero address cannot be proposed")
    return candidate


def claimed(pending, role):
    # A mistyped proposal is survivable: nothing moves until that address signs.
    if pending == ZERO_ADDRESS or gl.message.sender_address != pending:
        raise gl.vm.UserError("[EXPECTED] pending %s only" % (role,))
    return pending


def shown(address):
    return "" if address == ZERO_ADDRESS else address.as_hex


def refuse(reason):
    # A revert keeps what the call carried, so a rejection has to hand it
    # back itself. The refund leaves the way withdraw does and settles on
    # finalization.
    paid = int(gl.message.value)
    if paid:
        _Recipient(gl.message.sender_address).emit_transfer(value=u256(paid))
    return reason


def require_owner(owner):
    if gl.message.sender_address != owner:
        raise gl.vm.UserError("[EXPECTED] owner only")


def require_amount(amount, held):
    wei = int(amount)
    if wei <= 0 or wei > held:
        raise gl.vm.UserError("[EXPECTED] amount out of range")
    return wei


def registry_key(registry, domain, selector):
    # The read is inside the try as well: nothing on this path may raise.
    try:
        record = gl.get_contract_at(registry).view(state=StorageType.LATEST_FINAL).get_key(domain, selector)
        modulus = int(record["n_hex"], 16)
        exponent = as_number(record["e"])
        if not record["retired"] and modulus > 1 and exponent > 2:
            return record, modulus, exponent
    except Exception:
        pass
    return {}, 0, 0


@allow_storage
@dataclass
class Attestation:
    domain: str
    selector: str
    bh: str
    body_canon: str
    message_id_sha256: str
    key_bits: u256
    key_sha256: str
    valid: bool
    reason: str
    from_domain: str
    aligned: bool
    signed_at: u256
    source: str
    requester: Address
    attested_at: str
    fee_paid: u256


class Contract(gl.Contract):
    owner_address: Address
    pending_owner_address: Address
    registry_address: Address
    treasury_address: Address
    pending_treasury_address: Address
    fee_wei: u256
    records: TreeMap[str, Attestation]
    record_count: u256

    def __init__(self, registry: str):
        self.owner_address = gl.message.sender_address
        self.pending_owner_address = ZERO_ADDRESS
        self.registry_address = as_address(registry)
        self.treasury_address = gl.message.sender_address
        self.pending_treasury_address = ZERO_ADDRESS
        self.fee_wei = u256(0)
        self.record_count = u256(0)

    @gl.public.write.payable
    def attest(self, headers_url: str, domain: str, selector: str) -> str:
        url = str(headers_url).strip()
        if not url.startswith("https://") or len(url) > MAX_URL:
            return refuse("url not allowed")
        return self._attest(url, b"", domain, selector)

    @gl.public.write.payable
    def attest_inline(self, headers_blob: str, domain: str, selector: str) -> str:
        blob = str(headers_blob).encode("utf-8")
        if len(blob) > MAX_BLOB:
            return refuse("blob too large")
        return self._attest("", blob, domain, selector)

    def _attest(self, url, blob, domain, selector):
        paid = int(gl.message.value)
        if paid < int(self.fee_wei):
            return refuse("fee not paid")
        name = normalize(domain, MAX_DOMAIN)
        label = normalize(selector, MAX_LABEL)
        if not name or not label:
            return refuse("bad domain or selector")
        record, modulus, exponent = registry_key(self.registry_address, name, label)
        if not modulus:
            return refuse("key not registered")
        now = str(gl.message_raw["datetime"])

        def probe() -> str:
            return attest_once(url, blob, name, label, modulus, exponent, now)

        # Inline has nothing non-deterministic to agree on.
        agreed = str(gl.eq_principle.strict_eq(probe) if url else probe())
        parts = (agreed.split("|") + [""] * 8)[:8]

        record_id = str(self.record_count)
        self.records[record_id] = Attestation(
            domain=name, selector=label, bh=parts[0], body_canon=parts[1],
            message_id_sha256=parts[2],
            key_bits=u256(as_number(record.get("key_bits", 0))),
            key_sha256=str(record.get("key_sha256", "")),
            valid=parts[3] == "1", reason=parts[4],
            from_domain=parts[5], aligned=parts[6] == "1",
            signed_at=u256(as_number(parts[7])),
            source="url" if url else "inline",
            requester=gl.message.sender_address,
            attested_at=now,
            fee_paid=u256(paid),
        )
        self.record_count = u256(int(self.record_count) + 1)
        return record_id

    @gl.public.view
    def get(self, id: str) -> dict:
        held = self.records.get(str(id))
        if held is None:
            return {}
        return {
            "id": str(id), "domain": str(held.domain),
            "selector": str(held.selector), "bh": str(held.bh),
            "body_canon": str(held.body_canon),
            "message_id_sha256": str(held.message_id_sha256),
            "key_bits": str(held.key_bits), "key_sha256": str(held.key_sha256),
            "valid": bool(held.valid), "reason": str(held.reason),
            "from_domain": str(held.from_domain), "aligned": bool(held.aligned),
            "signed_at": str(held.signed_at), "source": str(held.source),
            "requester": held.requester.as_hex,
            "attested_at": str(held.attested_at),
            "fee_paid": str(held.fee_paid),
        }

    @gl.public.view
    def check_for(self, id: str, domain: str, min_key_bits: int, requester: str) -> bool:
        held = self.records.get(str(id))
        try:
            who = as_address(requester)
        except Exception:
            return False
        return held is not None and (
            held.valid
            and held.aligned
            and held.domain == normalize(domain, MAX_DOMAIN)
            and int(held.key_bits) >= int(min_key_bits)
            and held.requester == who
        )

    @gl.public.view
    def count(self) -> int:
        return int(self.record_count)

    @gl.public.view
    def fee(self) -> int:
        return int(self.fee_wei)

    @gl.public.view
    def treasury(self) -> str:
        return self.treasury_address.as_hex

    @gl.public.view
    def registry(self) -> str:
        return self.registry_address.as_hex

    @gl.public.view
    def owner(self) -> str:
        return self.owner_address.as_hex

    @gl.public.view
    def pending_owner(self) -> str:
        return shown(self.pending_owner_address)

    @gl.public.view
    def pending_treasury(self) -> str:
        return shown(self.pending_treasury_address)

    @gl.public.write
    def set_fee(self, new_fee: int) -> str:
        require_owner(self.owner_address)
        amount = int(new_fee)
        if amount < 0:
            raise gl.vm.UserError("[EXPECTED] negative fee")
        self.fee_wei = u256(amount)
        return str(amount)

    @gl.public.write
    def propose_owner(self, address: str) -> str:
        require_owner(self.owner_address)
        self.pending_owner_address = proposed(address)
        return self.pending_owner_address.as_hex

    @gl.public.write
    def accept_owner(self) -> str:
        self.owner_address = claimed(self.pending_owner_address, "owner")
        self.pending_owner_address = ZERO_ADDRESS
        return self.owner_address.as_hex

    @gl.public.write
    def propose_treasury(self, address: str) -> str:
        require_owner(self.owner_address)
        self.pending_treasury_address = proposed(address)
        return self.pending_treasury_address.as_hex

    @gl.public.write
    def accept_treasury(self) -> str:
        self.treasury_address = claimed(self.pending_treasury_address, "treasury")
        self.pending_treasury_address = ZERO_ADDRESS
        return self.treasury_address.as_hex

    @gl.public.write
    def withdraw(self, amount: int) -> str:
        require_owner(self.owner_address)
        wei = require_amount(amount, int(self.balance))
        # Settles on finalization: the balance does not move in this call.
        _Recipient(self.treasury_address).emit_transfer(value=u256(wei))
        return str(wei)
