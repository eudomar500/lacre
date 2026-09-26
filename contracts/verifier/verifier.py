# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }


from genlayer import *
from genlayer.py.public_abi import StorageType
from dataclasses import dataclass

import base64
import hashlib
import re


def sha256(data):
    return hashlib.sha256(data).digest()


_WSP = re.compile(rb"[ \t]+")


DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def field_name(name):
    return name.strip(b" \t").lower()


def parse_headers(blob):
    fields = []
    for line in blob.split(b"\n"):
        if line.endswith(b"\r"):
            line = line[:-1]
        if line[:1] in (b" ", b"\t"):
            if fields:
                fields[-1] = (fields[-1][0], fields[-1][1] + b"\r\n" + line)
            continue
        name, sep, value = line.partition(b":")
        if sep:
            fields.append((name, value))
    return fields


def canon(name, value):
    body = _WSP.sub(b" ", value.replace(b"\r\n", b"")).strip(b" ")
    return field_name(name) + b":" + body + b"\r\n"


def parse_tags(text):
    tags = {}
    for spec in text.split(";"):
        name, sep, value = spec.partition("=")
        name = name.strip()
        if sep and name:
            tags[name] = value.strip()
    return tags


def unfold(value):
    return "".join(value.split())


def b64decode(value):
    value = unfold(value)
    return base64.b64decode(value + "=" * (-len(value) % 4))


def strip_b(value):
    parts = value.split(b";")
    for i, part in enumerate(parts):
        name, sep, _ = part.partition(b"=")
        if sep and name.strip(b" \t\r\n").lower() == b"b":
            parts[i] = part[:len(name) + 1]
    return b";".join(parts)


def signed_data(fields, sig_index, names):
    pool = {}
    for i, field in enumerate(fields):
        if i != sig_index:
            pool.setdefault(field_name(field[0]), []).append(field)
    chunks = []
    for name in names:
        found = pool.get(name.strip().lower().encode("latin-1"))
        if found:
            chunks.append(canon(*found.pop()))
    chunks.append(canon(fields[sig_index][0], strip_b(fields[sig_index][1]))[:-2])
    return b"".join(chunks)


def rsa_verify(message, signature, n, e):
    size = (n.bit_length() + 7) // 8
    tail = DIGESTINFO + sha256(message)
    if len(signature) != size or size < len(tail) + 11:
        return False
    value = int.from_bytes(signature, "big")
    if value >= n:
        return False
    block = b"\x00\x01" + b"\xff" * (size - len(tail) - 3) + b"\x00" + tail
    return pow(value, e, n).to_bytes(size, "big") == block


def find_signature(fields):
    for i, (name, value) in enumerate(fields):
        if field_name(name) == b"dkim-signature":
            return i, parse_tags(value.decode("latin-1"))
    return -1, {}


def message_id(fields):
    for name, value in fields:
        if field_name(name) == b"message-id":
            return value.replace(b"\r\n", b"").strip(b" \t").decode("latin-1")
    return ""


def verify_headers(headers_blob, n, e):
    fields = parse_headers(headers_blob)
    index, tags = find_signature(fields)
    info = {
        "domain": tags.get("d", ""),
        "selector": tags.get("s", ""),
        "bh": unfold(tags.get("bh", "")),
        "message_id": message_id(fields),
        "key_bits": n.bit_length(),
        "reason": "",
    }
    names = [name.strip() for name in tags.get("h", "").split(":") if name.strip()]
    header_canon = tags.get("c", "simple/simple").partition("/")[0].strip()
    if index < 0:
        info["reason"] = "no DKIM-Signature header"
    elif tags.get("v") != "1":
        info["reason"] = "unsupported DKIM version"
    elif tags.get("a") != "rsa-sha256":
        info["reason"] = "unsupported algorithm"
    elif header_canon != "relaxed":
        info["reason"] = "unsupported header canonicalization"
    elif not names:
        info["reason"] = "h= tag is empty"
    if info["reason"]:
        return False, info
    try:
        signature = b64decode(tags.get("b", ""))
    except Exception:
        info["reason"] = "b= tag is not base64"
        return False, info
    ok = rsa_verify(signed_data(fields, index, names), signature, n, e)
    info["reason"] = "header signature verified" if ok else "RSA PKCS#1 v1.5 check failed"
    return ok, info

MAX_DOMAIN = 253
MAX_LABEL = 63
MAX_FIELD = 255
MAX_REASON = 96
MAX_BLOB = 16384
MAX_URL = 512
SCHEMA_VERSION = "2"
NO_L = "body length limit not supported"

ZERO_ADDRESS = Address(bytes(20))


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
    text = re.sub(r'"(?:[^"\\]|\\.)*"', "", value.decode("latin-1"))
    addr = text.rpartition("<")[2].partition(">")[0] if "<" in text else text
    if "@" not in addr or text.count("@") > 1 or text.count("<") > 1:
        return ""
    return addr.rpartition("@")[2].strip().lower().strip(".")


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


def body_mode(tags):
    return tags.get("c", "").partition("/")[2].strip().lower() or "simple"


def attest_once(url, blob, domain, selector, n, e, now):
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
    if "l" in tags:
        return failure(NO_L)
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
    for bad, why in (
        ("from" not in names, "from not signed"),
        (any(present.count(name) > names.count(name) for name in names),
         "duplicate signed header"),
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
    if pending == ZERO_ADDRESS or gl.message.sender_address != pending:
        raise gl.vm.UserError("[EXPECTED] pending %s only" % (role,))
    return pending


def shown(address):
    return "" if address == ZERO_ADDRESS else address.as_hex


def require_owner(owner):
    if gl.message.sender_address != owner:
        raise gl.vm.UserError("[EXPECTED] owner only")


def require_amount(amount, held):
    wei = int(amount)
    if wei <= 0 or wei > held:
        raise gl.vm.UserError("[EXPECTED] amount out of range")
    return wei


def cached_key(router, domain, selector):
    final = StorageType.LATEST_FINAL
    try:
        cache = gl.get_contract_at(router).view(state=final).resolve("keycache")
    except Exception:
        return "router unreadable", {}, 0, 0
    if not cache:
        return "router resolves no keycache", {}, 0, 0
    try:
        record = gl.get_contract_at(Address(cache)).view(state=final).key_status(domain, selector)
        state = record.get("state", "")
        if state != "active":
            return ("key " + state if state in ("pending", "rotated", "retired")
                    else "key not registered"), {}, 0, 0
        modulus = int(record["n_hex"], 16)
        exponent = as_number(record["e"])
        if modulus > 1 and exponent > 2:
            return "", record, modulus, exponent
    except Exception:
        return "keycache unreadable", {}, 0, 0
    return "key not registered", {}, 0, 0


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
    router_address: Address
    treasury_address: Address
    pending_treasury_address: Address
    fee_wei: u256
    records: TreeMap[str, Attestation]
    record_count: u256
    ids_of: TreeMap[str, DynArray[str]]
    refusals: TreeMap[str, str]

    def __init__(self, router: str):
        self.owner_address = gl.message.sender_address
        self.pending_owner_address = ZERO_ADDRESS
        self.router_address = as_address(router)
        self.treasury_address = gl.message.sender_address
        self.pending_treasury_address = ZERO_ADDRESS
        self.fee_wei = u256(0)
        self.record_count = u256(0)

    @gl.public.write.payable
    def attest(self, headers_url: str, domain: str, selector: str) -> str:
        url = str(headers_url).strip()
        if not url.startswith("https://") or len(url) > MAX_URL:
            return self._refuse("url not allowed")
        return self._attest(url, b"", domain, selector)

    @gl.public.write.payable
    def attest_inline(self, headers_blob: str, domain: str, selector: str) -> str:
        blob = str(headers_blob).encode("utf-8")
        if len(blob) > MAX_BLOB:
            return self._refuse("blob too large")
        return self._attest("", blob, domain, selector)

    def _refuse(self, reason):
        who = gl.message.sender_address
        self.refusals[who.as_hex] = reason
        paid = int(gl.message.value)
        if paid:
            _Recipient(who).emit_transfer(value=u256(paid))
        return reason

    def _attest(self, url, blob, domain, selector):
        paid = int(gl.message.value)
        if paid < int(self.fee_wei):
            return self._refuse("fee not paid")
        name = normalize(domain, MAX_DOMAIN)
        label = normalize(selector, MAX_LABEL)
        if not name or not label:
            return self._refuse("bad domain or selector")
        why, record, modulus, exponent = cached_key(self.router_address, name, label)
        if why:
            return self._refuse(why)
        now = str(gl.message_raw["datetime"])

        def probe() -> str:
            return attest_once(url, blob, name, label, modulus, exponent, now)

        agreed = str(gl.eq_principle.strict_eq(probe) if url else probe())
        parts = (agreed.split("|") + [""] * 8)[:8]
        if parts[4] == NO_L:
            return self._refuse(NO_L)

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
        self.ids_of.get_or_insert_default(gl.message.sender_address.as_hex).append(record_id)
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
            "schema_version": SCHEMA_VERSION,
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
    def records_of(self, requester: str) -> list:
        try:
            return list(self.ids_of.get(as_address(requester).as_hex, []))
        except Exception:
            return []

    @gl.public.view
    def last_refusal(self, requester: str) -> str:
        try:
            return self.refusals.get(as_address(requester).as_hex, "")
        except Exception:
            return ""

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
    def router(self) -> str:
        return self.router_address.as_hex

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
        _Recipient(self.treasury_address).emit_transfer(value=u256(wei))
        return str(wei)
