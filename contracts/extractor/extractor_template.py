# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

# build.py splices lacre/dkimbody.py and lacre/patterns.py in at the markers
# below and writes extractor.py: edit those or this template, never the built
# file. Design notes, the record format and the refusals: docs/extractor.md.

from genlayer import *
from genlayer.py.public_abi import StorageType
from dataclasses import dataclass

# @@DKIMBODY@@

# @@PATTERNS@@

ZERO_ADDRESS = Address(bytes(20))
# The fields of Extraction, in the order get_record returns them.
FIELDS = ("verifier record_id domain bh match reason patterns_sha256 shipped eta_day eta_date"
          " order_id_found signed_at requester extracted_at fee_paid").split()


# Empty on purpose: the only way to hand value to a chain-layer address.
@gl.evm.contract_interface
class _Recipient:
    class View:
        pass

    class Write:
        pass


def normalize(value):
    return str(value).strip().lower().strip(".")


def as_address(value):
    try:
        return Address(str(value).strip())
    except Exception:
        raise gl.vm.UserError("[EXPECTED] not a 20 byte hex address")


def proposed(value):
    candidate = as_address(value)
    if candidate == ZERO_ADDRESS:
        raise gl.vm.UserError("[EXPECTED] the zero address cannot be proposed")
    return candidate


def claimed(pending, role):
    if pending == ZERO_ADDRESS or gl.message.sender_address != pending:
        raise gl.vm.UserError("[EXPECTED] pending %s only" % (role,))
    return pending


def holder(requester):
    try:
        return as_address(requester).as_hex
    except Exception:
        return ""


def shown(address):
    return "" if address == ZERO_ADDRESS else address.as_hex


def require_owner(owner):
    if gl.message.sender_address != owner:
        raise gl.vm.UserError("[EXPECTED] owner only")


def verified(router, record_id):
    # The Verifier is resolved on every call and never stored, so the Router
    # owner can replace it without a new Extractor. Nothing here may raise:
    # a miss is a refusal.
    final = StorageType.LATEST_FINAL
    why = "router unreadable"
    try:
        verifier = gl.get_contract_at(router).view(state=final).resolve("verifier")
        if not verifier:
            return "router resolves no verifier", None, {}
        why = "verifier unreadable"
        address = Address(verifier)
        record = dict(gl.get_contract_at(address).view(state=final).get(record_id))
    except Exception:
        return why, None, {}
    return ("record not found" if not record
            else "record not valid" if record.get("valid") is not True
            else "record not aligned" if record.get("aligned") is not True
            # The Verifier stores whatever follows the slash in c=, unchecked.
            else "body canonicalization not supported"
            if record.get("body_canon") not in ("simple", "relaxed")
            else ""), address, record


def fetched(url, bh, canon, document):
    # Never raises: a failure here must be a stored record, not a revert. An
    # exception is reported by class name only, as its text can echo the URL.
    try:
        response = gl.nondet.web.get(url, headers={"accept": "*/*"})
        status = int(getattr(response, "status", 0) or 0)
        if status == 200:
            # Hashed as the octets received; one transcoded byte changes bh.
            return extract_body(response.body or b"", bh, canon, document)
        reason = "body HTTP %d" % (status,)
    except Exception as error:
        reason = "body fetch failed: " + type(error).__name__
    return canonical(reason, document_sha256(document))


@allow_storage
@dataclass
class Extraction:
    verifier: Address
    record_id: str
    domain: str
    bh: str
    match: bool
    reason: str
    patterns_sha256: str
    shipped: bool
    eta_day: str
    eta_date: str
    order_id_found: bool
    signed_at: u256
    requester: Address
    extracted_at: str
    fee_paid: u256


class Contract(gl.Contract):
    owner_address: Address
    pending_owner_address: Address
    router_address: Address
    treasury_address: Address
    pending_treasury_address: Address
    fee_wei: u256
    records: TreeMap[str, Extraction]
    record_count: u256
    documents: TreeMap[str, str]
    # The return value of a write cannot be read from the chain, so what each
    # call did has to be a view.
    ids_of: TreeMap[str, DynArray[str]]
    refusals: TreeMap[str, str]

    def __init__(self, router: str):
        self.owner_address = gl.message.sender_address
        self.treasury_address = gl.message.sender_address
        self.router_address = as_address(router)

    def _refuse(self, reason):
        # A revert keeps what the call carried, so a refusal hands it back
        # itself, by external message, settling on finalization.
        who = gl.message.sender_address
        self.refusals[who.as_hex] = reason
        if gl.message.value:
            _Recipient(who).emit_transfer(value=gl.message.value)
        return reason

    @gl.public.write.payable
    def extract(self, record_id: str, body_url: str) -> str:
        if gl.message.value < self.fee_wei:
            return self._refuse("fee not paid")
        source = str(record_id).strip()
        why, verifier, record = verified(self.router_address, source)
        if why:
            return self._refuse(why)
        domain = str(record.get("domain"))
        document = self.documents.get(domain)
        if document is None:
            return self._refuse("no patterns for domain")
        url = str(body_url).strip()
        if not url.startswith("https://") or len(url) > 512:
            return self._refuse("url not allowed")
        bh = str(record.get("bh"))
        canon = str(record.get("body_canon"))

        def probe() -> str:
            return fetched(url, bh, canon, document)

        parts = (str(gl.eq_principle.strict_eq(probe)).split("|") + [""] * 7)[:7]
        # Only the agreed string reaches storage, and each field is held to
        # its shape again here, so a mismatch can never carry a value.
        match = parts[0] == "1"
        signed = str(record.get("signed_at"))
        new_id = str(self.record_count)
        self.records[new_id] = Extraction(
            verifier=verifier, record_id=source, domain=domain, bh=bh,
            match=match, reason=parts[6][:96], patterns_sha256=document_sha256(document),
            shipped=match and parts[1] == "1",
            eta_day=parts[2] if match and parts[2] in WEEKDAYS else "",
            eta_date=parts[3] if match and re.fullmatch("[0-9]{4}-[0-9]{2}-[0-9]{2}", parts[3]) else "",
            order_id_found=match and parts[4] == "1",
            signed_at=u256(int(signed) if signed.isascii() and signed.isdigit() else 0),
            requester=gl.message.sender_address,
            extracted_at=str(gl.message_raw["datetime"]),
            fee_paid=u256(gl.message.value),
        )
        self.record_count += 1
        self.ids_of.get_or_insert_default(gl.message.sender_address.as_hex).append(new_id)
        return new_id

    @gl.public.write
    def set_patterns(self, domain: str, patterns_json: str) -> str:
        require_owner(self.owner_address)
        name = normalize(domain)
        if not name:
            raise gl.vm.UserError("[EXPECTED] bad domain")
        try:
            load_patterns(patterns_json)
        except ValueError as error:
            raise gl.vm.UserError("[EXPECTED] " + str(error))
        # Each record keeps the digest of the document that read it, so a
        # replacement changes later records only.
        self.documents[name] = clean_document(patterns_json)
        return document_sha256(patterns_json)

    @gl.public.view
    def patterns(self, domain: str) -> str:
        return self.documents.get(normalize(domain), "")

    @gl.public.view
    def patterns_sha256(self, domain: str) -> str:
        document = self.patterns(domain)
        return document_sha256(document) if document else ""

    @gl.public.view
    def get_record(self, id: str) -> dict:
        held = self.records.get(str(id))
        if held is None:
            return {}
        out = {"id": str(id), "schema_version": "1", "method": "patterns"}
        for key in FIELDS:
            value = getattr(held, key)
            # Addresses as hex and u256 as decimal strings, as the Verifier
            # returns them; booleans and strings as they are.
            out[key] = (value.as_hex if isinstance(value, Address)
                        else value if isinstance(value, (bool, str)) else str(value))
        return out

    @gl.public.view
    def records_of(self, requester: str) -> list:
        return list(self.ids_of.get(holder(requester), []))

    @gl.public.view
    def last_refusal(self, requester: str) -> str:
        return self.refusals.get(holder(requester), "")

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
        if new_fee < 0:
            raise gl.vm.UserError("[EXPECTED] negative fee")
        self.fee_wei = u256(new_fee)
        return str(new_fee)

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
        if amount <= 0 or amount > self.balance:
            raise gl.vm.UserError("[EXPECTED] amount out of range")
        # Settles on finalization: the balance does not move in this call.
        _Recipient(self.treasury_address).emit_transfer(value=u256(amount))
        return str(amount)
