# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

# Lacre: a signed-evidence primitive for GenLayer.
# By Insidr Labs, MIT license.

# A minimal consumer of Lacre, meant to be copied into another project. It
# holds the Router address and nothing else of Lacre's, and asks the two
# questions an app has before it acts: did this sender sign it, and does the
# signed body say it shipped. The rules it follows are docs/interfaces.md,
# section 5; what it leaves to the copier is in docs/direct-use.md. It is an
# example and is not deployed.

from genlayer import *
from genlayer.py.public_abi import StorageType

# What mark_delivered accepts. A copy sets its own sender and key floor; the
# amazon.com key is 1024 bits, so a higher floor refuses every record today.
DOMAIN = "amazon.com"
MIN_KEY_BITS = 1024

# The Router name of each extraction lane.
LANES = {"patterns": "extractor", "llm": "extractor_llm"}

# records_of grows with every extraction a requester makes and is never
# trimmed, so only the newest MAX_SCAN are read: one check costs a bounded
# number of cross-contract reads however busy the requester is.
MAX_SCAN = 32


def as_address(value):
    try:
        return Address(str(value).strip())
    except Exception:
        raise gl.vm.UserError("[EXPECTED] not a 20 byte hex address")


def final(address):
    # A record read before FINALIZED can still be appealed away (rule 1), so
    # nothing here reads any other state.
    return gl.get_contract_at(address).view(state=StorageType.LATEST_FINAL)


def resolved(router, name):
    # Resolved on every use and never stored: when the Router moves a name
    # after its 48 hour notice, this contract follows without a redeploy.
    found = str(final(router).resolve(name))
    return Address(found) if found else None


def attested(router, record_id, domain, min_key_bits):
    """(Verifier, record) for a record that passes check_for, or (None, {}).

    Never raises: an unreadable Router or Verifier reads as no attestation.
    """
    try:
        verifier = resolved(router, "verifier")
        if verifier is None:
            return None, {}
        record = dict(final(verifier).get(record_id))
        if not record:
            return None, {}
        # check_for binds a requester. This app accepts a record whoever paid
        # for it, since the requester proves nothing about who received the
        # message (rule 6), so the record's own is passed and the Verifier's
        # own comparisons decide validity, alignment, domain and key size
        # (rule 3). An app that pays out to the requester passes its own.
        ok = final(verifier).check_for(record_id, str(domain), int(min_key_bits),
                                       str(record.get("requester", "")))
        return (verifier, record) if ok is True else (None, {})
    except Exception:
        return None, {}


def shipped(router, record_id, lane):
    """Whether the lane holds a matched, shipped extraction of record_id.

    Never raises. The Extractors index their records by requester, not by
    Verifier record, so the extraction is looked for among those of the
    requester who attested it, which is how tools/attest.py and
    tools/extract.py, run from one wallet, and the gateway both leave them.
    """
    name = LANES.get(str(lane).strip().lower())
    if name is None:
        return False
    try:
        verifier = resolved(router, "verifier")
        extractor = resolved(router, name)
        if verifier is None or extractor is None:
            return False
        record = dict(final(verifier).get(record_id))
        if not record:
            return False
        ids = list(final(extractor).records_of(str(record.get("requester", ""))))
        for extraction_id in reversed(ids[-MAX_SCAN:]):
            held = dict(final(extractor).get_record(str(extraction_id)))
            # Record ids restart at "0" on every Verifier, so an extraction
            # of the same id against an earlier Verifier is another message.
            if (held.get("record_id") == record_id
                    and str(held.get("verifier", "")).lower() == verifier.as_hex.lower()
                    and held.get("match") is True
                    and held.get("reason") == "extracted"
                    and held.get("shipped") is True):
                return True
    except Exception:
        return False
    return False


class Contract(gl.Contract):
    router_address: Address
    # "<verifier>/<record id>" to the datetime of the call that marked it. The
    # Verifier is part of the key for the same reason as above (rule 4).
    delivered: TreeMap[str, str]
    # The signed values of each delivered message to its "<verifier>/<record
    # id>". One message can be attested any number of times, each a new
    # record, so acting once per message is this contract's job (rule 5).
    messages: TreeMap[str, str]

    def __init__(self, router: str):
        self.router_address = as_address(router)

    @gl.public.view
    def require_attestation(self, record_id: str, domain: str, min_key_bits: int) -> bool:
        verifier, _ = attested(self.router_address, str(record_id).strip(), domain,
                               min_key_bits)
        return verifier is not None

    @gl.public.view
    def require_shipped(self, record_id: str, lane: str) -> bool:
        return shipped(self.router_address, str(record_id).strip(), lane)

    @gl.public.write
    def mark_delivered(self, record_id: str, lane: str) -> str:
        source = str(record_id).strip()
        verifier, record = attested(self.router_address, source, DOMAIN, MIN_KEY_BITS)
        if verifier is None:
            raise gl.vm.UserError("[EXPECTED] no accepted attestation")
        if not shipped(self.router_address, source, lane):
            raise gl.vm.UserError("[EXPECTED] no shipped extraction")
        key = verifier.as_hex.lower() + "/" + source
        # Signed values only: message_id_sha256 may come from an unsigned
        # header, so whoever submits the blob could vary it.
        message = "|".join(str(record.get(field, "")) for field in
                           ("domain", "selector", "bh", "signed_at"))
        if message in self.messages:
            raise gl.vm.UserError("[EXPECTED] already delivered")
        self.messages[message] = key
        self.delivered[key] = str(gl.message_raw["datetime"])
        return key

    @gl.public.view
    def delivered_at(self, verifier: str, record_id: str) -> str:
        # A write's return value cannot be read from the chain (rule 15), so
        # what mark_delivered stored is read here: "" when never marked.
        return self.delivered.get(str(verifier).strip().lower() + "/" + str(record_id).strip(), "")

    @gl.public.view
    def router(self) -> str:
        return self.router_address.as_hex
