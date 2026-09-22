# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

# scripts/build_contract.py splices experiments/dkim-probe/dkim/body.py into
# scripts/contract_template.py and writes contracts/body_probe.py. body.py is
# the one source of the hashing and extraction logic: edit it there, not here.
#
# Privacy: the body is read inside the non-deterministic block and discarded
# there. What leaves that block is two hashes, a byte count, three booleans, a
# weekday word and a fixed reason phrase. The order id is matched and counted,
# never returned, so no order number reaches calldata, storage or a log.
#
# There is no RSA here. The signature over the headers is probe A's question;
# this one only asks whether the body behind a URL is the body a signature
# already claimed, and what can be read out of it once that holds.

from genlayer import *
from dataclasses import dataclass

# @@BODY@@

# The reference message is 116 KB. The cap only stops a wrong URL from being
# hashed at length; a body over it is a recorded result, not a revert.
MAX_BODY = 1048576
MAX_FIELD = 255
MAX_REASON = 96


def http_status(response):
    # The pinned SDK calls the field status; some published examples call it
    # status_code. Accept either rather than fail on the name.
    return int(getattr(response, "status", getattr(response, "status_code", 0)) or 0)


def content_length(response):
    # Response.headers is dict[str, bytes] on the pinned runner and the
    # executor promises nothing about the case of a name. A header that cannot
    # be read is treated as absent: the truncation guard must only fire on a
    # length it actually saw, never on one it failed to parse.
    headers = getattr(response, "headers", None) or {}
    try:
        items = list(headers.items())
    except AttributeError:
        return -1
    for name, value in items:
        if str(name).strip().lower() != "content-length":
            continue
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("ascii", "replace")
        value = str(value).strip()
        return int(value) if value.isdigit() else -1
    return -1


def scrub(value, limit):
    # Every field has to survive a split on "|", and nothing multi-line may
    # reach storage.
    return str(value).replace("|", " ").replace("\r", " ").replace("\n", " ")[:limit]


def canonical(claimed, computed, match, body_bytes, order_id_found, eta_day,
              shipped, reason):
    return "%s|%s|%d|%d|%d|%s|%d|%s" % (
        scrub(claimed, MAX_FIELD),
        scrub(computed, MAX_FIELD),
        1 if match else 0,
        int(body_bytes),
        1 if order_id_found else 0,
        scrub(eta_day, 32),
        1 if shipped else 0,
        scrub(reason, MAX_REASON),
    )


def attest_once(body_url, claimed):
    # Never raises. Anything the probe can hit becomes a stored match=false
    # record with a reason rather than a revert.
    try:
        return attest_body_hash(body_url, claimed)
    except Exception as error:
        return canonical(claimed, "", False, 0, False, "", False,
                         "probe failed: " + type(error).__name__)


def attest_body_hash(body_url, claimed):
    try:
        response = gl.nondet.web.get(body_url, headers={"accept": "*/*"})
    except Exception as error:
        # The class name only: an exception's text can echo the body URL.
        return canonical(claimed, "", False, 0, False, "", False,
                         "body fetch failed: " + type(error).__name__)

    status = http_status(response)
    if status != 200:
        return canonical(claimed, "", False, 0, False, "", False,
                         "body HTTP %d" % (status,))

    # Response.body is declared bytes | None and is handed over untouched, so
    # the hash runs on the octets as received. There is no text path to fall
    # back to, and there must not be: one transcoded byte changes bh.
    raw = response.body or b""
    if not raw or len(raw) > MAX_BODY:
        return canonical(claimed, "", False, len(raw), False, "", False,
                         "body is empty or oversized")

    # A size-capped or interrupted transfer hashes to something plausible, so
    # it has to be caught by length rather than by the result of the hash.
    declared = content_length(response)
    if declared >= 0 and declared != len(raw):
        return canonical(claimed, "", False, len(raw), False, "", False,
                         "body truncated: got %d of %d" % (len(raw), declared))

    computed = body_hash(raw)
    match = computed == claimed
    verdict = "body hash matches bh=" if match else "body hash does not match bh="

    text = first_text_part(raw)
    if not text:
        return canonical(claimed, computed, match, len(raw), False, "", False,
                         verdict + ", no text part")

    fields = extract_fields(text.decode("utf-8", "replace"))
    order_id_found = bool(fields["order_id"])
    return canonical(
        claimed, computed, match, len(raw), order_id_found,
        fields["eta_day"], fields["shipped"],
        verdict if order_id_found else verdict + ", no order id",
    )


@allow_storage
@dataclass
class BodyRecord:
    record_id: u256
    bh_claimed: str
    bh_computed: str
    match: bool
    body_bytes: u256
    order_id_found: bool
    eta_day: str
    shipped: bool
    reason: str


class Contract(gl.Contract):
    records: TreeMap[u256, BodyRecord]
    next_id: u256

    def __init__(self):
        self.next_id = u256(0)

    @gl.public.write
    def attest_body(self, body_url: str, bh_claimed: str) -> str:
        url = str(body_url).strip()
        if not url.startswith("https://") and not url.startswith("http://"):
            raise gl.vm.UserError("[EXPECTED] body_url must be http or https")
        if len(url) > 512:
            raise gl.vm.UserError("[EXPECTED] body_url is too long")

        # A bh= tag is folded across lines in the message it came from, and
        # the folding is not part of the base64.
        claimed = "".join(str(bh_claimed).split())
        if not claimed or len(claimed) > MAX_FIELD:
            raise gl.vm.UserError("[EXPECTED] bh_claimed is empty or too long")

        def probe() -> str:
            return attest_once(url, claimed)

        # strict_eq runs probe() in a sandbox on every validator and compares
        # the two Return values for exact equality: same type, same string,
        # byte for byte, no normalization. Consensus therefore rides on the
        # canonical string alone and never on the fetched bytes, which is what
        # makes a 116 KB body agreeable at all.
        agreed = str(gl.eq_principle.strict_eq(probe))

        parts = agreed.split("|")
        if len(parts) != 8:
            raise gl.vm.UserError("[EXPECTED] malformed attestation string")

        # A body that does not match its bh= is a result, not a failure: it is
        # stored with match=false and a reason, and nothing rolls back.
        record_id = self.next_id
        self.records[record_id] = BodyRecord(
            record_id=record_id,
            bh_claimed=parts[0],
            bh_computed=parts[1],
            match=parts[2] == "1",
            body_bytes=u256(int(parts[3]) if parts[3].isdigit() else 0),
            order_id_found=parts[4] == "1",
            eta_day=parts[5],
            shipped=parts[6] == "1",
            reason=parts[7],
        )
        self.next_id += u256(1)
        return str(record_id)

    @gl.public.view
    def get(self, record_id: u256) -> dict:
        record = self.records[record_id]
        return {
            "id": str(record.record_id),
            "bh_claimed": str(record.bh_claimed),
            "bh_computed": str(record.bh_computed),
            "match": bool(record.match),
            "body_bytes": str(record.body_bytes),
            "order_id_found": bool(record.order_id_found),
            "eta_day": str(record.eta_day),
            "shipped": bool(record.shipped),
            "reason": str(record.reason),
        }

    @gl.public.view
    def count(self) -> int:
        return int(self.next_id)
