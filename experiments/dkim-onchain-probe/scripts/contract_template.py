# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

# scripts/build_contract.py splices experiments/dkim-probe/dkim/core.py into
# scripts/contract_template.py and writes contracts/dkim_probe.py. core.py is
# the one source of the verification logic: edit it there, not here.
#
# Privacy: no header value, address, subject or message id reaches calldata,
# storage or a log. The contract is handed a URL and nothing else; the blob is
# read inside the non-deterministic block and only the canonical string leaves
# it.

from genlayer import *
from dataclasses import dataclass

# @@CORE@@

# Google's DNS over HTTPS endpoint, reachable from Bradbury validators.
DOH_URL = "https://dns.google/resolve?name=%s._domainkey.%s&type=TXT"

# A blob is one DKIM-Signature plus the headers it signs: under 1 KB in
# practice. The cap only stops a wrong URL from being parsed at length.
MAX_BLOB = 65536
MAX_FIELD = 255
MAX_REASON = 96


def http_status(response):
    # The pinned SDK calls the field status; some published examples call it
    # status_code. Accept either rather than fail on the name.
    return int(getattr(response, "status", getattr(response, "status_code", 0)) or 0)


def scrub(value, limit):
    # Every field has to survive a split on "|", and nothing multi-line may
    # reach storage.
    return str(value).replace("|", " ").replace("\r", " ").replace("\n", " ")[:limit]


def canonical(domain, selector, bh, mid_hash, key_bits, ok, reason):
    return "%s|%s|%s|%s|%d|%d|%s" % (
        scrub(domain, MAX_FIELD),
        scrub(selector, MAX_FIELD),
        scrub(bh, MAX_FIELD),
        scrub(mid_hash, 64),
        int(key_bits),
        1 if ok else 0,
        scrub(reason, MAX_REASON),
    )


def attest_once(blob_url):
    # Never raises. Anything the probe can hit, including a hashlib with no
    # SHA-256 implementation behind it, becomes a stored valid=false record
    # rather than a revert.
    try:
        return attest_verified(blob_url)
    except Exception as error:
        return canonical("", "", "", "", 0, False, "probe failed: " + type(error).__name__)


def attest_verified(blob_url):
    # Everything the message carries stays inside this function. What leaves
    # is the canonical string: domain, selector, bh, the SHA-256 of the
    # Message-ID, the key size, the verdict and a fixed reason phrase.
    try:
        response = gl.nondet.web.get(blob_url, headers={"accept": "text/plain"})
    except Exception as error:
        return canonical("", "", "", "", 0, False, "blob fetch failed: " + type(error).__name__)

    status = http_status(response)
    if status != 200:
        return canonical("", "", "", "", 0, False, "blob HTTP %d" % (status,))
    blob = response.body or b""
    if not blob or len(blob) > MAX_BLOB:
        return canonical("", "", "", "", 0, False, "blob is empty or oversized")

    fields = parse_headers(blob)
    index, tags = find_signature(fields)
    identifier = message_id(fields)
    mid_hash = sha256(identifier.encode("utf-8")).hex() if identifier else ""
    if index < 0:
        return canonical("", "", "", mid_hash, 0, False, "no DKIM-Signature in the blob")

    domain = tags.get("d", "")
    selector = tags.get("s", "")
    bh = unfold(tags.get("bh", ""))
    if not domain or not selector:
        return canonical(domain, selector, bh, mid_hash, 0, False, "d= or s= is missing")

    try:
        answer = gl.nondet.web.get(
            DOH_URL % (selector, domain), headers={"accept": "application/dns-json"}
        )
        n, e = key_from_txt(txt_from_doh((answer.body or b"").decode("utf-8", "replace")))
    except Exception as error:
        # The class name only: an exception's text could echo the blob URL.
        return canonical(
            domain, selector, bh, mid_hash, 0, False,
            "key lookup failed: " + type(error).__name__,
        )

    ok, info = verify_headers(blob, n, e)
    return canonical(
        info["domain"], info["selector"], info["bh"], mid_hash,
        info["key_bits"], ok, info["reason"],
    )


@allow_storage
@dataclass
class Attestation:
    record_id: u256
    domain: str
    selector: str
    bh: str
    message_id_sha256: str
    key_bits: u256
    valid: bool
    reason: str


class Contract(gl.Contract):
    records: TreeMap[u256, Attestation]
    next_id: u256

    def __init__(self):
        self.next_id = u256(0)

    @gl.public.write
    def attest(self, blob_url: str) -> str:
        url = str(blob_url).strip()
        if not url.startswith("https://") and not url.startswith("http://"):
            raise gl.vm.UserError("[EXPECTED] blob_url must be http or https")
        if len(url) > 512:
            raise gl.vm.UserError("[EXPECTED] blob_url is too long")

        def probe() -> str:
            return attest_once(url)

        # strict_eq runs probe() in a sandbox on every validator and compares
        # the two Return values for exact equality: same type, same string,
        # byte for byte, no normalization. Consensus therefore rides on the
        # canonical string alone and never on the fetched bytes.
        agreed = str(gl.eq_principle.strict_eq(probe))

        parts = agreed.split("|")
        if len(parts) != 7:
            raise gl.vm.UserError("[EXPECTED] malformed attestation string")

        # An invalid signature is a result, not a failure: it is stored with
        # valid=false and the reason, so the probe never rolls back.
        record_id = self.next_id
        self.records[record_id] = Attestation(
            record_id=record_id,
            domain=parts[0],
            selector=parts[1],
            bh=parts[2],
            message_id_sha256=parts[3],
            key_bits=u256(int(parts[4]) if parts[4].isdigit() else 0),
            valid=parts[5] == "1",
            reason=parts[6],
        )
        self.next_id += u256(1)
        return str(record_id)

    @gl.public.view
    def get(self, record_id: u256) -> dict:
        record = self.records[record_id]
        return {
            "id": str(record.record_id),
            "domain": str(record.domain),
            "selector": str(record.selector),
            "bh": str(record.bh),
            "message_id_sha256": str(record.message_id_sha256),
            "key_bits": str(record.key_bits),
            "valid": bool(record.valid),
            "reason": str(record.reason),
        }

    @gl.public.view
    def count(self) -> int:
        return int(self.next_id)
