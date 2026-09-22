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

# On-chain subset of rfc6376.py. Contract source is charged by the byte on
# Bradbury, so this file is deliberately small: relaxed header canonicalization,
# the DKIM-Signature tag list, the signed data, RSA PKCS#1 v1.5 over SHA-256,
# the DER public key and the DoH TXT answer. No body, no files, no network.
# A hashlib without a SHA-256 implementation raises here; the contract turns
# that into a stored valid=false record rather than a revert.

import base64
import hashlib
import re


def sha256(data):
    return hashlib.sha256(data).digest()


_WSP = re.compile(rb"[ \t]+")
_OBJECT = re.compile(r"\{[^{}]*\}")
_TXT = re.compile(r'"type"\s*:\s*16\b')
_DATA = re.compile(r'"data"\s*:\s*"((?:[^"\\]|\\.)*)"')
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
# RFC 8017 B.1 DigestInfo for id-sha256, and the rsaEncryption OID.
DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")
RSA_OID = bytes.fromhex("06092a864886f70d010101")


def field_name(name):
    return name.strip(b" \t").lower()


def parse_headers(blob):
    # A continuation line belongs to the field above it; folds are re-emitted
    # as CRLF so an LF-only copy canonicalizes like the CRLF original.
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
    # 3.4.2 relaxed: lowercase name, unfold, collapse WSP runs, trim.
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
    # 3.7: empty the b= value, keep the tag. Splitting on ";" is lossless
    # because a semicolon is only ever a tag separator.
    parts = value.split(b";")
    for i, part in enumerate(parts):
        name, sep, _ = part.partition(b"=")
        if sep and name.strip(b" \t\r\n").lower() == b"b":
            parts[i] = part[:len(name) + 1]
    return b";".join(parts)


def signed_data(fields, sig_index, names):
    # 5.4.2: each h= entry consumes the lowest unused instance, so a repeated
    # name is taken bottom up; a name with no field left is oversigning.
    pool = {}
    for i, field in enumerate(fields):
        if i != sig_index:
            pool.setdefault(field_name(field[0]), []).append(field)
    chunks = []
    for name in names:
        found = pool.get(name.strip().lower().encode("latin-1"))
        if found:
            chunks.append(canon(*found.pop()))
    # The signature closes the input with b= empty and no trailing CRLF.
    chunks.append(canon(fields[sig_index][0], strip_b(fields[sig_index][1]))[:-2])
    return b"".join(chunks)


def rsa_verify(message, signature, n, e):
    # Re-encode and compare the whole block: scanning for the DigestInfo is
    # what the Bleichenbacher forgery exploits.
    size = (n.bit_length() + 7) // 8
    tail = DIGESTINFO + sha256(message)
    if len(signature) != size or size < len(tail) + 11:
        return False
    value = int.from_bytes(signature, "big")
    if value >= n:
        return False
    block = b"\x00\x01" + b"\xff" * (size - len(tail) - 3) + b"\x00" + tail
    return pow(value, e, n).to_bytes(size, "big") == block


def read_tlv(der, at):
    # Definite lengths only, which is all X.509 emits.
    if at + 2 > len(der):
        raise ValueError("truncated DER element")
    tag, size, at = der[at], der[at + 1], at + 2
    if size & 0x80:
        count = size & 0x7F
        if count == 0 or count > 4 or at + count > len(der):
            raise ValueError("unsupported DER length")
        size = int.from_bytes(der[at:at + count], "big")
        at += count
    if at + size > len(der):
        raise ValueError("truncated DER value")
    return tag, der[at:at + size], at + size


def rsa_key(der):
    tag, modulus, at = read_tlv(der, 0)
    tag2, exponent, _ = read_tlv(der, at)
    if tag != 0x02 or tag2 != 0x02:
        raise ValueError("RSAPublicKey is not two INTEGERs")
    return int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")


def decode_spki(der):
    tag, outer, _ = read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("public key is not a DER SEQUENCE")
    tag, first, at = read_tlv(outer, 0)
    if tag == 0x02:
        # A few published records still carry a bare PKCS#1 RSAPublicKey.
        return rsa_key(outer)
    if tag != 0x30 or RSA_OID not in first:
        raise ValueError("public key algorithm is not rsaEncryption")
    tag, bits, _ = read_tlv(outer, at)
    if tag != 0x03 or not bits or bits[0] != 0:
        raise ValueError("unexpected subjectPublicKey BIT STRING")
    tag, key, _ = read_tlv(bits, 1)
    if tag != 0x30:
        raise ValueError("subjectPublicKey is not an RSAPublicKey")
    return rsa_key(key)


def unquote(data):
    pieces = _QUOTED.findall(data.replace('\\"', '"').replace("\\\\", "\\"))
    return "".join(pieces) if pieces else data


def txt_from_doh(payload):
    # A delegated selector answers with a CNAME hop first, so filter by type,
    # and a long key arrives split into several character-strings.
    chunks = []
    for obj in _OBJECT.findall(payload):
        found = _DATA.search(obj) if _TXT.search(obj) else None
        if found:
            chunks.append(unquote(found.group(1)))
    if not chunks:
        raise ValueError("no TXT record in the DoH answer")
    return "".join(chunks)


def key_from_txt(txt):
    tags = parse_tags(txt)
    if tags.get("v", "DKIM1") != "DKIM1" or tags.get("k", "rsa") != "rsa":
        raise ValueError("unsupported key record")
    published = unfold(tags.get("p", ""))
    if not published:
        raise ValueError("key has been revoked (empty p=)")
    return decode_spki(b64decode(published))


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
    # Only relaxed is carried on chain; every signer this probe targets
    # publishes c=relaxed/something.
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
