"""RFC 6376 verification core in pure Python.

Only the standard library is used, and only the parts that a GenVM contract can
be expected to have: int, bytes, re, base64, hashlib, hmac. No ssl, no socket,
no third party crypto. Every function is named after the RFC step it implements
so it can be lifted into a contract method one at a time.
"""

import base64
import hashlib
import hmac
import re

__all__ = [
    "split_message",
    "parse_header_fields",
    "canonicalize_header_relaxed",
    "canonicalize_header_simple",
    "canonicalize_body_simple",
    "canonicalize_body_relaxed",
    "normalize_line_endings",
    "body_hash",
    "parse_tag_list",
    "strip_signature_value",
    "build_signed_data",
    "pkcs1_v15_encode_sha256",
    "rsa_verify_pkcs1_v15_sha256",
    "parse_key_record",
    "decode_subject_public_key_info",
    "public_key_from_record",
    "find_signature",
    "verify_headers",
]

_WSP_RUN = re.compile(rb"[ \t]+")

LINE_ENDING_MODES = ("as-is", "crlf")

HEADER_CANONICALIZATIONS = {}
BODY_CANONICALIZATIONS = {}

# RFC 8017 appendix B.1 DigestInfo for id-sha256, DER encoded with a NULL
# parameter. PKCS#1 v1.5 verification is a byte comparison against this prefix
# plus the digest, so the constant is the whole algorithm agility we need.
SHA256_DIGESTINFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

# 1.2.840.113549.1.1.1 rsaEncryption, as it appears inside AlgorithmIdentifier.
RSA_ENCRYPTION_OID = bytes.fromhex("06092a864886f70d010101")


# --- RFC 5322 section 2.1: message structure -------------------------------


def split_message(raw):
    """Split a raw message into the header block and the body.

    The empty line that ends the header block is not returned with either part.
    Both CRLF and bare LF separators are accepted because a message copied out
    of a webmail "show original" view has already lost its CRLFs.
    """
    found = [(raw.find(sep), sep) for sep in (b"\r\n\r\n", b"\n\n")]
    found = [(index, sep) for index, sep in found if index != -1]
    if not found:
        return raw, b""
    index, sep = min(found)
    return raw[:index], raw[index + len(sep):]


def parse_header_fields(raw_headers):
    """Return [(name, value)] in original order, folds preserved.

    The value excludes the final line terminator but keeps internal folds,
    which are re-emitted as CRLF so that a LF-only copy of a message hashes the
    same way as the CRLF original. Lines without a colon are dropped, which
    discards an mbox "From " separator without disturbing the field order.
    """
    fields = []
    for line in raw_headers.split(b"\n"):
        if line.endswith(b"\r"):
            line = line[:-1]
        if line[:1] in (b" ", b"\t"):
            if fields:
                name, value = fields[-1]
                fields[-1] = (name, value + b"\r\n" + line)
            continue
        name, sep, value = line.partition(b":")
        if sep:
            fields.append((name, value))
    return fields


def field_name(name):
    """Comparable form of a header field name (section 3.4.2, first step)."""
    return name.strip(b" \t").lower()


# --- RFC 6376 section 3.4: canonicalization --------------------------------


def canonicalize_header_simple(name, value):
    """Section 3.4.1: the field is presented exactly as it appears."""
    return name + b":" + value + b"\r\n"


def canonicalize_header_relaxed(name, value):
    """Section 3.4.2: lowercase name, unfold, collapse WSP, trim around colon."""
    value = value.replace(b"\r\n", b"")
    value = _WSP_RUN.sub(b" ", value)
    return field_name(name) + b":" + value.strip(b" ") + b"\r\n"


def canonicalize_body_simple(body):
    """Section 3.4.3: trailing empty lines collapse to a single CRLF."""
    if body and not body.endswith(b"\r\n"):
        body += b"\r\n"
    while body.endswith(b"\r\n\r\n"):
        body = body[:-2]
    return body or b"\r\n"


def canonicalize_body_relaxed(body):
    """Section 3.4.4: reduce in-line WSP, then drop trailing empty lines.

    An empty body canonicalizes to the null input here, not to a CRLF.
    """
    body = _WSP_RUN.sub(b" ", body)
    body = body.replace(b" \r\n", b"\r\n")
    while body.endswith(b"\r\n\r\n"):
        body = body[:-2]
    if body == b"\r\n":
        return b""
    if body and not body.endswith(b"\r\n"):
        body += b"\r\n"
    return body


HEADER_CANONICALIZATIONS.update(
    {"simple": canonicalize_header_simple, "relaxed": canonicalize_header_relaxed}
)
BODY_CANONICALIZATIONS.update(
    {"simple": canonicalize_body_simple, "relaxed": canonicalize_body_relaxed}
)


def parse_canonicalization(tag):
    """Section 3.5 c= tag. A missing body algorithm means "simple"."""
    header, _, body = (tag or "simple/simple").partition("/")
    header = header.strip() or "simple"
    body = body.strip() or "simple"
    if header not in HEADER_CANONICALIZATIONS or body not in BODY_CANONICALIZATIONS:
        raise ValueError("unsupported canonicalization %r" % (tag,))
    return header, body


def normalize_line_endings(data, mode):
    """Bring a body to the line endings DKIM assumes were on the wire.

    "as-is" trusts the file, "crlf" rewrites every lone LF. Bare CR is left
    alone: it is data, not a terminator, on every path we care about.
    """
    if mode == "as-is":
        return data
    if mode == "crlf":
        return data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    raise ValueError("unknown line ending mode %r" % (mode,))


# --- RFC 6376 section 3.7 hash step 1: the body hash -----------------------


def body_hash(raw_body_bytes, line_ending_mode="as-is", canonicalization="simple"):
    """Return the base64 bh= value for a body. Never needs the headers."""
    body = normalize_line_endings(raw_body_bytes, line_ending_mode)
    canonical = BODY_CANONICALIZATIONS[canonicalization](body)
    return base64.b64encode(hashlib.sha256(canonical).digest()).decode("ascii")


# --- RFC 6376 section 3.2: tag lists ---------------------------------------


def parse_tag_list(text):
    """Section 3.2. Whitespace around a tag name or value is not significant."""
    tags = {}
    for spec in text.split(";"):
        name, sep, value = spec.partition("=")
        name = name.strip()
        if sep and name:
            tags[name] = value.strip()
    return tags


def unfold_tag_value(value):
    """base64 tag values carry FWS that is not part of the encoding."""
    return "".join(value.split())


def decode_base64(value):
    """Tolerate the missing padding some published key records ship with."""
    value = unfold_tag_value(value)
    return base64.b64decode(value + "=" * (-len(value) % 4))


# --- RFC 6376 section 3.7 hash step 2: the signed header data --------------


def strip_signature_value(value):
    """Empty the b= tag, with the whitespace around its value (section 3.7).

    Splitting on ";" and rejoining is lossless: a semicolon only ever appears
    as a tag separator, so every other byte of the field keeps its position.
    """
    parts = value.split(b";")
    for index, part in enumerate(parts):
        name, sep, _ = part.partition(b"=")
        if sep and name.strip(b" \t\r\n").lower() == b"b":
            parts[index] = part[: len(name) + 1]
    return b";".join(parts)


def select_signed_fields(fields, h_names, skip_index=None):
    """Section 5.4.2: each h= entry consumes the lowest unused instance.

    A name in h= with no matching field contributes nothing; that is the
    "oversigning" trick and it must not be treated as an error.
    """
    pool = {}
    for index, (name, value) in enumerate(fields):
        if index == skip_index:
            continue
        pool.setdefault(field_name(name), []).append((name, value))
    selected = []
    for entry in h_names:
        instances = pool.get(entry.strip().lower().encode("latin-1"))
        if instances:
            selected.append(instances.pop())
    return selected


def build_signed_data(fields, sig_index, h_names, canonicalize):
    """Section 3.7 hash step 2: the h= fields, then the signature with b= empty.

    The signature field is appended without its trailing CRLF.
    """
    chunks = [
        canonicalize(name, value)
        for name, value in select_signed_fields(fields, h_names, skip_index=sig_index)
    ]
    sig_name, sig_value = fields[sig_index]
    tail = canonicalize(sig_name, strip_signature_value(sig_value))
    if tail.endswith(b"\r\n"):
        tail = tail[:-2]
    chunks.append(tail)
    return b"".join(chunks)


# --- RFC 8017: RSASSA-PKCS1-v1_5 verification ------------------------------


def pkcs1_v15_encode_sha256(digest, modulus_bytes):
    """RFC 8017 section 9.2 EMSA-PKCS1-v1_5 encoding for a SHA-256 digest."""
    suffix = SHA256_DIGESTINFO_PREFIX + digest
    if modulus_bytes < len(suffix) + 11:
        raise ValueError("modulus too short for a SHA-256 PKCS#1 v1.5 signature")
    return b"\x00\x01" + b"\xff" * (modulus_bytes - len(suffix) - 3) + b"\x00" + suffix


def rsa_verify_pkcs1_v15_sha256(message, signature, n, e):
    """Verify by re-encoding and comparing, never by parsing the padding.

    Comparing the full encoded block rules out the classic Bleichenbacher
    forgery against implementations that only scan for the DigestInfo.
    """
    modulus_bytes = (n.bit_length() + 7) // 8
    if len(signature) != modulus_bytes:
        return False
    value = int.from_bytes(signature, "big")
    if value >= n:
        return False
    try:
        expected = pkcs1_v15_encode_sha256(hashlib.sha256(message).digest(), modulus_bytes)
    except ValueError:
        return False
    recovered = pow(value, e, n).to_bytes(modulus_bytes, "big")
    return hmac.compare_digest(recovered, expected)


# --- RFC 6376 section 3.6.1: the public key record -------------------------


def parse_key_record(txt):
    """Section 3.6.1 tags. Defaults are applied for v=, k= and t=."""
    tags = parse_tag_list(txt)
    return {
        "v": tags.get("v", "DKIM1"),
        "k": tags.get("k", "rsa"),
        "p": unfold_tag_value(tags.get("p", "")),
        "h": tags.get("h", ""),
        "t": tags.get("t", ""),
    }


def _read_der_tlv(data, offset):
    """Minimal DER reader: definite lengths only, which is all X.509 emits."""
    if offset + 2 > len(data):
        raise ValueError("truncated DER element")
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, data[offset:end], end


def decode_subject_public_key_info(der):
    """Decode a DER SubjectPublicKeyInfo into (n, e).

    A bare PKCS#1 RSAPublicKey is accepted too: a few published records still
    carry one, and telling them apart costs one tag check.
    """
    tag, outer, _ = _read_der_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("public key is not a DER SEQUENCE")
    tag, first, offset = _read_der_tlv(outer, 0)
    if tag == 0x02:
        return _decode_rsa_public_key(outer)
    if tag != 0x30:
        raise ValueError("unexpected AlgorithmIdentifier")
    if RSA_ENCRYPTION_OID not in first:
        raise ValueError("public key algorithm is not rsaEncryption")
    tag, bit_string, _ = _read_der_tlv(outer, offset)
    if tag != 0x03 or not bit_string or bit_string[0] != 0:
        raise ValueError("unexpected subjectPublicKey BIT STRING")
    tag, key, _ = _read_der_tlv(bit_string, 1)
    if tag != 0x30:
        raise ValueError("subjectPublicKey is not an RSAPublicKey")
    return _decode_rsa_public_key(key)


def _decode_rsa_public_key(der):
    """RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }."""
    tag, modulus, offset = _read_der_tlv(der, 0)
    if tag != 0x02:
        raise ValueError("modulus is not an INTEGER")
    tag, exponent, _ = _read_der_tlv(der, offset)
    if tag != 0x02:
        raise ValueError("exponent is not an INTEGER")
    return int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")


def public_key_from_record(txt):
    """Turn a published TXT record into (n, e, record)."""
    record = parse_key_record(txt)
    if record["v"] != "DKIM1":
        raise ValueError("unsupported key record version %r" % (record["v"],))
    if record["k"] != "rsa":
        raise ValueError("unsupported key type %r" % (record["k"],))
    if not record["p"]:
        raise ValueError("key has been revoked (empty p= tag)")
    n, e = decode_subject_public_key_info(decode_base64(record["p"]))
    return n, e, record


# --- entry points that mirror the contract methods -------------------------


def find_signature(fields, selector, domain):
    """Locate the DKIM-Signature whose s= and d= match. Order is preserved."""
    for index, (name, value) in enumerate(fields):
        if field_name(name) != b"dkim-signature":
            continue
        tags = parse_tag_list(value.decode("latin-1"))
        if tags.get("s") == selector and tags.get("d") == domain:
            return index, tags
    return None


def verify_headers(raw_headers_bytes, selector, domain, pubkey_n, pubkey_e):
    """Verify the header signature alone. The body is never needed here.

    Returns signed_fields, bh_from_header, valid and reason, plus the parsed
    tags so a caller can report on them without re-parsing the field.
    """
    result = {
        "signed_fields": [],
        "bh_from_header": "",
        "valid": False,
        "reason": "",
        "tags": {},
        "algorithm": "",
        "canonicalization": "",
        "has_length_tag": False,
        "signed_data_bytes": 0,
    }
    fields = parse_header_fields(raw_headers_bytes)
    located = find_signature(fields, selector, domain)
    if located is None:
        result["reason"] = "no DKIM-Signature with s=%s and d=%s" % (selector, domain)
        return result

    sig_index, tags = located
    result["tags"] = tags
    result["algorithm"] = tags.get("a", "")
    result["canonicalization"] = tags.get("c", "simple/simple")
    result["has_length_tag"] = "l" in tags
    result["bh_from_header"] = unfold_tag_value(tags.get("bh", ""))
    result["signed_fields"] = [
        entry.strip() for entry in tags.get("h", "").split(":") if entry.strip()
    ]

    if tags.get("v") != "1":
        result["reason"] = "unsupported DKIM version %r" % (tags.get("v"),)
        return result
    if result["algorithm"] != "rsa-sha256":
        result["reason"] = "unsupported algorithm %r" % (result["algorithm"],)
        return result
    if not result["signed_fields"]:
        result["reason"] = "h= tag is empty"
        return result
    try:
        header_canon, _ = parse_canonicalization(result["canonicalization"])
        signature = decode_base64(tags.get("b", ""))
    except ValueError as error:
        result["reason"] = str(error)
        return result

    signed_data = build_signed_data(
        fields, sig_index, result["signed_fields"], HEADER_CANONICALIZATIONS[header_canon]
    )
    result["signed_data_bytes"] = len(signed_data)
    result["valid"] = rsa_verify_pkcs1_v15_sha256(signed_data, signature, pubkey_n, pubkey_e)
    result["reason"] = "header signature verified" if result["valid"] else (
        "RSA PKCS#1 v1.5 check failed over the h= fields"
    )
    return result
