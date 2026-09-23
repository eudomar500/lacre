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
