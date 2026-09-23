"""DKIM key records: a DNS over HTTPS answer in, an RSA public key out.

The key half of the probe's verifier, with no network and no SDK import, so
the contract build splices it in whole and the tests drive it directly.
"""

import base64
import re

_OBJECT = re.compile(r"\{[^{}]*\}")
_TXT = re.compile(r'"type"\s*:\s*16\b')
_DATA = re.compile(r'"data"\s*:\s*"((?:[^"\\]|\\.)*)"')
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
RSA_OID = bytes.fromhex("06092a864886f70d010101")  # rsaEncryption, RFC 8017 A.1
KEY_TAGS = ("v", "k", "p", "h", "t")


def txt_from_doh(payload):
    # A delegated selector answers with a CNAME hop first, so filter by type,
    # and a key over 255 bytes arrives split into chunks joined with nothing.
    chunks = []
    for obj in _OBJECT.findall(payload):
        found = _DATA.search(obj) if _TXT.search(obj) else None
        if found:
            data = found.group(1).replace('\\"', '"').replace("\\\\", "\\")
            quoted = _QUOTED.findall(data)
            chunks.append("".join(quoted) if quoted else data)
    if not chunks:
        raise ValueError("no TXT record in the answer")
    return "".join(chunks)


def key_tags(txt):
    """The RFC 6376 3.6.1 tags, with whitespace folded out of each value."""
    tags = {}
    for spec in txt.split(";"):
        name, sep, value = spec.partition("=")
        if sep and name.strip() in KEY_TAGS:
            tags[name.strip()] = "".join(value.split())
    return tags


def key_der(tags):
    if tags.get("v", "DKIM1") != "DKIM1" or tags.get("k", "rsa") != "rsa":
        raise ValueError("unsupported key record")
    p = tags.get("p", "")
    if not p:
        raise ValueError("key revoked (empty p=)")
    return base64.b64decode(p + "=" * (-len(p) % 4))


def read_tlv(der, at):
    # Definite lengths only, which is all X.509 emits.
    if at + 2 > len(der):
        raise ValueError("truncated DER")
    tag, size, at = der[at], der[at + 1], at + 2
    if size & 0x80:
        count = size & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported DER length")
        size = int.from_bytes(der[at:at + count], "big")
        at += count
    if at + size > len(der):
        raise ValueError("truncated DER")
    return tag, der[at:at + size], at + size


def rsa_key(der):
    tag, n, at = read_tlv(der, 0)
    tag2, e, _ = read_tlv(der, at)
    if tag != 0x02 or tag2 != 0x02:
        raise ValueError("RSAPublicKey is not two INTEGERs")
    return int.from_bytes(n, "big"), int.from_bytes(e, "big")


def decode_spki(der):
    tag, outer, _ = read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("key is not a DER SEQUENCE")
    tag, first, at = read_tlv(outer, 0)
    if tag == 0x02:
        return rsa_key(outer)  # a few records still carry a bare PKCS#1 key
    if tag != 0x30 or RSA_OID not in first:
        raise ValueError("algorithm is not rsaEncryption")
    tag, bits, _ = read_tlv(outer, at)
    if tag != 0x03 or not bits or bits[0] != 0:
        raise ValueError("bad subjectPublicKey")
    tag, key, _ = read_tlv(bits, 1)
    if tag != 0x30:
        raise ValueError("subjectPublicKey is not an RSAPublicKey")
    return rsa_key(key)


def key_from_tags(tags):
    """Modulus, exponent, size in bits and the DER the record published."""
    der = key_der(tags)
    n, e = decode_spki(der)
    return {"n": n, "e": e, "key_bits": n.bit_length(), "der": der}
