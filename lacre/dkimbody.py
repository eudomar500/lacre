# Body canonicalization and the body hash, RFC 6376 sections 3.4.3 and 3.4.4,
# with the field extraction the body probe measured on Bradbury. Pure stdlib
# and no file or network access, so this can be spliced into a contract the way
# lacre/dkimcore.py is.

import base64
import hashlib
import re

_WSP = re.compile(rb"[ \t]+")

# The body arrives without the headers that declared the boundary, so the
# delimiter line has to be recovered from the wire format itself.
_DELIMITER = re.compile(rb"(?m)^--(\S+?)[ \t]*\r?$")
_QP_HEX = re.compile(rb"=([0-9A-Fa-f]{2})")
_PART_SEPARATORS = (b"\r\n\r\n", b"\n\n")

_ORDER_ID = re.compile(r"\b\d{3}-\d{7}-\d{7}\b")
_ETA_DAY = re.compile(r"\bllega\s+el\s+([a-z]+)")
_SHIPPED = re.compile(r"\bse\s+envi(?:aron|o)\b|\bha\s+sido\s+enviado\b")

# The template is Spanish, and an accented byte must never reach the canonical
# string consensus rides on, so the text is folded to ASCII before matching.
_ACCENTS = str.maketrans("\u00e1\u00e9\u00ed\u00f3\u00fa\u00fc\u00f1", "aeiouun")

WEEKDAYS = ("lunes", "martes", "miercoles", "jueves", "viernes", "sabado",
            "domingo")


def canonicalize_body_simple(body):
    # 3.4.3. Unlike relaxed, simple keeps whitespace as sent and hashes an
    # empty body as a single CRLF rather than as nothing.
    if body and not body.endswith(b"\r\n"):
        body += b"\r\n"
    while body.endswith(b"\r\n\r\n"):
        body = body[:-2]
    return body or b"\r\n"


def canonicalize_body_relaxed(body):
    # 3.4.4. Lines are cut on CRLF alone, so a bare LF stays inside a line and
    # is hashed as content: a body that was rewritten in transit has to fail to
    # match rather than be repaired here into something the signer never saw.
    lines = [_WSP.sub(b" ", line).rstrip(b" ") for line in body.split(b"\r\n")]
    while lines and not lines[-1]:
        lines.pop()
    if not lines:
        return b""
    return b"\r\n".join(lines) + b"\r\n"


def canonicalize_body(body, canon):
    if canon == "simple":
        return canonicalize_body_simple(body)
    if canon == "relaxed":
        return canonicalize_body_relaxed(body)
    # Deliberately no default. The caller takes this from the signed c= tag,
    # and falling back to one algorithm would hash a body the signer did not
    # sign and report it as a match.
    raise ValueError("unsupported body canonicalization")


def body_hash_b64(body, canon):
    # The whole body, every time. A signer may cap the signed body with l= and
    # leave the rest unsigned; that is not implemented, so such a signature
    # fails to match instead of vouching for an appended tail.
    digest = hashlib.sha256(canonicalize_body(body, canon)).digest()
    return base64.b64encode(digest).decode("ascii")


def count_bare_lf(body):
    # Diagnostics only. Nothing above branches on this: it exists to tell a
    # mangled transfer apart from a genuinely wrong body when a hash misses.
    return body.count(b"\n") - body.count(b"\r\n")


def qp_decode(data):
    # Soft line breaks go first. An "=" before a terminator encodes nothing
    # and cannot be confused with an "=XX" escape, whose next byte is hex.
    data = data.replace(b"=\r\n", b"").replace(b"=\n", b"")
    return _QP_HEX.sub(lambda hit: bytes([int(hit.group(1), 16)]), data)


def split_part(part):
    found = [(part.find(sep), sep) for sep in _PART_SEPARATORS]
    found = [(index, sep) for index, sep in found if index >= 0]
    if not found:
        return b"", part
    index, sep = min(found)
    return part[:index].lower(), part[index + len(sep):]


def first_text_part(raw_bytes):
    delimiter = _DELIMITER.search(raw_bytes)
    if not delimiter:
        return b""
    for part in raw_bytes.split(b"--" + delimiter.group(1))[1:]:
        head, payload = split_part(part.lstrip(b"-\r\n"))
        if b"text/plain" not in head:
            continue
        if b"quoted-printable" in head:
            return qp_decode(payload)
        if b"base64" in head:
            payload = re.sub(rb"\s", b"", payload)
            return base64.b64decode(payload + b"=" * (-len(payload) % 4))
        return payload
    return b""


def extract_fields(text):
    folded = text.translate(_ACCENTS).lower()
    order_id = _ORDER_ID.search(folded)
    eta_day = _ETA_DAY.search(folded)
    day = eta_day.group(1) if eta_day else ""
    return {
        "order_id": order_id.group(0) if order_id else "",
        "eta_day": day if day in WEEKDAYS else "",
        "shipped": bool(_SHIPPED.search(folded)),
    }
