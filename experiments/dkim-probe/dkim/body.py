import base64
import hashlib
import re

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
    # RFC 6376 section 3.4.3, extracted from rfc6376.py so the contract can
    # carry this one algorithm without the rest of the verifier.
    if body and not body.endswith(b"\r\n"):
        body += b"\r\n"
    while body.endswith(b"\r\n\r\n"):
        body = body[:-2]
    return body or b"\r\n"


def body_hash(raw_bytes):
    digest = hashlib.sha256(canonicalize_body_simple(raw_bytes)).digest()
    return base64.b64encode(digest).decode("ascii")


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
