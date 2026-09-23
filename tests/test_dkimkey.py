"""lacre.dkimkey against a key this file builds, so nothing is fetched.

The modulus is synthetic and the DER around it is assembled here rather than
taken from a fixture: a decoder tested against its own output would prove
nothing, so the encoder below follows RFC 8017 and X.509 directly.
"""

import base64

import pytest

from lacre import dkimkey

EXPONENT = 65537
# 1024 bits, the size large senders still publish, and odd so it looks like a
# modulus to anything that checks.
MODULUS = (1 << 1023) | int.from_bytes(b"lacre registry key material" * 4, "big") | 1


def der(tag, payload):
    if len(payload) < 0x80:
        return bytes([tag, len(payload)]) + payload
    size = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + payload


def der_int(value):
    # A leading zero byte keeps a positive INTEGER from reading as negative.
    return der(0x02, value.to_bytes((value.bit_length() + 8) // 8, "big"))


def pkcs1(n=MODULUS, e=EXPONENT):
    return der(0x30, der_int(n) + der_int(e))


def spki(n=MODULUS, e=EXPONENT):
    algorithm = der(0x30, dkimkey.RSA_OID + der(0x05, b""))
    return der(0x30, algorithm + der(0x03, b"\x00" + pkcs1(n, e)))


def record(der_bytes=None, extra="; h=sha256; t=s"):
    published = base64.b64encode(spki() if der_bytes is None else der_bytes)
    return "v=DKIM1; k=rsa" + extra + "; p=" + published.decode("ascii")


def doh(txt, chunk=200, cname=True):
    """One DoH answer, split into character-strings the way a resolver does."""
    strings = " ".join(
        '\\"%s\\"' % (txt[at:at + chunk],) for at in range(0, len(txt), chunk)
    )
    answers = []
    if cname:
        answers.append(
            '{"name":"sel._domainkey.example.com.","type":5,"TTL":300,'
            '"data":"sel.dkim.example.net."}'
        )
    answers.append(
        '{"name":"sel.dkim.example.net.","type":16,"TTL":300,"data":"%s"}' % (strings,)
    )
    return '{"Status":0,"TC":false,"Answer":[%s]}' % (",".join(answers),)


def test_txt_from_doh_joins_chunks_and_ignores_the_cname():
    txt = record()
    assert len(txt) > 200, "the fixture must span more than one character-string"
    assert dkimkey.txt_from_doh(doh(txt)) == txt


def test_txt_from_doh_accepts_a_single_unsplit_string():
    assert dkimkey.txt_from_doh(doh("v=DKIM1; p=AAAA", cname=False)) == "v=DKIM1; p=AAAA"


def test_txt_from_doh_rejects_an_answer_with_no_txt():
    payload = (
        '{"Status":0,"Answer":[{"name":"sel._domainkey.example.com.","type":5,'
        '"TTL":300,"data":"sel.dkim.example.net."}]}'
    )
    with pytest.raises(ValueError):
        dkimkey.txt_from_doh(payload)


def test_key_tags_keeps_the_five_defined_tags():
    tags = dkimkey.key_tags("v=DKIM1; h=sha256; k=rsa; s=email; n=note; t=y; p=QUJD")
    assert tags == {"v": "DKIM1", "h": "sha256", "k": "rsa", "t": "y", "p": "QUJD"}


def test_key_tags_folds_whitespace_inside_a_value():
    assert dkimkey.key_tags("p=QU\r\n\tJD ; k=rsa")["p"] == "QUJD"


def test_key_from_tags_recovers_the_published_key():
    key = dkimkey.key_from_tags(dkimkey.key_tags(dkimkey.txt_from_doh(doh(record()))))
    assert key["n"] == MODULUS
    assert key["e"] == EXPONENT
    assert key["key_bits"] == 1024
    assert key["der"] == spki()


def test_key_from_tags_accepts_a_bare_pkcs1_key():
    key = dkimkey.key_from_tags(dkimkey.key_tags(record(pkcs1())))
    assert (key["n"], key["e"], key["key_bits"]) == (MODULUS, EXPONENT, 1024)


def test_key_from_tags_accepts_a_record_with_no_v_or_k():
    key = dkimkey.key_from_tags(dkimkey.key_tags("p=" + base64.b64encode(spki()).decode()))
    assert key["key_bits"] == 1024


def test_key_bits_follows_the_modulus():
    key = dkimkey.key_from_tags(dkimkey.key_tags(record(spki(n=(1 << 511) | 1))))
    assert key["key_bits"] == 512


def test_an_empty_p_tag_is_a_revoked_key():
    with pytest.raises(ValueError, match="revoked"):
        dkimkey.key_from_tags(dkimkey.key_tags("v=DKIM1; k=rsa; p="))


def test_a_non_rsa_key_is_refused():
    with pytest.raises(ValueError, match="unsupported"):
        dkimkey.key_from_tags(dkimkey.key_tags(record(extra="; k=ed25519")))


def test_a_future_record_version_is_refused():
    with pytest.raises(ValueError, match="unsupported"):
        dkimkey.key_from_tags(dkimkey.key_tags("v=DKIM2; k=rsa; p=QUJD"))


def test_a_truncated_der_is_refused():
    with pytest.raises(ValueError):
        dkimkey.key_from_tags(dkimkey.key_tags(record(spki()[:-20])))


def test_a_key_that_is_not_rsa_encryption_is_refused():
    other_oid = bytes.fromhex("06092a864886f70d010105")
    algorithm = der(0x30, other_oid + der(0x05, b""))
    body = der(0x30, algorithm + der(0x03, b"\x00" + pkcs1()))
    with pytest.raises(ValueError, match="rsaEncryption"):
        dkimkey.key_from_tags(dkimkey.key_tags(record(body)))
