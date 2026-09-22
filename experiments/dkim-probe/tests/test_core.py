"""The on-chain subset must agree with the reference core.

Nothing here touches the network or the sample message: every fixture is
generated in process, reusing the signer and the RSA helpers already written
for test_rfc6376.
"""

import base64
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_rfc6376 as reference
from dkim import core, dns_doh, rfc6376

SELECTOR = "probe"
DOMAIN = "example.com"


@pytest.fixture(scope="module")
def signed():
    """(headers, n, e) for one synthetic message signed with a fresh key."""
    n, e, d = reference.generate_rsa_key(512)
    headers = reference.sign_message(
        reference.SYNTHETIC_HEADERS, reference.SYNTHETIC_BODY, SELECTOR, DOMAIN, n, d
    )
    return headers, n, e


# --- the pieces, against the reference implementation ----------------------


def test_sha256_matches_hashlib():
    for data in (b"", b"abc", b"x" * 55, b"y" * 56, b"z" * 64, bytes(range(256)) * 3):
        assert core.sha256(data) == hashlib.sha256(data).digest()


def test_a_hash_module_without_sha256_raises_for_the_caller_to_record(monkeypatch):
    """core.py has no fallback: a broken hashlib must reach the caller.

    The contract wraps the whole probe and stores the failure as a record with
    valid=false, so this exception is the boundary between the two, not a bug.
    """

    class Broken:
        @staticmethod
        def sha256(data):
            raise ValueError("unsupported hash type sha256")

    monkeypatch.setattr(core, "hashlib", Broken)
    with pytest.raises(ValueError):
        core.sha256(b"abc")
    with pytest.raises(ValueError):
        core.rsa_verify(b"m", b"\x00" * 64, (1 << 511) + 1, 65537)


def test_relaxed_canonicalization_matches_reference():
    fields = rfc6376.parse_header_fields(reference.EXAMPLE_HEADERS)
    assert b"".join(core.canon(n, v) for n, v in fields) == b"a:X\r\nb:Y Z\r\n"
    for name, value in fields:
        assert core.canon(name, value) == rfc6376.canonicalize_header_relaxed(name, value)


def test_header_parsing_matches_reference(signed):
    headers, _, _ = signed
    assert core.parse_headers(headers) == rfc6376.parse_header_fields(headers)


def test_b_tag_is_emptied_like_the_reference():
    value = b" v=1; bh=AAAA; b=SGVsbG8=\r\n\tV29ybGQ=; s=sel"
    assert core.strip_b(value) == rfc6376.strip_signature_value(value)
    assert core.strip_b(value) == b" v=1; bh=AAAA; b=; s=sel"


def test_signed_data_matches_reference(signed):
    headers, _, _ = signed
    fields = rfc6376.parse_header_fields(headers)
    expected = rfc6376.build_signed_data(
        fields, 0, reference.SYNTHETIC_H, rfc6376.canonicalize_header_relaxed
    )
    assert core.signed_data(fields, 0, reference.SYNTHETIC_H) == expected


def test_duplicate_header_names_are_consumed_bottom_up():
    raw = b"DKIM-Signature: v=1; h=Received:Received; b=AAAA\r\n"
    raw += b"Received: A\r\nReceived: B\r\nReceived: C\r\n"
    fields = core.parse_headers(raw)
    data = core.signed_data(fields, 0, ["Received", "Received"])
    assert data.startswith(b"received:C\r\nreceived:B\r\n")


def test_der_public_key_matches_reference():
    n, e, _ = reference.generate_rsa_key(512)
    der = base64.b64decode(reference.encode_public_key_record(n, e))
    assert core.decode_spki(der) == rfc6376.decode_subject_public_key_info(der)
    assert core.decode_spki(der) == (n, e)


def test_bare_pkcs1_public_key_is_accepted():
    n, e, _ = reference.generate_rsa_key(512)
    der = reference.der_sequence(reference.der_integer(n) + reference.der_integer(e))
    assert core.decode_spki(der) == (n, e)


def test_non_rsa_algorithm_identifier_is_rejected():
    bogus = reference.der_sequence(
        reference.der_sequence(bytes.fromhex("06072a8648ce3d0201"))
        + bytes([0x03, 0x02, 0x00, 0x00])
    )
    with pytest.raises(ValueError):
        core.decode_spki(bogus)


def test_key_record_matches_reference():
    n, e, _ = reference.generate_rsa_key(512)
    record = "v=DKIM1; k=rsa; p=%s" % reference.encode_public_key_record(n, e)
    assert core.key_from_txt(record) == rfc6376.public_key_from_record(record)[:2]


def test_revoked_key_is_rejected():
    with pytest.raises(ValueError):
        core.key_from_txt("v=DKIM1; k=rsa; p=")


# --- the DoH answer ---------------------------------------------------------


DOH_PAYLOAD = (
    '{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,'
    '"Question":[{"name":"probe._domainkey.example.com.","type":16}],'
    '"Answer":['
    '{"name":"probe._domainkey.example.com.","type":5,"TTL":300,'
    '"data":"target.example.net."},'
    '{"name":"target.example.net.","type":16,"TTL":300,'
    '"data":"\\"v=DKIM1; k=rsa; \\" \\"p=QUJD\\""}]}'
)


def test_doh_answer_parses_like_the_reference_resolver():
    answers = [
        {"type": 5, "data": "target.example.net."},
        {"type": 16, "data": '"v=DKIM1; k=rsa; " "p=QUJD"'},
    ]
    assert core.txt_from_doh(DOH_PAYLOAD) == dns_doh.join_txt_answers(answers)
    assert core.txt_from_doh(DOH_PAYLOAD) == "v=DKIM1; k=rsa; p=QUJD"


def test_doh_answer_without_a_txt_record_is_an_error():
    with pytest.raises(ValueError):
        core.txt_from_doh('{"Status":3,"Question":[{"name":"x.","type":16}]}')


# --- the entry point --------------------------------------------------------


def test_verify_headers_agrees_with_the_reference(signed):
    headers, n, e = signed
    ok, info = core.verify_headers(headers, n, e)
    expected = rfc6376.verify_headers(headers, SELECTOR, DOMAIN, n, e)

    assert ok is expected["valid"] is True
    assert info["domain"] == DOMAIN
    assert info["selector"] == SELECTOR
    assert info["bh"] == expected["bh_from_header"]
    assert info["message_id"] == "<probe-0001@example.com>"
    assert info["key_bits"] == n.bit_length()
    assert info["reason"] == "header signature verified"


def test_a_tampered_signed_header_fails_on_both_sides(signed):
    headers, n, e = signed
    tampered = headers.replace(b"a folded subject", b"a folded subjecu")

    ok, info = core.verify_headers(tampered, n, e)
    expected = rfc6376.verify_headers(tampered, SELECTOR, DOMAIN, n, e)

    assert ok is expected["valid"] is False
    assert info["reason"] == "RSA PKCS#1 v1.5 check failed"
    # The tamper is invisible to the tags: the probe still reports what the
    # signature claimed, which is the point of storing them next to valid.
    assert info["domain"] == DOMAIN
    assert info["bh"] == expected["bh_from_header"]


def test_the_wrong_key_fails_on_both_sides(signed):
    headers, n, _ = signed
    other_n, other_e, _ = reference.generate_rsa_key(512)

    ok, _ = core.verify_headers(headers, other_n, other_e)
    expected = rfc6376.verify_headers(headers, SELECTOR, DOMAIN, other_n, other_e)
    assert ok is expected["valid"] is False


def test_a_blob_without_a_signature_reports_the_reason():
    ok, info = core.verify_headers(b"To: a\r\nSubject: b\r\n", 3, 65537)
    assert ok is False
    assert info["reason"] == "no DKIM-Signature header"
    assert info["domain"] == ""


def test_an_unsupported_algorithm_is_reported_not_raised():
    raw = b"DKIM-Signature: v=1; a=rsa-sha1; c=relaxed/simple; d=d; s=s; h=To; b=AA\r\n"
    ok, info = core.verify_headers(raw + b"To: a\r\n", 3, 65537)
    assert ok is False
    assert info["reason"] == "unsupported algorithm"


def test_simple_header_canonicalization_is_out_of_scope_on_chain():
    raw = b"DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=d; s=s; h=To; b=AA\r\n"
    ok, info = core.verify_headers(raw + b"To: a\r\n", 3, 65537)
    assert ok is False
    assert info["reason"] == "unsupported header canonicalization"
