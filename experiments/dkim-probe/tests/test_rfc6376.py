"""Unit tests for the verification core.

Everything except the two live tests runs with no network and without the
sample message: the end to end case generates its own RSA key pair.
"""

import base64
import hashlib
import os
import random
import sys
from pathlib import Path
from urllib.error import URLError

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dkim import dns_doh, rfc6376

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "amazon-shipped.eml"
SAMPLE_SELECTOR = "yg4mwqurec7fkhzutopddd3ytuaqrvuz"
SAMPLE_DOMAIN = "amazon.com"

# RFC 6376 section 3.4.5, example 1, with the bracketed descriptors expanded.
EXAMPLE_HEADERS = b"A: X\r\nB : Y\t\r\n\tZ  \r\n"
EXAMPLE_BODY = b" C \r\nD \t E\r\n\r\n\r\n"


# --- section 3.4 canonicalization ------------------------------------------


def test_relaxed_header_matches_rfc_example():
    fields = rfc6376.parse_header_fields(EXAMPLE_HEADERS)
    canonical = b"".join(rfc6376.canonicalize_header_relaxed(n, v) for n, v in fields)
    assert canonical == b"a:X\r\nb:Y Z\r\n"


def test_simple_header_leaves_the_field_untouched():
    fields = rfc6376.parse_header_fields(EXAMPLE_HEADERS)
    canonical = b"".join(rfc6376.canonicalize_header_simple(n, v) for n, v in fields)
    assert canonical == EXAMPLE_HEADERS


def test_relaxed_body_matches_rfc_example():
    assert rfc6376.canonicalize_body_relaxed(EXAMPLE_BODY) == b" C\r\nD E\r\n"


def test_simple_body_matches_rfc_example():
    assert rfc6376.canonicalize_body_simple(EXAMPLE_BODY) == b" C \r\nD \t E\r\n"


def test_empty_body_hashes_to_the_published_constants():
    # Section 3.4.3 and 3.4.4 publish these for an empty body.
    assert rfc6376.body_hash(b"", canonicalization="simple") == (
        "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="
    )
    assert rfc6376.body_hash(b"", canonicalization="relaxed") == (
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    )


def test_simple_body_adds_a_crlf_when_the_body_has_none():
    assert rfc6376.canonicalize_body_simple(b"abc") == b"abc\r\n"
    assert rfc6376.canonicalize_body_simple(b"abc\r\n\r\n\r\n") == b"abc\r\n"


def test_crlf_mode_makes_an_lf_body_hash_like_the_crlf_original():
    crlf = b"line one\r\nline two\r\n"
    lf = b"line one\nline two\n"
    assert rfc6376.body_hash(lf, "crlf") == rfc6376.body_hash(crlf, "as-is")
    assert rfc6376.body_hash(lf, "as-is") != rfc6376.body_hash(crlf, "as-is")


def test_folded_header_is_unfolded_across_lf_and_crlf_input():
    crlf = rfc6376.parse_header_fields(b"Subject: one\r\n two\r\n")
    lf = rfc6376.parse_header_fields(b"Subject: one\n two\n")
    assert crlf == lf
    assert rfc6376.canonicalize_header_relaxed(*crlf[0]) == b"subject:one two\r\n"


def test_split_message_separates_on_the_empty_line():
    headers, body = rfc6376.split_message(b"A: 1\r\nB: 2\r\n\r\nbody\r\n")
    assert headers == b"A: 1\r\nB: 2"
    assert body == b"body\r\n"


def test_parse_header_fields_keeps_order_and_duplicates():
    fields = rfc6376.parse_header_fields(b"Received: a\r\nReceived: b\r\nTo: c\r\n")
    assert [n for n, _ in fields] == [b"Received", b"Received", b"To"]


# --- section 3.7 signed data -----------------------------------------------


def test_b_tag_value_is_emptied_but_the_tag_remains():
    value = b" v=1; bh=AAAA; b=SGVsbG8=\r\n\tV29ybGQ=; s=sel"
    assert rfc6376.strip_signature_value(value) == b" v=1; bh=AAAA; b=; s=sel"


def test_duplicate_header_names_are_consumed_from_the_bottom_up():
    fields = rfc6376.parse_header_fields(b"Received: A\r\nReceived: B\r\nReceived: C\r\n")
    selected = rfc6376.select_signed_fields(fields, ["Received", "Received"])
    assert [v for _, v in selected] == [b" C", b" B"]


def test_a_header_named_in_h_but_absent_contributes_nothing():
    fields = rfc6376.parse_header_fields(b"To: a\r\n")
    assert rfc6376.select_signed_fields(fields, ["To", "Subject"]) == [(b"To", b" a")]


def test_signed_data_ends_with_the_signature_and_no_trailing_crlf():
    raw = b"DKIM-Signature: v=1; h=To; b=AAAA\r\nTo: a\r\n"
    fields = rfc6376.parse_header_fields(raw)
    data = rfc6376.build_signed_data(
        fields, 0, ["To"], rfc6376.canonicalize_header_relaxed
    )
    assert data == b"to:a\r\ndkim-signature:v=1; h=To; b="


# --- RFC 8017 PKCS#1 v1.5 ---------------------------------------------------


def test_digestinfo_prefix_is_the_sha256_constant():
    assert rfc6376.SHA256_DIGESTINFO_PREFIX.hex() == (
        "3031300d060960864801650304020105000420"
    )


def test_pkcs1_encoding_has_the_expected_shape():
    digest = hashlib.sha256(b"payload").digest()
    block = rfc6376.pkcs1_v15_encode_sha256(digest, 128)
    assert len(block) == 128
    assert block[:2] == b"\x00\x01"
    assert block.endswith(rfc6376.SHA256_DIGESTINFO_PREFIX + digest)
    assert set(block[2:-len(rfc6376.SHA256_DIGESTINFO_PREFIX) - len(digest) - 1]) == {0xFF}


def test_pkcs1_encoding_refuses_a_modulus_that_is_too_short():
    with pytest.raises(ValueError):
        rfc6376.pkcs1_v15_encode_sha256(hashlib.sha256(b"x").digest(), 48)


# --- section 3.6.1 key records ----------------------------------------------


def test_key_record_tags_and_defaults():
    record = rfc6376.parse_key_record("k=rsa; p=QUJD REVG ; h=sha256; t=y")
    assert record["v"] == "DKIM1"
    assert record["k"] == "rsa"
    assert record["p"] == "QUJDREVG"
    assert record["h"] == "sha256"
    assert record["t"] == "y"


def test_revoked_key_is_rejected():
    with pytest.raises(ValueError):
        rfc6376.public_key_from_record("v=DKIM1; k=rsa; p=")


def test_base64_der_key_round_trips():
    n, e, _ = generate_rsa_key(512)
    record = "v=DKIM1; k=rsa; p=%s" % encode_public_key_record(n, e)
    assert rfc6376.public_key_from_record(record)[:2] == (n, e)


def test_bare_pkcs1_public_key_is_also_accepted():
    n, e, _ = generate_rsa_key(512)
    der = der_sequence(der_integer(n) + der_integer(e))
    assert rfc6376.decode_subject_public_key_info(der) == (n, e)


def test_non_rsa_algorithm_identifier_is_rejected():
    bogus = der_sequence(
        der_sequence(bytes.fromhex("06072a8648ce3d0201"))
        + bytes([0x03, 0x02, 0x00, 0x00])
    )
    with pytest.raises(ValueError):
        rfc6376.decode_subject_public_key_info(bogus)


# --- synthetic end to end ---------------------------------------------------


SYNTHETIC_HEADERS = (
    b"Date: Mon, 22 Sep 2025 10:00:00 +0000\r\n"
    b"From: sender <sender@example.com>\r\n"
    b"To: receiver <receiver@example.net>\r\n"
    b"Message-ID: <probe-0001@example.com>\r\n"
    b"Subject: a folded subject that\r\n continues on a second line\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=UTF-8\r\n"
)
SYNTHETIC_BODY = b"first line\r\nsecond line\r\n\r\n\r\n"
SYNTHETIC_H = ["Date", "From", "To", "Message-ID", "Subject", "MIME-Version", "Content-Type"]


def test_synthetic_message_verifies_end_to_end():
    n, e, d = generate_rsa_key(512)
    headers = sign_message(SYNTHETIC_HEADERS, SYNTHETIC_BODY, "probe", "example.com", n, d)

    result = rfc6376.verify_headers(headers, "probe", "example.com", n, e)
    assert result["valid"], result["reason"]
    assert result["signed_fields"] == SYNTHETIC_H
    assert result["has_length_tag"] is False
    assert rfc6376.body_hash(SYNTHETIC_BODY) == result["bh_from_header"]


def test_synthetic_message_fails_when_a_signed_header_changes():
    n, e, d = generate_rsa_key(512)
    headers = sign_message(SYNTHETIC_HEADERS, SYNTHETIC_BODY, "probe", "example.com", n, d)
    tampered = headers.replace(b"a folded subject", b"a folded subjecu")

    result = rfc6376.verify_headers(tampered, "probe", "example.com", n, e)
    assert result["valid"] is False
    assert "PKCS#1" in result["reason"]


def test_synthetic_message_fails_under_the_wrong_key():
    n, _, d = generate_rsa_key(512)
    other_n, other_e, _ = generate_rsa_key(512)
    headers = sign_message(SYNTHETIC_HEADERS, SYNTHETIC_BODY, "probe", "example.com", n, d)

    assert rfc6376.verify_headers(headers, "probe", "example.com", other_n, other_e)["valid"] is False


def test_body_hash_detects_a_single_flipped_byte():
    expected = rfc6376.body_hash(SYNTHETIC_BODY)
    mutated = bytearray(SYNTHETIC_BODY)
    mutated[0] ^= 0x01
    assert rfc6376.body_hash(bytes(mutated)) != expected


def test_selector_and_domain_must_both_match():
    n, e, d = generate_rsa_key(512)
    headers = sign_message(SYNTHETIC_HEADERS, SYNTHETIC_BODY, "probe", "example.com", n, d)

    assert rfc6376.verify_headers(headers, "probe", "example.org", n, e)["valid"] is False
    assert rfc6376.verify_headers(headers, "other", "example.com", n, e)["valid"] is False


# --- live checks, skipped when the sample or the network is missing ---------


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample message is not present")
def test_live_sample_verifies():
    raw = SAMPLE.read_bytes()
    raw_headers, raw_body = rfc6376.split_message(raw)
    try:
        record = dns_doh.fetch_dkim_key(SAMPLE_SELECTOR, SAMPLE_DOMAIN, timeout=10.0)
    except (URLError, LookupError, OSError) as error:
        pytest.skip("DNS over HTTPS is unavailable: %s" % (error,))

    n, e, _ = rfc6376.public_key_from_record(record)
    result = rfc6376.verify_headers(raw_headers, SAMPLE_SELECTOR, SAMPLE_DOMAIN, n, e)
    assert result["valid"], result["reason"]

    matched = [
        mode
        for mode in rfc6376.LINE_ENDING_MODES
        if rfc6376.body_hash(raw_body, mode) == result["bh_from_header"]
    ]
    assert matched, "body hash matched under neither line ending mode"


def test_txt_answers_skip_the_cname_hop():
    answers = [
        {"type": 5, "data": "target.example.com."},
        {"type": 16, "data": '"v=DKIM1; k=rsa; " "p=QUJD"'},
    ]
    assert dns_doh.join_txt_answers(answers) == "v=DKIM1; k=rsa; p=QUJD"


def test_key_record_name_follows_the_rfc():
    assert dns_doh.key_record_name("sel", "example.com") == "sel._domainkey.example.com"


# --- test helpers -----------------------------------------------------------


def der_length(size):
    if size < 0x80:
        return bytes([size])
    body = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der_sequence(payload):
    return b"\x30" + der_length(len(payload)) + payload


def der_integer(value):
    body = value.to_bytes((value.bit_length() + 8) // 8, "big")
    return b"\x02" + der_length(len(body)) + body


def encode_public_key_record(n, e):
    """Wrap (n, e) as a base64 DER SubjectPublicKeyInfo, as a signer would."""
    key = der_sequence(der_integer(n) + der_integer(e))
    algorithm = der_sequence(rfc6376.RSA_ENCRYPTION_OID + b"\x05\x00")
    bit_string = b"\x03" + der_length(len(key) + 1) + b"\x00" + key
    return base64.b64encode(der_sequence(algorithm + bit_string)).decode("ascii")


def is_probable_prime(candidate, rounds=24):
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if candidate in small:
        return True
    if candidate < 2 or any(candidate % p == 0 for p in small):
        return False
    d, r = candidate - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    rng = random.Random(candidate)
    for _ in range(rounds):
        a = rng.randrange(2, candidate - 1)
        x = pow(a, d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(r - 1):
            x = x * x % candidate
            if x == candidate - 1:
                break
        else:
            return False
    return True


def random_prime(bits):
    while True:
        candidate = int.from_bytes(os.urandom(bits // 8), "big")
        candidate |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_probable_prime(candidate):
            return candidate


def generate_rsa_key(bits):
    """A small key is enough here: 512 bits still leaves room for the padding."""
    e = 65537
    while True:
        p, q = random_prime(bits // 2), random_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if n.bit_length() != bits or phi % e == 0:
            continue
        return n, e, pow(e, -1, phi)


def sign_message(header_block, body, selector, domain, n, d):
    """Minimal signer, so the end to end test owns both sides of the check."""
    sig = "v=1; a=rsa-sha256; c=relaxed/simple; d=%s; s=%s; h=%s; bh=%s; b=" % (
        domain, selector, ":".join(SYNTHETIC_H), rfc6376.body_hash(body)
    )
    unsigned = b"DKIM-Signature: " + sig.encode("ascii") + b"\r\n" + header_block
    fields = rfc6376.parse_header_fields(unsigned)
    data = rfc6376.build_signed_data(
        fields, 0, SYNTHETIC_H, rfc6376.canonicalize_header_relaxed
    )
    size = (n.bit_length() + 7) // 8
    block = rfc6376.pkcs1_v15_encode_sha256(hashlib.sha256(data).digest(), size)
    signature = pow(int.from_bytes(block, "big"), d, n).to_bytes(size, "big")
    return unsigned.replace(b"b=\r\n", b"b=" + base64.b64encode(signature) + b"\r\n", 1)
