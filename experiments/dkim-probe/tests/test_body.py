"""Unit tests for the body probe's hashing and field extraction.

Everything except the live test runs with no network and without the sample
message: the multipart case builds its own fixture and checks the hash against
a hashlib call written out independently of body.py.
"""

import base64
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dkim import body, rfc6376

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "amazon-shipped.eml"
SAMPLE_DOMAIN = "amazon.com"

BOUNDARY = b"----=_Part_1_998877.1700000000000"

SYNTHETIC_TEXT = (
    b"Tu pedido 123-4567890-1234567 ya va en camino.\r\n"
    b"Se enviaron 2 art=C3=ADculos.\r\n"
    b"Llega el mi=C3=A9rcoles\r\n"
)


def synthetic_body():
    """A two part alternative body in the shape the sender's template uses."""
    return (
        b"This is a multi-part message in MIME format.\r\n"
        b"--" + BOUNDARY + b"\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n"
        b"\r\n" + SYNTHETIC_TEXT +
        b"--" + BOUNDARY + b"\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n"
        b"\r\n"
        b"<html><body>123-4567890-1234567</body></html>\r\n"
        b"--" + BOUNDARY + b"--\r\n"
    )


# --- RFC 6376 section 3.4.3 canonicalization -------------------------------


def test_simple_body_matches_the_rfc_example():
    # Section 3.4.5, example 1: the trailing empty lines collapse to one CRLF.
    assert body.canonicalize_body_simple(b" C \r\nD \t E\r\n\r\n\r\n") == (
        b" C \r\nD \t E\r\n"
    )


def test_simple_body_leaves_in_line_whitespace_alone():
    assert body.canonicalize_body_simple(b"a  b\t c\r\n") == b"a  b\t c\r\n"


def test_simple_body_appends_the_missing_terminator():
    assert body.canonicalize_body_simple(b"one line") == b"one line\r\n"


def test_an_empty_body_canonicalizes_to_a_single_crlf():
    assert body.canonicalize_body_simple(b"") == b"\r\n"
    assert body.canonicalize_body_simple(b"\r\n\r\n\r\n") == b"\r\n"


def test_simple_body_matches_the_reference_implementation():
    for raw in (b"", b"a\r\n", b"a\r\n\r\n\r\n", b"a", b" x \r\ny\r\n"):
        assert body.canonicalize_body_simple(raw) == (
            rfc6376.canonicalize_body_simple(raw)
        )


def test_body_hash_is_base64_sha256_of_the_canonical_form():
    raw = b"the body\r\n\r\n\r\n"
    expected = base64.b64encode(hashlib.sha256(b"the body\r\n").digest())
    assert body.body_hash(raw) == expected.decode("ascii")


# --- quoted-printable ------------------------------------------------------


def test_qp_decodes_hex_escapes():
    assert body.qp_decode(b"mi=C3=A9rcoles") == "mi\u00e9rcoles".encode("utf-8")


def test_qp_hex_escapes_are_case_insensitive():
    assert body.qp_decode(b"=c3=a9") == body.qp_decode(b"=C3=A9")


def test_qp_drops_soft_line_breaks():
    assert body.qp_decode(b"one=\r\ntwo") == b"onetwo"
    assert body.qp_decode(b"one=\ntwo") == b"onetwo"


def test_qp_keeps_hard_line_breaks():
    assert body.qp_decode(b"one\r\ntwo\r\n") == b"one\r\ntwo\r\n"


def test_qp_decodes_an_escaped_equals_sign():
    assert body.qp_decode(b"a=3Db") == b"a=b"


def test_qp_leaves_a_lone_equals_sign_alone():
    # Not legal quoted-printable, but a probe records what it was served
    # rather than rejecting the whole part over one byte.
    assert body.qp_decode(b"2 = 2") == b"2 = 2"


def test_a_soft_break_before_an_escape_does_not_merge_into_one():
    assert body.qp_decode(b"a=\r\n=3Db") == b"a=b"


# --- multipart -------------------------------------------------------------


def test_first_text_part_returns_the_decoded_plain_part():
    text = body.first_text_part(synthetic_body()).decode("utf-8")
    assert text.startswith("Tu pedido")
    assert "<html>" not in text
    assert "mi\u00e9rcoles" in text


def test_first_text_part_ignores_the_preamble_and_the_closing_delimiter():
    assert b"multi-part message" not in body.first_text_part(synthetic_body())


def test_first_text_part_decodes_a_base64_part():
    payload = base64.b64encode(b"Llega el jueves\r\n")
    raw = (
        b"--" + BOUNDARY + b"\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n" + payload + b"\r\n"
        b"--" + BOUNDARY + b"--\r\n"
    )
    assert body.first_text_part(raw) == b"Llega el jueves\r\n"


def test_first_text_part_returns_nothing_when_the_body_is_not_multipart():
    assert body.first_text_part(b"just a flat body\r\n") == b""


def test_first_text_part_returns_nothing_when_no_part_is_text_plain():
    raw = (
        b"--" + BOUNDARY + b"\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n<html></html>\r\n"
        b"--" + BOUNDARY + b"--\r\n"
    )
    assert body.first_text_part(raw) == b""


def test_body_hash_of_the_synthetic_body_matches_an_independent_hashlib():
    raw = synthetic_body()
    # Written out rather than reusing canonicalize_body_simple: the fixture
    # already ends in exactly one CRLF, so the canonical form is the input.
    expected = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")
    assert body.body_hash(raw) == expected


# --- field extraction ------------------------------------------------------


def test_extract_fields_reads_the_synthetic_part():
    text = body.first_text_part(synthetic_body()).decode("utf-8")
    fields = body.extract_fields(text)
    assert fields["order_id"] == "123-4567890-1234567"
    assert fields["eta_day"] == "miercoles"
    assert fields["shipped"] is True


def test_extract_fields_returns_empty_values_for_unrelated_text():
    fields = body.extract_fields("nothing to see here")
    assert fields == {"order_id": "", "eta_day": "", "shipped": False}


def test_an_order_id_of_the_wrong_shape_is_not_matched():
    assert body.extract_fields("12-4567890-1234567")["order_id"] == ""
    assert body.extract_fields("123-456789-1234567")["order_id"] == ""


def test_the_eta_day_is_only_kept_when_it_is_a_weekday():
    assert body.extract_fields("Llega el jueves")["eta_day"] == "jueves"
    assert body.extract_fields("Llega el paquete")["eta_day"] == ""


def test_the_eta_day_is_folded_to_ascii():
    day = body.extract_fields("Llega el s\u00e1bado")["eta_day"]
    assert day == "sabado"
    assert day.isascii()


def test_shipped_accepts_the_singular_form():
    assert body.extract_fields("Se envi\u00f3 tu pedido")["shipped"] is True
    assert body.extract_fields("Tu pedido ha sido enviado")["shipped"] is True


def test_shipped_is_false_for_a_delivery_notice():
    assert body.extract_fields("Tu pedido fue entregado")["shipped"] is False


# --- live: the sample message ----------------------------------------------


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample message is not present")
def test_the_sample_body_hashes_to_the_bh_its_signature_claims():
    raw_headers, raw_body = rfc6376.split_message(SAMPLE.read_bytes())
    claimed = ""
    for name, value in rfc6376.parse_header_fields(raw_headers):
        if rfc6376.field_name(name) != b"dkim-signature":
            continue
        tags = rfc6376.parse_tag_list(value.decode("latin-1"))
        if tags.get("d") == SAMPLE_DOMAIN:
            claimed = rfc6376.unfold_tag_value(tags.get("bh", ""))
            break
    assert claimed, "no DKIM-Signature for d=%s in the sample" % (SAMPLE_DOMAIN,)
    assert body.body_hash(raw_body) == claimed


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample message is not present")
def test_the_sample_text_part_yields_every_field():
    _, raw_body = rfc6376.split_message(SAMPLE.read_bytes())
    text = body.first_text_part(raw_body).decode("utf-8", "replace")
    fields = body.extract_fields(text)
    # The values themselves stay out of the assertions and out of pytest's
    # output on failure; only their shape is checked.
    assert len(fields["order_id"]) == 19
    assert fields["eta_day"] in body.WEEKDAYS
    assert fields["shipped"] is True
