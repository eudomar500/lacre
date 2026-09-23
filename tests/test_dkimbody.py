"""lacre/dkimbody.py: RFC 6376 body canonicalization and the body hash.

Relaxed is new here. Simple is carried over from the body probe and is held to
it byte for byte, so the algorithm that was measured on Bradbury cannot drift
from the one the Extractor will run.
"""

import base64
import hashlib
import importlib.util
from pathlib import Path

import pytest

from lacre import dkimbody, dkimcore

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "experiments" / "dkim-probe" / "dkim" / "body.py"
SAMPLES = ROOT / "samples"

# RFC 6376 section 3.4.5, the worked example.
RFC_BODY = b" C \r\nD \t E\r\n\r\n\r\n"
RFC_RELAXED = b" C\r\nD E\r\n"
RFC_SIMPLE = b" C \r\nD \t E\r\n"

# Inputs the two implementations of simple have to agree on.
CASES = (
    b"",
    b"\r\n",
    b"\r\n\r\n\r\n",
    RFC_BODY,
    b"a",
    b"a\r\n",
    b"a\r\n\r\n",
    b"a \t \r\nb\r\n",
    b" \t \r\n \r\n",
    b"line one\r\nline two",
    b"bare\nlf\r\n",
    b"\x00\xff binary \xfe\r\n",
)


def load_probe():
    spec = importlib.util.spec_from_file_location("probe_body", PROBE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rfc_example():
    assert dkimbody.canonicalize_body(RFC_BODY, "relaxed") == RFC_RELAXED
    assert dkimbody.canonicalize_body(RFC_BODY, "simple") == RFC_SIMPLE


def test_empty_body():
    assert dkimbody.canonicalize_body(b"", "simple") == b"\r\n"
    assert dkimbody.canonicalize_body(b"", "relaxed") == b""


def test_body_of_only_empty_lines():
    assert dkimbody.canonicalize_body(b"\r\n\r\n\r\n", "relaxed") == b""
    assert dkimbody.canonicalize_body(b"\r\n\r\n\r\n", "simple") == b"\r\n"


def test_only_whitespace_lines():
    # A line of nothing but WSP collapses to empty, so it counts as trailing.
    assert dkimbody.canonicalize_body(b" \t \r\n   \r\n", "relaxed") == b""
    assert dkimbody.canonicalize_body(b"a\r\n \r\n", "relaxed") == b"a\r\n"


def test_htab_runs():
    assert dkimbody.canonicalize_body(b"a\t\t\tb\r\n", "relaxed") == b"a b\r\n"
    assert dkimbody.canonicalize_body(b"a \t \t b\r\n", "relaxed") == b"a b\r\n"
    assert dkimbody.canonicalize_body(b"\ta\r\n", "relaxed") == b" a\r\n"


def test_trailing_wsp_before_crlf():
    assert dkimbody.canonicalize_body(b"a   \r\nb\t\r\n", "relaxed") == b"a\r\nb\r\n"


def test_body_without_final_crlf():
    assert dkimbody.canonicalize_body(b"a  b", "relaxed") == b"a b\r\n"
    assert dkimbody.canonicalize_body(b"a  b", "simple") == b"a  b\r\n"


def test_bare_lf_is_not_rewritten():
    # The LF stays inside the line, so the byte reaches the hash unchanged.
    assert dkimbody.canonicalize_body(b"a\nb\r\n", "relaxed") == b"a\nb\r\n"
    assert dkimbody.canonicalize_body(b"a \n \r\n", "relaxed") == b"a \n\r\n"
    assert dkimbody.count_bare_lf(b"a\nb\r\nc\n") == 2
    assert dkimbody.count_bare_lf(b"a\r\nb\r\n") == 0
    assert dkimbody.count_bare_lf(b"") == 0


def test_unknown_canon_raises():
    for canon in ("", "Simple", "RELAXED", "relaxed/relaxed", "nowsp", None):
        with pytest.raises(ValueError):
            dkimbody.canonicalize_body(b"a\r\n", canon)


def test_canon_has_no_default():
    with pytest.raises(TypeError):
        dkimbody.canonicalize_body(b"a\r\n")
    with pytest.raises(TypeError):
        dkimbody.body_hash_b64(b"a\r\n")


def test_simple_is_the_probe_byte_for_byte():
    probe = load_probe()
    for case in CASES:
        assert dkimbody.canonicalize_body(case, "simple") == probe.canonicalize_body_simple(case)
        assert dkimbody.body_hash_b64(case, "simple") == probe.body_hash(case)


def test_body_hash_is_sha256_of_the_canonical_body():
    for canon in ("simple", "relaxed"):
        for case in CASES:
            canonical = dkimbody.canonicalize_body(case, canon)
            expected = base64.b64encode(hashlib.sha256(canonical).digest()).decode("ascii")
            assert dkimbody.body_hash_b64(case, canon) == expected


def test_the_whole_body_is_hashed():
    # There is no l= support, so an appended tail has to change the hash.
    head = b"a\r\n" * 32
    assert dkimbody.body_hash_b64(head, "relaxed") != dkimbody.body_hash_b64(head + b"tail\r\n", "relaxed")


def test_relaxed_and_simple_differ_on_the_same_body():
    assert dkimbody.body_hash_b64(RFC_BODY, "relaxed") != dkimbody.body_hash_b64(RFC_BODY, "simple")


def split_message(raw):
    """The header block and the body, cut at the first blank line."""
    found = [(raw.find(sep), sep) for sep in (b"\r\n\r\n", b"\n\n")]
    found = [(index, sep) for index, sep in found if index >= 0]
    if not found:
        return raw, b""
    index, sep = min(found)
    return raw[:index], raw[index + len(sep):]


def dkim_signatures(headers):
    """Tags of every field named exactly DKIM-Signature.

    ARC-Message-Signature, ARC-Seal and X-Google-DKIM-Signature carry the same
    tag names over a different input, so matching on anything looser than the
    full field name would hash a body against a bh nobody claimed for it.
    """
    found = []
    for name, value in dkimcore.parse_headers(headers):
        if dkimcore.field_name(name) == b"dkim-signature":
            found.append(dkimcore.parse_tags(value.decode("latin-1")))
    return found


def body_canon_of(tags):
    return tags.get("c", "").partition("/")[2].strip().lower() or "simple"


def test_relaxed_body_hash_matches_a_real_signature():
    files = sorted(SAMPLES.glob("*.eml")) if SAMPLES.is_dir() else []
    if not files:
        pytest.skip("no samples/*.eml in the working tree")
    checked = 0
    for path in files:
        headers, body = split_message(path.read_bytes())
        for tags in dkim_signatures(headers):
            if body_canon_of(tags) != "relaxed":
                continue
            got = dkimbody.body_hash_b64(body, "relaxed")
            # Only these five values are ever printed: nothing from the
            # message itself leaves this test.
            print("d=%s c=%s match=%s body=%d bare_lf=%d"
                  % (tags.get("d", ""), tags.get("c", ""),
                     got == dkimcore.unfold(tags.get("bh", "")),
                     len(body), dkimbody.count_bare_lf(body)))
            assert got == dkimcore.unfold(tags.get("bh", ""))
            checked += 1
    if not checked:
        pytest.skip("no sample signs with a relaxed body canonicalization")
