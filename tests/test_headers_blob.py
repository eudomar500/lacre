"""tools/headers_blob.py: the blob attest_inline takes, cut from a message.

The messages here are signed on the spot with the Verifier stub run's
throwaway key, so "the blob verifies" is the Verifier's own RSA check in
lacre/dkimcore.py and not a comparison with a stored answer. The sample
message, when it is on disk, is also held to the probe's make_blob.py, which
cut the blob of the first record on Verifier v1.2.
"""

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

from lacre import dkimcore

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "experiments" / "dkim-probe" / "samples" / "amazon-shipped.eml"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = load(ROOT / "tools" / "headers_blob.py", "lacre_test_headers_blob")
stub = load(ROOT / "tests" / "verifier_stub_run.py", "lacre_test_headers_blob_stub")
KEY = stub.generate_key()

HEADERS = ["From: Shop <orders@lacre.test>", "To: someone@example.org",
           "Subject: first", "Subject: second", "Date: Mon, 28 Sep 2026 10:00:00 +0000"]


def message(names, headers=HEADERS, above=(), below=(), body=b"hello\r\n"):
    """A whole message: unsigned fields above the signature, the signed
    block, more unsigned fields, then the body."""
    signed = stub.sign(KEY, list(headers), names)
    lines = "".join(line + "\r\n" for line in above).encode()
    lines += signed + "".join(line + "\r\n" for line in below).encode()
    return lines + b"\r\n" + body


def verifies(text):
    return dkimcore.verify_headers(text.encode("utf-8"), KEY["n"], KEY["e"])[0]


def names_in(text):
    return [dkimcore.field_name(name).decode() for name, _ in
            dkimcore.parse_headers(text.encode("utf-8"))]


def test_the_blob_is_the_signature_and_what_it_signs():
    raw = message(["from", "to", "subject", "date"],
                  above=["Received: from relay by mx; Mon, 28 Sep 2026"],
                  below=["X-Unsigned: yes", "Received: from inner"])
    text = tool.build(raw, "lacre.test", "stub")
    assert verifies(text)
    assert names_in(text) == ["dkim-signature", "from", "to", "subject", "date"]
    assert "Subject: second" in text and "Subject: first" not in text
    assert "hello" not in text and "Received" not in text and "X-Unsigned" not in text
    assert text.endswith("\r\n") and "\n" not in text.replace("\r\n", "")


def test_a_repeated_name_is_taken_bottom_up_as_signed_data_takes_it():
    both = tool.build(message(["from", "subject", "subject"]), "lacre.test")
    assert verifies(both) and names_in(both).count("subject") == 2
    assert both.index("Subject: first") < both.index("Subject: second")
    one = tool.build(message(["from", "subject"]), "lacre.test")
    assert verifies(one) and "Subject: first" not in one


def test_an_oversigned_name_adds_nothing():
    text = tool.build(message(["from", "from", "to"]), "lacre.test")
    assert verifies(text) and names_in(text) == ["dkim-signature", "from", "to"]


def test_the_blob_does_not_trip_the_duplicate_rule():
    # The Verifier refuses a blob holding more instances of a signed name
    # than h= lists; the cut carries only the ones listed.
    names = ["from", "subject"]
    text = tool.build(message(names), "lacre.test")
    present = names_in(text)[1:]
    assert all(present.count(name) <= names.count(name) for name in names)


def test_an_lf_only_copy_cuts_to_the_same_blob():
    raw = message(["from", "to", "subject"])
    assert tool.build(raw.replace(b"\r\n", b"\n"), "lacre.test") == tool.build(raw, "lacre.test")


def test_the_signature_is_chosen_by_domain_and_selector():
    raw = message(["from", "to"], above=["DKIM-Signature: v=1; a=rsa-sha256; d=relay.test;"
                                         " s=r1; h=from; bh=x; b=y"])
    text = tool.build(raw, "LACRE.test.", "STUB")
    assert verifies(text) and "d=relay.test" not in text
    with pytest.raises(tool.BlobError, match="no DKIM-Signature with d=lacre.test and s=other"):
        tool.build(raw, "lacre.test", "other")
    with pytest.raises(tool.BlobError, match="no DKIM-Signature with d=example.com"):
        tool.build(raw, "example.com")


def test_two_selectors_for_one_domain_need_the_selector():
    raw = message(["from"], above=["DKIM-Signature: v=1; a=rsa-sha256; d=lacre.test;"
                                   " s=second; h=from; bh=x; b=y"])
    with pytest.raises(tool.BlobError, match="pass SELECTOR"):
        tool.build(raw, "lacre.test")
    assert verifies(tool.build(raw, "lacre.test", "stub"))


def test_headers_that_are_not_utf8_are_refused():
    raw = message(["from", "subject"], headers=["From: a@lacre.test", "Subject: caf\xe9"])
    assert b"caf\xc3\xa9" in raw
    with pytest.raises(tool.BlobError, match="not UTF-8"):
        tool.build(raw.replace(b"caf\xc3\xa9", b"caf\xe9"), "lacre.test")


def test_an_oversized_blob_is_refused():
    long = "Subject: " + "x" * tool.MAX_BLOB
    with pytest.raises(tool.BlobError, match="over the 16384"):
        tool.build(message(["from", "subject"], headers=["From: a@lacre.test", long]),
                   "lacre.test")


def test_a_tracked_file_is_refused_and_an_ignored_or_outside_one_is_not(tmp_path):
    assert tool.tracked(ROOT / "README.md")
    assert not tool.tracked(tmp_path / "message.eml")
    assert not tool.tracked(ROOT / "samples" / "message.eml")
    with pytest.raises(SystemExit, match="not gitignored"):
        tool.main([str(ROOT / "README.md"), "lacre.test"])


def test_digest_prints_the_length_and_hash_and_nothing_of_the_message(tmp_path, capsys):
    path = tmp_path / "message.eml"
    path.write_bytes(message(["from", "to", "subject"]))
    tool.main([str(path), "lacre.test", "--digest"])
    out = capsys.readouterr().out
    data = tool.build(path.read_bytes(), "lacre.test").encode("utf-8")
    assert out == "bytes        : %d\nsha256       : %s\n" % (
        len(data), hashlib.sha256(data).hexdigest())


@pytest.mark.skipif(not SAMPLE.is_file(), reason="samples are not tracked")
def test_the_sample_cuts_to_the_probes_blob():
    sys.path.insert(0, str(ROOT / "experiments" / "dkim-probe"))
    make_blob = load(ROOT / "experiments" / "dkim-probe" / "make_blob.py",
                     "lacre_test_make_blob")
    raw = SAMPLE.read_bytes()
    text = tool.build(raw, stub.DOMAIN, stub.SELECTOR)
    assert text.encode("utf-8") == make_blob.build_blob(raw, stub.DOMAIN)
