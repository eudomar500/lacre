"""Local DKIM verification probe.

Usage:
    python probe.py samples/amazon-shipped.eml --domain amazon.com

Prints a report on one DKIM-Signature: what was signed, whether the header
signature verifies, whether the body hash matches under either line ending
convention, and how long the two expensive steps take. The report never
contains the message body, and no header value other than the signature tags.
"""

import argparse
import importlib.machinery
import importlib.util
import os
import re
import sys
import time
from urllib.error import URLError

from dkim import dns_doh, rfc6376


def load_message(path):
    with open(path, "rb") as handle:
        return handle.read()


def pick_signature(fields, domain, selector=None):
    """First DKIM-Signature whose d= matches, and whose s= matches if given."""
    for name, value in fields:
        if rfc6376.field_name(name) != b"dkim-signature":
            continue
        tags = rfc6376.parse_tag_list(value.decode("latin-1"))
        if tags.get("d") != domain:
            continue
        if selector is not None and tags.get("s") != selector:
            continue
        return tags
    return None


def measure(function, *args, **kwargs):
    """Return (result, elapsed milliseconds)."""
    start = time.perf_counter()
    value = function(*args, **kwargs)
    return value, (time.perf_counter() - start) * 1000.0


def match_body_hash(raw_body, expected, canonicalization):
    """Try both line ending conventions, report the one that matched."""
    timings = {}
    matched = None
    for mode in rfc6376.LINE_ENDING_MODES:
        digest, elapsed = measure(
            rfc6376.body_hash, raw_body, mode, canonicalization
        )
        timings[mode] = elapsed
        if matched is None and digest == expected:
            matched = mode
    return matched, timings


def flip_one_byte(data, offset):
    """Flip the low bit of one byte, leaving length and structure untouched."""
    mutated = bytearray(data)
    mutated[offset] ^= 0x01
    return bytes(mutated)


def subject_value_offset(raw_headers):
    """Offset of the first byte of the Subject value, for the tamper check."""
    match = re.search(rb"(?im)^subject:[ \t]*", raw_headers)
    if match is None or match.end() >= len(raw_headers):
        return None
    if raw_headers[match.end()] in b"\r\n":
        return None
    return match.end()


def tamper_checks(raw_headers, raw_body, selector, domain, n, e, expected_bh, mode, body_canon):
    """A verifier that cannot be made to fail is not a verifier."""
    results = {}

    body_offset = next(
        (i for i, byte in enumerate(raw_body) if byte not in b"\r\n"), None
    )
    if body_offset is None:
        results["body byte flipped"] = "skipped (body has no data byte)"
    else:
        digest = rfc6376.body_hash(flip_one_byte(raw_body, body_offset), mode, body_canon)
        results["body byte flipped"] = "rejected" if digest != expected_bh else "ACCEPTED"

    offset = subject_value_offset(raw_headers)
    if offset is None:
        results["subject byte flipped"] = "skipped (no Subject field)"
    else:
        outcome = rfc6376.verify_headers(
            flip_one_byte(raw_headers, offset), selector, domain, n, e
        )
        results["subject byte flipped"] = "rejected" if not outcome["valid"] else "ACCEPTED"

    return results


def crosscheck(raw):
    """Optional second opinion from dkimpy, loaded only when asked for.

    dkimpy's package is also called "dkim", so the probe's own package shadows
    it on sys.path. It is located by searching the rest of sys.path and then
    bound to the name it expects for the length of the call, since its own
    submodules import each other relatively.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    search = [entry for entry in sys.path if entry and os.path.abspath(entry) != here]
    spec = importlib.machinery.PathFinder().find_spec("dkim", search)
    if spec is None or spec.loader is None:
        return "dkimpy is not installed"

    module = importlib.util.module_from_spec(spec)
    shadowed = {n: m for n, m in sys.modules.items() if n == "dkim" or n.startswith("dkim.")}
    for name in shadowed:
        del sys.modules[name]
    sys.modules["dkim"] = module
    try:
        spec.loader.exec_module(module)
        return "pass" if module.verify(raw) else "fail"
    except Exception as error:  # dkimpy raises a family of its own errors
        return "error: %s" % (error,)
    finally:
        for name in [n for n in sys.modules if n == "dkim" or n.startswith("dkim.")]:
            del sys.modules[name]
        sys.modules.update(shadowed)


def render(rows):
    width = max(len(label) for label, _ in rows)
    return "\n".join("%-*s : %s" % (width, label, value) for label, value in rows)


def run(args):
    raw = load_message(args.path)
    raw_headers, raw_body = rfc6376.split_message(raw)
    fields = rfc6376.parse_header_fields(raw_headers)

    tags = pick_signature(fields, args.domain, args.selector)
    if tags is None:
        print("no DKIM-Signature with d=%s in %s" % (args.domain, args.path))
        return 2
    selector = tags.get("s", "")

    try:
        record = dns_doh.fetch_dkim_key(selector, args.domain, timeout=args.timeout)
        n, e, key = rfc6376.public_key_from_record(record)
    except (URLError, LookupError, OSError, ValueError) as error:
        print("key lookup failed for %s._domainkey.%s: %s" % (selector, args.domain, error))
        return 2

    header_result, rsa_ms = measure(
        rfc6376.verify_headers, raw_headers, selector, args.domain, n, e
    )
    _, body_canon = rfc6376.parse_canonicalization(header_result["canonicalization"])
    expected_bh = header_result["bh_from_header"]
    matched_mode, body_ms = match_body_hash(raw_body, expected_bh, body_canon)

    checks = tamper_checks(
        raw_headers, raw_body, selector, args.domain, n, e,
        expected_bh, matched_mode or "as-is", body_canon,
    )

    tampering_rejected = all(v != "ACCEPTED" for v in checks.values())
    passed = header_result["valid"] and matched_mode is not None and tampering_rejected
    if passed:
        reason = "header signature and body hash both verify"
    elif not header_result["valid"]:
        reason = header_result["reason"]
    elif matched_mode is None:
        reason = "body hash does not match bh= under either line ending mode"
    else:
        reason = "a tampered message still verified"

    rows = [
        ("message", args.path),
        ("selector", selector),
        ("domain", args.domain),
        ("algorithm", header_result["algorithm"]),
        ("canonicalization", header_result["canonicalization"]),
        ("signed headers", ":".join(header_result["signed_fields"])),
        ("l= tag present", "yes" if header_result["has_length_tag"] else "no"),
        ("key type", "%s (t=%s)" % (key["k"], key["t"] or "none")),
        ("key size", "%d bits" % n.bit_length()),
        ("public exponent", str(e)),
        ("signed header data", "%d bytes" % header_result["signed_data_bytes"]),
        ("body size", "%d bytes" % len(raw_body)),
        ("bh match", "yes (%s)" % matched_mode if matched_mode else "no"),
        ("header signature valid", "yes" if header_result["valid"] else "no"),
        ("rsa verify time", "%.3f ms" % rsa_ms),
        ("body hash time as-is", "%.3f ms" % body_ms["as-is"]),
        ("body hash time crlf", "%.3f ms" % body_ms["crlf"]),
    ]
    rows.extend(("tamper: " + label, value) for label, value in sorted(checks.items()))
    if args.crosscheck:
        rows.append(("dkimpy crosscheck", crosscheck(raw)))
    rows.append(("result", "PASS" if passed else "FAIL"))
    rows.append(("reason", reason))

    print(render(rows))
    return 0 if passed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify one DKIM signature on a local message.")
    parser.add_argument("path", help="path to a raw .eml message")
    parser.add_argument("--domain", required=True, help="the d= value to verify")
    parser.add_argument("--selector", help="the s= value, if the domain has several")
    parser.add_argument("--timeout", type=float, default=10.0, help="DoH timeout in seconds")
    parser.add_argument(
        "--crosscheck",
        action="store_true",
        help="also run dkimpy, if it happens to be installed (development only)",
    )
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
