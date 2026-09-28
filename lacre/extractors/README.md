# Pattern documents

One JSON document per sender domain, which the Extractor's owner stores with
`set_patterns(domain, document)`. The file name is for people; the contract
keys a document by the domain it was set under.

A document is an object with exactly four keys, each a list of Python `re`
expressions:

| key | what a match means |
|-----|--------------------|
| `shipped` | any expression matching anywhere sets `shipped` true |
| `eta_day` | the first expression whose first match yields a weekday sets `eta_day`; the weekday is group 1, or the whole match for an expression with no group, and has to be one of `lunes` to `domingo` |
| `eta_date` | the first expression whose first match yields a valid date sets `eta_date` as `YYYY-MM-DD`; each expression needs named groups `y`, `m` and `d`, all ASCII digits |
| `order_id` | any expression matching anywhere sets `order_id_found` true; the matched text is never kept |

The expressions run over the first `text/plain` part of the body, decoded as
UTF-8, with the lowercase accented vowels, u with diaeresis and n with tilde
folded to ASCII and then the text lowercased, the body probe's order, so they
are written in lowercase ASCII. An empty list never matches. The whole
document, trimmed of surrounding whitespace, is at most 4096 bytes, and its
SHA-256 over those trimmed bytes is what every record carries as
`patterns_sha256`. The full rules are in [docs/extractor.md](../../docs/extractor.md).

`amazon.json` is the amazon.com Spanish shipping template, ported from the
three expressions the body probe measured on Bradbury.

To check a document before it is stored, run it against a message you hold:

```bash
python3 tools/extract_check.py path/to/message.eml lacre/extractors/amazon.json --domain amazon.com
```

It rejects a document the contract would reject, verifies the body against
the signature's `bh=`, and prints the canonical string the validators would
agree on and the document's SHA-256. Send the document to `set_patterns`
exactly as checked; `patterns_sha256(domain)` on the contract has to print
the same digest afterwards.
