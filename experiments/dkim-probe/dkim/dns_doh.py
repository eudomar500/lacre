"""DNS over HTTPS lookup of a DKIM key record.

This is the only module in the probe that touches the network. In the contract
port the body of fetch_txt becomes a single web.get call under a comparative
equivalence principle; nothing else in the package has to change.
"""

import json
import re
import urllib.parse
import urllib.request

RESOLVER_URL = "https://dns.google/resolve"
TXT_RECORD_TYPE = 16

_QUOTED_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')


def key_record_name(selector, domain):
    """RFC 6376 section 3.6.2.1: the record lives under _domainkey."""
    return "%s._domainkey.%s" % (selector, domain)


def fetch_txt(name, timeout=10.0, resolver_url=RESOLVER_URL):
    """Return the TXT rdata for a name as one concatenated string."""
    url = resolver_url + "?" + urllib.parse.urlencode({"name": name, "type": "TXT"})
    request = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    status = payload.get("Status")
    if status != 0:
        raise LookupError("resolver returned status %s for %s" % (status, name))
    return join_txt_answers(payload.get("Answer") or [])


def join_txt_answers(answers):
    """Concatenate the TXT character-strings, skipping CNAME hops.

    A delegated selector (the common setup at the large senders) answers with a
    CNAME followed by the TXT at the target, so the answer list is filtered by
    type rather than taken as given. Long keys are split into several
    character-strings inside one record and must be joined with no separator.
    """
    chunks = []
    for answer in answers:
        if answer.get("type") != TXT_RECORD_TYPE:
            continue
        chunks.append(_unquote(answer.get("data", "")))
    if not chunks:
        raise LookupError("no TXT record in the answer")
    return "".join(chunks)


def _unquote(data):
    pieces = _QUOTED_STRING.findall(data)
    if not pieces:
        return data
    return "".join(p.replace('\\"', '"').replace("\\\\", "\\") for p in pieces)


def fetch_dkim_key(selector, domain, timeout=10.0, resolver_url=RESOLVER_URL):
    """Convenience wrapper: selector and domain in, key record text out."""
    return fetch_txt(key_record_name(selector, domain), timeout, resolver_url)
