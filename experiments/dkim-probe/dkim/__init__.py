"""Pure Python DKIM verification probe.

The package is split so that the verification core (rfc6376) never imports the
network module (dns_doh). The same split is expected in the contract port,
where key retrieval becomes a non-deterministic web call and everything else
stays deterministic.
"""
