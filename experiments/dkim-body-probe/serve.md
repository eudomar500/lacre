# Serving the body for the length of one test

Note, 24 September 2026: the URL is published on chain. It is part of the
attest transaction's calldata, which is public from the moment the
transaction is submitted, so "anyone holding the hostname" below means
anyone reading the chain, and the random hostname and filename protect
nothing once the transaction is sent: the body can be fetched by anyone for
as long as it is served. See
[docs/interfaces.md](../../docs/interfaces.md), section 6.

The mechanics are the header probe's, unchanged. Follow
[../dkim-onchain-probe/serve.md](../dkim-onchain-probe/serve.md): what the
validators accept, installing `cloudflared`, starting the quick tunnel,
reading the hostname out of the log, confirming the byte count with `curl`,
and the cleanup block at the end. Record 0 was served exactly that way, with
`python3 -m http.server 8765 --bind 127.0.0.1` behind a cloudflared quick
tunnel on `trycloudflare.com`, and all five validators fetched the full
116 564 bytes.

Three things differ.

## The file is the raw body, not a header blob

Build it with `make_body.py` rather than `make_blob.py`:

```bash
cd experiments/dkim-probe && python3 make_body.py path/to/message.eml
```

It prints the byte count and the simple canonicalized body hash, and writes
the bytes to `/tmp/lacre-body.bin` unless `--out` says otherwise. The hash is
the value to pass as `BH_CLAIMED`; it must equal the `bh=` tag of the
signature you are attesting against, and if it does not, there is nothing to
measure on chain.

The file is about 116 KB rather than 810 bytes. Serve it as
`$SLUG.bin` instead of `$SLUG.txt`, and check the byte count the tunnel
returns against the one `make_body.py` printed before spending gas: a proxy
that rewrites a single byte changes the hash, and the probe would record that
as a mismatch rather than as the transport fault it is.

## It contains personal data, so the tunnel is not a convenience

The header blob is a set of routing headers. The body is the message: it
carries the recipient's name, their delivery address, what they bought and
when it arrives, and anyone holding the hostname can read all of it for as
long as the tunnel is up. The hostname is random and the filename carries
another 128 bits, which buys obscurity and nothing else.

So:

- Start the tunnel immediately before the attest call, not while you are still
  setting up.
- **Run the cleanup block the moment the write reaches ACCEPTED.** Not after
  FINALIZED, which can be 30 minutes later, and not at the end of the session.
  ACCEPTED means every validator has already fetched what it needed.
- Use a message whose recipient is you.

## Cleaning up over ssh needs the bracket form

The cleanup and the checks that nothing survived are in the header probe's
`serve.md`, and the filename is the only thing that changes about them. There
is one trap, and it cost a session today.

`pkill -f cloudflared` matches against the full command line of every process.
When you are on the host over ssh, the shell running the cleanup has that
pattern in its own command line, so `pkill` kills the shell before it gets to
the rest of the block. The connection drops, the tunnel survives, and the body
stays public until you notice. `pgrep -af 'cloudflared|http\.server'` has the
same problem in reverse: it reports itself and the shell, so it never prints
the "nothing is running" fallback and you cannot tell a clean host from a
dirty one.

Bracket one character of each pattern. A bracket expression matches the same
process names but not the literal text in the command line that contains it:

```bash
pkill -f 'cloudflare[d]'
pkill -f 'http\.serve[r] 8765'
rm -rf "$HOME/lacre-body"
sudo ufw delete allow 8765/tcp
```

```bash
pgrep -af 'cloudflare[d]|http\.serve[r]' || echo "no tunnel or server running"
ss -ltn 'sport = :8765' | grep -q 8765 && echo "PORT 8765 STILL LISTENING" || echo "port 8765 closed"
ls "$HOME/lacre-body" 2>/dev/null || echo "work directory removed"
sudo ufw status | grep -q 8765 && echo "FIREWALL RULE STILL PRESENT" || echo "no firewall rule for 8765"
```

Run the verification from a fresh connection if the first one dropped. A
cleanup you could not read the output of is not a cleanup.
