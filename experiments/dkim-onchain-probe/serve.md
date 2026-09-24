# Serving the blob for the length of one test

Note, 24 September 2026: the URL is published on chain. It is part of the
attest transaction's calldata, which is public from the moment the
transaction is submitted, so the random hostname and path below protect
nothing once the transaction is sent: anyone reading the chain can fetch the
blob for as long as it is served. See
[docs/interfaces.md](../../docs/interfaces.md), section 6.

The contract is given a URL and nothing else. The blob behind that URL is one
DKIM-Signature plus the headers it signs: no body, no recipient list, no
attachments. It still identifies a message, so it is published under a random
path, only while the attest transaction is in flight, and deleted afterwards.

## What the validators accept

Measured on Bradbury, 2026-09-22, and not negotiable from the contract side:

- **HTTPS on a domain name works.** Record 2 verified through a cloudflared
  quick tunnel on `trycloudflare.com`.
- **Plain HTTP to a raw IP on a non standard port is refused.** Records 0 and
  1 both came back `blob fetch failed: NondetException`. Record 0 used a
  truncated path that the server would have answered with 404, and it produced
  the same reason as record 1, whose path was correct and answered an
  external `curl` with the full 810 byte blob. The validators therefore
  rejected the URL before any request reached the server.

Serving the blob directly on a public port is not an option. It has to sit
behind a name with a certificate. The quick tunnel below is the shortest way
to get one on a host that has neither a domain nor a web server.

## Build the blob

On the machine that holds the message:

```bash
cd experiments/dkim-probe && python3 make_blob.py path/to/message.eml --domain amazon.com
```

It prints a byte count and nothing else. The output path defaults to
`/tmp/lacre-blob.txt` and `--out` overrides it; the rest of this page calls it
`BLOB`. Copy that one file to the host that will serve it:

```bash
scp "$BLOB" vps:blob.txt
```

## Serve it through a cloudflared quick tunnel

A quick tunnel needs no Cloudflare account and no DNS record. It hands back a
random `*.trycloudflare.com` hostname with a valid certificate, which is
exactly the shape the validators accept.

Install the binary once, straight from the GitHub release:

```bash
sudo curl -fsSL -o /usr/local/bin/cloudflared \
  https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
  && sudo chmod 755 /usr/local/bin/cloudflared && cloudflared --version
```

Start the local backend and the tunnel. `http.server` binds to loopback only:
the tunnel reaches it from the same host, so the port is never exposed and no
firewall rule is needed.

```bash
WORK="$HOME/lacre-blob"
SLUG=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
mkdir -p "$WORK" && cp ~/blob.txt "$WORK/$SLUG.txt"

( cd "$WORK" && setsid nohup python3 -m http.server 8765 --bind 127.0.0.1 \
    > "$WORK/http.log" 2>&1 & )

setsid nohup cloudflared tunnel --url http://localhost:8765 \
  > "$WORK/cloudflared.log" 2>&1 &
```

The hostname is assigned a few seconds after startup and only ever appears in
the log, so read it from there:

```bash
sleep 8
HOST=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$WORK/cloudflared.log" | head -1)
echo "$HOST/$SLUG.txt"
```

Confirm the validators will see the same bytes you do before spending gas.
The byte count must match what `make_blob.py` printed:

```bash
curl -sS -o /dev/null -w 'HTTP %{http_code}, %{size_download} bytes\n' "$HOST/$SLUG.txt"
```

Pass `$HOST/$SLUG.txt` to `attest_bradbury.py`, and tear the tunnel down as
soon as the transaction reaches ACCEPTED.

## Cleanup

Run all of it, including the firewall rule: an earlier plain HTTP attempt may
have left port 8765 open, and the tunnel never needed it.

```bash
pkill -f cloudflared
pkill -f 'http.server 8765'
rm -rf "$HOME/lacre-blob"
sudo ufw delete allow 8765/tcp
```

Then confirm nothing survived. Each command prints the fallback message when
the host is clean:

```bash
pgrep -af 'cloudflared|http\.server' || echo "no tunnel or server running"
ss -ltn 'sport = :8765' | grep -q 8765 && echo "PORT 8765 STILL LISTENING" || echo "port 8765 closed"
ls "$HOME/lacre-blob" 2>/dev/null || echo "work directory removed"
sudo ufw status | grep -q 8765 && echo "FIREWALL RULE STILL PRESENT" || echo "no firewall rule for 8765"
```

## Why a public URL is acceptable here at all

The blob is readable by anyone who has the hostname for as long as the tunnel
is up, so it is worth being explicit about what that does and does not cost:

- The blob carries an RSA signature over its own headers. Rewriting a byte in
  transit makes the signature fail and the probe records `valid=false` rather
  than accepting the altered version. An attacker on the path can break the
  measurement; forging one that passes needs the sender's private key, which
  is the whole point of the check.
- The key the signature is verified against is fetched over HTTPS from
  `dns.google` by each validator independently, not over this connection.
- The hostname is random and the filename carries another 128 bits, the blob
  holds no body and no credential, and it is public for minutes.

What remains is that the headers themselves are disclosed to anyone holding
the URL. Use a message you are willing to publish.
