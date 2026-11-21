# Security policy

`qb` sits next to subscription credentials, so security reports are welcome.

- Report privately via GitHub's "Report a vulnerability" (Security tab):
  <https://github.com/pasekahq/quota-balancer/security/advisories/new>. Please do not open a
  public issue for a vulnerability.
- Include the version (`qb --version`), the role involved (`qbd`, `qb agent`, `qb gateway`, CLI) and steps to
  reproduce.

Threat model in short: the daemon holds no vendor secrets and has no network access. Only the
agent and the optional gateway touch credential files, both under landlock and as the
credential owner: the agent reads them, read-only and briefly; the gateway reads them per
request and writes refreshed OAuth tokens back. See `docs/design.md` and
`docs/adr/0001-model-gateway.md`.

## Secret copies outside `zeroize`

The agent and the gateway read a credential file into a zeroizing buffer and build each secret
header value at its final size in a zeroizing string. The agent borrows the token straight from
that buffer: it reads the JSON string raw and refuses one with escapes, so the JSON parser never
unescapes it into a scratch buffer of its own. Sending the request still makes copies that are
freed without being overwritten:

- **ureq's header value.** ureq copies each header value, `Authorization` included, into an
  `http::HeaderValue` when the request is built; it is freed when the call returns.
- **ureq's output buffer.** ureq writes the request head into the connection's output buffer. It
  lives as long as the connection: until the connection closes, or for at most 15 s (ureq's
  idle age) in the agent's connection pool.
- **rustls.** rustls copies the plaintext it encrypts into its record buffers, and holds it in
  plaintext while a handshake is not yet done.

The same holds for the body of the gateway's OAuth token requests. Every copy stays in freed heap
memory of the process that read the file: non-dumpable (no core dump, no `ptrace` by the same
user), confined by landlock, and running as the credential owner, who can read the file anyway.
Closing these needs ureq and rustls to zeroize their buffers: `http::HeaderValue` shares a buffer
only through a `bytes::Bytes`, which would remove the first copy alone, and the output and record
buffers sit behind ureq's transport and rustls's connection, so it takes a fork of both.
