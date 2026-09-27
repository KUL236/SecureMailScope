# TLS Analysis

## What's extracted
From `app/parsing/tls_x509.py::parse_tls_records`, run on the reassembled
bytes *after* STARTTLS was accepted (or from the start of the stream for
implicit-TLS ports like 465):

| Field | Source |
|---|---|
| `tls_version_offered` | ClientHello legacy_version |
| `tls_version_negotiated` | ServerHello legacy_version, refined by the `supported_versions` extension if present (TLS 1.3 detection) |
| `cipher_suite` | ServerHello cipher suite (hex code; map to name in the UI layer if desired) |
| `sni` | ClientHello `server_name` extension |
| `alpn` | ClientHello ALPN extension |
| `handshake_complete` | `true` once a `Finished` (or its ciphertext wrapper) is observed |
| `alerts` | any TLS alert records, with level (1=warning, 2=fatal) and description code |
| certificates | parsed from the `Certificate` handshake message, each entry fed to X.509 parsing (`CERTIFICATE_ANALYSIS.md`) |

## Records vs. TShark
The parser reads raw TLS records (5-byte header: type/version/length) and
walks handshake sub-messages by their own length prefixes. It handles
both TLS 1.2-style and TLS 1.3-style Certificate messages (the latter has
a `certificate_request_context` + per-certificate extensions). It is
**best-effort**: malformed or truncated records are skipped, never
guessed — see the `except (IndexError, UnicodeError): return` pattern
throughout, which leaves fields as `None`/`NOT_OBSERVED` rather than
crashing or fabricating.

For captures this can't fully parse (e.g. many small TCP segments
splitting a single TLS record in ways the simple reassembly doesn't
recombine cleanly), add a TShark-based fallback via `pyshark`:
```python
import pyshark
cap = pyshark.FileCapture(pcap_path, display_filter="tls")
for pkt in cap:
    if hasattr(pkt, "tls"):
        # pkt.tls.handshake_certificate, pkt.tls.handshake_version, etc.
```
Wireshark's TLS field reference (`tls.handshake.certificate`,
`tls.handshake.version`, ...) documents every field name available this
way.

## Negotiated cipher suite: name, key exchange, forward secrecy
`app/parsing/cipher_suites.py` maps the raw hex cipher code from
ServerHello to a human-readable name, the key exchange mechanism
(ECDHE/DHE/RSA/UNKNOWN), the authentication mechanism, and a
`forward_secrecy` boolean. TLS 1.3 suites are always forward-secret
(ephemeral key exchange is baked into the protocol); static RSA key
exchange suites (`TLS_RSA_WITH_*`) are not. Unrecognized cipher codes are
conservatively reported as `forward_secrecy=False` rather than assumed
safe. `app/rules.py::NO_FORWARD_SECRECY` fires whenever
`forward_secrecy is False`, explaining the exposure and recommending
ECDHE/DHE-only configuration.

## Legacy/weak detection
`app/rules.py` flags:
- `LEGACY_TLS_VERSION`: TLS 1.0/1.1, SSL 3.0/2.0
- `WEAK_CIPHER`: NULL/EXPORT/RC4/DES/3DES/MD5 substrings in the cipher
  suite name
- `TLS_HANDSHAKE_INCOMPLETE`: handshake started but no Finished observed
- fatal alerts as `UNEXPECTED_CRYPTO_CONFIGURATION`

## TLS decryption — explicitly out of scope
Per the original spec, this system never collects or stores private
keys and never decrypts email payloads. If a future controlled research
mode needs to use TLS session secrets (e.g. from `SSLKEYLOGFILE`), keep
it fully isolated and explicitly opt-in — do not wire it into the core
pipeline.
