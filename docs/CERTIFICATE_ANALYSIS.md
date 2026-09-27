# X.509 Certificate Analysis

## Extraction path
```
TLS Certificate handshake message (parsed in tls_x509.py)
  -> DER bytes per certificate entry
  -> cryptography.x509.load_der_x509_certificate()
  -> CertificateInfo (app/parsing/tls_x509.py::parse_der_certificate)
```
No certificate is ever fetched externally or fabricated — every field
traces back to bytes actually present in the capture.

## Fields extracted
subject, issuer, serial_number, version, not_before/not_after,
public_key_type + size (RSA/EC/DSA via `isinstance` checks against
`cryptography`'s key classes), signature_algorithm, SAN, basic
constraints, key usage, extended key usage, authority/subject key
identifiers, SHA-256 fingerprint (of the raw DER), byte length.

## Status determination
`parse_der_certificate` compares `not_before`/`not_after` against current
UTC time and checks `subject == issuer` for self-signed detection:

| Status | Condition |
|---|---|
| `EXPIRED` | `now > not_after` |
| `NOT_YET_VALID` | `now < not_before` |
| `SELF_SIGNED` | `subject == issuer` (checked after the date checks) |
| `VALID` | none of the above at parse time (chain trust re-evaluated below, and can downgrade this) |
| `CHAIN_ISSUE` | issuer not observed in the capture *and* not found in the local trust store |
| `CHAIN_SIGNATURE_INVALID` | a signature in the chain did not cryptographically verify against its issuer's real public key |

## Chain reconstruction and cryptographic verification
Chain handling is now two passes, run automatically inside
`parse_tls_records()`:

1. **`evaluate_chain()`** (`tls_x509.py`) -- the original cheap pass:
   links certificates by matching `issuer` strings against observed
   `subject` strings within the same handshake, and provisionally marks
   the leaf `CHAIN_ISSUE` if its issuer isn't present.
2. **`verify_certificate_chain()`** (`app/parsing/chain_validation.py`)
   -- the real cryptographic pass, which runs immediately after and can
   correct pass 1's verdict:
   - Each consecutive pair of certificates actually observed in the
     capture has its signature verified against the issuer's real
     public key (`cryptography`'s `verify_directly_issued_by`, not a
     name comparison).
   - If the top-most certificate in the capture is not self-signed
     (the normal case -- servers send leaf + intermediate(s) and omit
     the root), its issuer is looked up **by subject name in a local
     root CA trust store** (Mozilla's bundle, shipped via the `certifi`
     package, loaded once from disk -- no network call), and the
     signature is verified against that root's real public key.
   - If the top-most certificate *is* self-signed, it's only treated
     as trusted when it matches a known root **by SHA-256 fingerprint**
     -- `subject == issuer` alone is never treated as trust.
   - Every certificate gets `.chain_signature_verified` (True/False/
     `None` if undeterminable) and `.issuer_public_key_source`
     (`OBSERVED_IN_CAPTURE` / `LOCAL_TRUST_STORE` / `NOT_AVAILABLE`).
   - The leaf additionally gets `.chain_validation_status` (one of
     `CHAIN_VALID_TRUSTED_ROOT`, `CHAIN_VALID_SELF_SIGNED_ROOT_TRUSTED`,
     `CHAIN_SIGNATURE_INVALID`, `CHAIN_SELF_SIGNED_UNTRUSTED_ROOT`,
     `CHAIN_INCOMPLETE_NO_TRUST_ANCHOR`, `CHAIN_VALIDATION_ERROR`) and a
     `.chain_validation_detail` dict recording exactly which links were
     checked, against what, and with what result.

   A cryptographically valid chain to a trusted root corrects an
   over-pessimistic `CHAIN_ISSUE` from pass 1 back to `VALID`. A broken
   signature downgrades `VALID` to `CHAIN_SIGNATURE_INVALID` and fires
   the `CERT_CHAIN_SIGNATURE_INVALID` (CRITICAL) rule in `rules.py` --
   this is the case most worth an analyst's attention, since a normal
   misconfiguration produces an *incomplete* chain, not an *invalid
   signature*.

   `CertificateChainLink.link_type` in the schema still distinguishes
   `OBSERVED` (what's actually in the packet) from `EXPECTED_EXTERNAL`
   chain members (the trust-store-supplied root, when used).

   What this still does **not** do: policy/name-constraint checking,
   path-length enforcement, or building anything beyond a simple linear
   chain. It answers "does this signature chain cryptographically to a
   locally trusted root," not the full RFC 5280 path-validation
   algorithm.

## Revocation -- explicit, opt-in live checking
`revocation_status` still defaults to `NOT_DETERMINED_FROM_PCAP` and a
passive PCAP still carries no revocation information by itself. What's
new is `app/parsing/revocation.py`, which *can* determine real
revocation status via a live OCSP request (primary) or CRL fetch
(fallback), extracting the responder/distribution-point URL from the
certificate's AIA / CRL Distribution Points extensions.

This is **off by default** (`config.ENABLE_LIVE_REVOCATION_CHECKS`,
env var `ENABLE_LIVE_REVOCATION_CHECKS=true`) because it's a genuine
network call to a third party (the issuing CA), which is a deliberate,
explicit departure from this tool's passive-capture-only design point --
an operator has to opt in. When enabled, every outcome is one of a
specific set of statuses (`GOOD_OCSP`, `REVOKED_OCSP`, `UNKNOWN_OCSP`,
`GOOD_CRL`, `REVOKED_CRL`, `NO_REVOCATION_ENDPOINT_IN_CERTIFICATE`,
`REVOCATION_CHECK_UNAVAILABLE`, `ISSUER_CERTIFICATE_UNAVAILABLE`) --
never silently coerced into "valid" just because a check couldn't be
completed. `REVOKED_OCSP`/`REVOKED_CRL` fires the `CERT_REVOKED`
(CRITICAL) rule.

## Hostname validation
`evaluate_hostname(sni, leaf_cert)` returns:
- `MATCH` — SNI matches a SAN entry (including wildcard `*.example.com`
  matching) or the certificate's CN
- `MISMATCH` — SNI present, but matches nothing on the leaf certificate
- `NO_HOSTNAME_EVIDENCE` — no SNI was observed (e.g. non-SNI TLS, or TLS
  not reached) — never reported as a mismatch when there's no hostname
  evidence to compare

## Weak crypto rules
`WEAK_KEY_SIZE` fires for RSA < 2048 bits. `LEGACY_SIGNATURE_ALGORITHM`
fires for MD5/SHA1-based signature algorithms. Both thresholds are
constants at the top of `app/rules.py` (`WEAK_RSA_BITS`,
`LEGACY_SIG_ALGOS`) — adjust to your org's policy and bump
`RULE_VERSION` in `app/config.py` when you do, so historical findings
remain attributable to the policy that produced them.
