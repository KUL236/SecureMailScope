# PCAP Analysis

## Validation
`app/parsing/pcap_loader.py::validate_pcap` checks, in order:
1. Extension is `.pcap`/`.pcapng` (never trusted alone)
2. File is non-empty and under `MAX_PCAP_SIZE_BYTES`
3. Magic bytes match a real pcap/pcapng header (classic pcap
   little/big-endian, or pcapng's block magic) — this is what actually
   catches `INVALID_PCAP`, not the extension
4. SHA-256 computed by streaming 1MB chunks (safe for large files)

## TCP reconstruction
`app/parsing/tcp_reassembly.py::reassemble_streams` groups packets by
canonicalized 4-tuple, tracks SYN/SYN-ACK/FIN/RST flags to determine
`is_complete`, counts retransmissions (duplicate sequence numbers per
direction), and reassembles each direction's byte stream in the order
packets were seen (note: this is capture-order, not strict sequence-number
reordering — see the TODO below for handling genuinely out-of-order
captures).

**TODO for production**: add explicit sequence-number-based reordering
(buffer segments by `seq`, flush in order) rather than relying on
capture order, to correctly handle captures with real network-level
reordering (rare on a single vantage point, common on multi-path
captures).

## Protocol detection
Port numbers are a *hypothesis*, never a conclusion. `detect_protocol()`
in `app/parsing/smtp_starttls.py` requires the server's actual banner
text (`220 ... SMTP`, IMAP's `* OK`, POP3's `+OK`) to reach high
confidence; port-only matches are flagged with confidence 0.4 and
surfaced as such via `protocol_confidence` on `NetworkSession`.

## STARTTLS state machine
Chronological line-by-line walk of the reassembled SMTP session (see
`analyze_smtp_starttls`), producing the exact state sequence from your
spec: `PLAIN_SMTP -> STARTTLS_ADVERTISED -> STARTTLS_REQUESTED ->
STARTTLS_ACCEPTED -> ...`. Every state transition is timestamped and
tied to a `packet_no` for the evidence UI.

## Generating test PCAPs (Certificate Test Lab)
`tests/certgen.py` generates certificates locally (valid, expired,
not-yet-valid, self-signed, CA-chained) with **no internet dependency**.
To turn these into real PCAPs for end-to-end pipeline testing:
1. Run a local `openssl s_server` (or Python's `ssl` module) using a
   generated test certificate
2. Point a test SMTP client at it that issues EHLO/STARTTLS
3. Capture with `tshark -i lo -w test.pcap` (or `tcpdump`) while the
   exchange happens
4. Feed `test.pcap` into `POST /api/pcaps/upload`

This is the recommended way to build both the ML training set
(`ML_PIPELINE.md`) and a regression test corpus with known ground truth.

## Error handling (never hidden)
| Condition | Behavior |
|---|---|
| Invalid/corrupted PCAP | `400` from upload endpoint with `INVALID_PCAP: ...` |
| Empty PCAP | `400` with `EMPTY_PCAP` |
| Incomplete TCP stream | `NetworkSession.is_complete=False` + `SESSION_ANOMALY` finding, never silently treated as complete |
| Protocol not identified | `protocol_guess=None`, pipeline skips SMTP-specific analysis for that session rather than guessing |
| TLS not observed | `TlsHandshake.status="NOT_OBSERVED"`, no certificate rules fire |
| Certificate parse failure | logged and skipped per-certificate (`pipeline.py`'s `except Exception: continue`) — never fabricated |
| Any pipeline exception | `Investigation.status=FAILED` + `error_message` populated, re-raised to logs (see `app/pipeline.py`) |
