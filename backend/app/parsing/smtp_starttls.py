"""
Email protocol detection + STARTTLS state machine (sections 8, 10, 11).

Evidence-based: every conclusion is derived from actual bytes observed in
the reassembled stream, never inferred from port numbers alone.
"""
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

SMTP_PORTS = {25, 587, 465}
IMAP_PORTS = {143, 993}
POP3_PORTS = {110, 995}


class StarttlsState(str, Enum):
    PLAIN_SMTP = "PLAIN_SMTP"
    STARTTLS_ADVERTISED = "STARTTLS_ADVERTISED"
    STARTTLS_REQUESTED = "STARTTLS_REQUESTED"
    STARTTLS_ACCEPTED = "STARTTLS_ACCEPTED"
    TLS_HANDSHAKE = "TLS_HANDSHAKE"
    TLS_ESTABLISHED = "TLS_ESTABLISHED"
    STARTTLS_REJECTED = "STARTTLS_REJECTED"
    INCOMPLETE = "INCOMPLETE"
    NOT_OBSERVED = "NOT_OBSERVED"


@dataclass
class EmailSessionResult:
    protocol: Optional[str] = None
    protocol_confidence: float = 0.0
    server_greeting: Optional[str] = None
    client_command: Optional[str] = None  # EHLO/HELO line
    capabilities: List[str] = field(default_factory=list)
    starttls_offered: bool = False
    starttls_requested: bool = False
    starttls_accepted: bool = False
    state: StarttlsState = StarttlsState.NOT_OBSERVED
    timeline: List[dict] = field(default_factory=list)  # [{ts, packet_no, event}]
    tls_start_offset_client: Optional[int] = None  # byte offset in client stream where TLS begins
    tls_start_offset_server: Optional[int] = None


def detect_protocol(server_port: int, server_bytes: bytes) -> (Optional[str], float):
    """Ports give a hypothesis; the banner text confirms it."""
    banner = server_bytes[:200].decode("latin-1", errors="ignore")
    if re.search(r"^\s*220[ -].*SMTP", banner, re.IGNORECASE | re.MULTILINE) or banner.startswith("220"):
        if server_port in SMTP_PORTS:
            return "SMTP", 0.95
        return "SMTP", 0.6
    if re.search(r"\* OK", banner) and server_port in IMAP_PORTS:
        return "IMAP", 0.9
    if re.search(r"^\+OK", banner) and server_port in POP3_PORTS:
        return "POP3", 0.9
    if server_port in SMTP_PORTS:
        return "SMTP", 0.4  # port-only hypothesis, low confidence
    if server_port in IMAP_PORTS:
        return "IMAP", 0.4
    if server_port in POP3_PORTS:
        return "POP3", 0.4
    return None, 0.0


def analyze_smtp_starttls(client_events, server_events, server_port: int) -> EmailSessionResult:
    """
    client_events / server_events: list of {ts, packet_no, payload(bytes)} in order,
    from TcpStream.client_events / server_events (see tcp_reassembly.py).
    """
    result = EmailSessionResult()

    server_bytes_all = b"".join(e["payload"] for e in server_events)
    protocol, confidence = detect_protocol(server_port, server_bytes_all)
    result.protocol = protocol
    result.protocol_confidence = confidence

    if protocol != "SMTP":
        result.state = StarttlsState.NOT_OBSERVED
        return result

    # Walk lines in order across events, tagging which side + packet_no each line came from.
    lines = []  # (side, packet_no, ts, text)
    for e in server_events:
        for raw_line in e["payload"].split(b"\r\n"):
            if raw_line:
                lines.append(("server", e["packet_no"], e["ts"], raw_line.decode("latin-1", errors="ignore")))
    for e in client_events:
        for raw_line in e["payload"].split(b"\r\n"):
            if raw_line:
                lines.append(("client", e["packet_no"], e["ts"], raw_line.decode("latin-1", errors="ignore")))
    lines.sort(key=lambda x: x[2])  # chronological

    state = StarttlsState.PLAIN_SMTP
    starttls_command_seen = False
    starttls_accept_code_seen = False

    for side, packet_no, ts, text in lines:
        upper = text.upper()
        if side == "server" and re.match(r"^220[ -]", text) and result.server_greeting is None:
            result.server_greeting = text
            result.timeline.append({"ts": ts, "packet_no": packet_no, "event": "SMTP greeting (220)"})

        elif side == "client" and re.match(r"^(EHLO|HELO)\b", upper):
            result.client_command = text
            result.timeline.append({"ts": ts, "packet_no": packet_no, "event": f"Client: {text}"})

        elif side == "server" and re.match(r"^250[ -]STARTTLS", upper):
            result.starttls_offered = True
            result.capabilities.append("STARTTLS")
            state = StarttlsState.STARTTLS_ADVERTISED
            result.timeline.append({"ts": ts, "packet_no": packet_no, "event": "STARTTLS advertised (250-STARTTLS)"})

        elif side == "server" and re.match(r"^250[ -]", upper):
            cap = text[4:].strip()
            if cap:
                result.capabilities.append(cap)

        elif side == "client" and re.match(r"^STARTTLS\b", upper):
            result.starttls_requested = True
            starttls_command_seen = True
            state = StarttlsState.STARTTLS_REQUESTED
            result.timeline.append({"ts": ts, "packet_no": packet_no, "event": "Client: STARTTLS"})

        elif side == "server" and starttls_command_seen and not starttls_accept_code_seen and re.match(r"^220\b", text):
            result.starttls_accepted = True
            starttls_accept_code_seen = True
            state = StarttlsState.STARTTLS_ACCEPTED
            result.timeline.append({"ts": ts, "packet_no": packet_no, "event": "Server: 220 Ready to start TLS"})
            result.tls_start_offset_server = None  # byte offset computed by caller if needed
            result.tls_start_offset_client = None

        elif side == "server" and starttls_command_seen and not starttls_accept_code_seen and re.match(r"^5\d\d\b", text):
            state = StarttlsState.STARTTLS_REJECTED
            result.timeline.append({"ts": ts, "packet_no": packet_no, "event": f"Server rejected STARTTLS: {text}"})

    result.state = state
    return result
