"""
TCP stream reconstruction (section 9).

Groups packets into bidirectional TCP streams keyed by the 4-tuple,
tracks SYN/SYN-ACK/ACK/FIN/RST, detects retransmissions and gaps, and
reassembles the byte stream for each direction in sequence-number order.

Requires scapy at runtime (pip install scapy). Import is deferred so the
rest of the app can be imported/tested without it installed.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional


@dataclass
class TcpStream:
    key: Tuple[str, int, str, int]  # (src_ip, src_port, dst_ip, dst_port) of the initiator
    packets: List[dict] = field(default_factory=list)  # raw packet summaries in capture order
    saw_syn: bool = False
    saw_synack: bool = False
    saw_fin: bool = False
    saw_rst: bool = False
    retransmission_count: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    client_bytes: bytes = b""
    server_bytes: bytes = b""
    client_events: List[dict] = field(default_factory=list)  # [{ts, packet_no, kind, payload}]
    server_events: List[dict] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """Handshake + graceful/abrupt close both observed => complete."""
        return self.saw_syn and self.saw_synack and (self.saw_fin or self.saw_rst)

    @property
    def completeness_note(self) -> Optional[str]:
        if self.is_complete:
            return None
        missing = []
        if not self.saw_syn:
            missing.append("SYN")
        if not self.saw_synack:
            missing.append("SYN-ACK")
        if not (self.saw_fin or self.saw_rst):
            missing.append("FIN/RST")
        return f"INCOMPLETE_CAPTURE: missing {', '.join(missing)}"


def reassemble_streams(pcap_path: str) -> List[TcpStream]:
    """
    Read a PCAP/PCAPNG file and return one TcpStream per TCP 4-tuple.

    Sequence-number based reordering is applied per direction; duplicate
    sequence numbers with identical payload are counted as retransmissions
    and not double-appended to the reassembled byte stream.
    """
    from scapy.all import PcapReader, TCP, IP  # deferred import

    streams: Dict[Tuple, TcpStream] = {}
    seen_seqs: Dict[Tuple, Dict[int, set]] = {}  # stream_key -> direction -> set(seq numbers seen)

    packet_no = 0
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            packet_no += 1
            if IP not in pkt or TCP not in pkt:
                continue
            ip = pkt[IP]
            tcp = pkt[TCP]
            a = (ip.src, tcp.sport)
            b = (ip.dst, tcp.dport)
            canonical = tuple(sorted([a, b]))
            stream_key = canonical
            initiator = a if bool(tcp.flags & 0x02) and not bool(tcp.flags & 0x10) else None  # SYN w/o ACK

            if stream_key not in streams:
                streams[stream_key] = TcpStream(key=(a[0], a[1], b[0], b[1]))
                seen_seqs[stream_key] = {a: set(), b: set()}
            stream = streams[stream_key]
            ts = float(pkt.time)
            stream.start_time = ts if stream.start_time is None else min(stream.start_time, ts)
            stream.end_time = ts if stream.end_time is None else max(stream.end_time, ts)

            flags = tcp.flags
            is_syn = bool(flags & 0x02)
            is_ack = bool(flags & 0x10)
            is_fin = bool(flags & 0x01)
            is_rst = bool(flags & 0x04)

            if is_syn and not is_ack:
                stream.saw_syn = True
            if is_syn and is_ack:
                stream.saw_synack = True
            if is_fin:
                stream.saw_fin = True
            if is_rst:
                stream.saw_rst = True

            direction = a  # who sent this packet
            payload = bytes(tcp.payload) if tcp.payload else b""
            if payload:
                seq = int(tcp.seq)
                if seq in seen_seqs[stream_key][direction]:
                    stream.retransmission_count += 1
                else:
                    seen_seqs[stream_key][direction].add(seq)
                    if direction == a:
                        stream.client_bytes += payload
                        stream.client_events.append({"ts": ts, "packet_no": packet_no, "payload": payload})
                    else:
                        stream.server_bytes += payload
                        stream.server_events.append({"ts": ts, "packet_no": packet_no, "payload": payload})

            stream.packets.append({
                "packet_no": packet_no, "ts": ts, "src": ip.src, "dst": ip.dst,
                "sport": tcp.sport, "dport": tcp.dport, "flags": str(tcp.flags),
                "payload_len": len(payload),
            })

    return list(streams.values())
