"""
PCAP validation + integrity hashing.

No TShark dependency here on purpose: hashing/validation must work even in
environments where TShark isn't installed yet. Packet-level parsing (see
tcp_reassembly.py) uses scapy, which is pure Python + libpcap bindings.
"""
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.config import ALLOWED_PCAP_EXTENSIONS, MAX_PCAP_SIZE_BYTES


class PcapValidationError(Exception):
    pass


@dataclass
class PcapValidationResult:
    sha256: str
    size_bytes: int
    packet_count: Optional[int] = None


MAGIC_NUMBERS = {
    b"\xd4\xc3\xb2\xa1": "pcap",  # little-endian classic pcap
    b"\xa1\xb2\xc3\xd4": "pcap",  # big-endian classic pcap
    b"\x0a\x0d\x0d\x0a": "pcapng",
}


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_pcap(path: Path, original_filename: str) -> PcapValidationResult:
    """Never trust the filename or extension alone; check magic bytes too."""
    ext = Path(original_filename).suffix.lower()
    if ext not in ALLOWED_PCAP_EXTENSIONS:
        raise PcapValidationError(f"Unsupported file extension: {ext}")

    size = path.stat().st_size
    if size == 0:
        raise PcapValidationError("EMPTY_PCAP")
    if size > MAX_PCAP_SIZE_BYTES:
        raise PcapValidationError(f"File exceeds max size of {MAX_PCAP_SIZE_BYTES} bytes")

    with open(path, "rb") as f:
        header = f.read(4)
    if header not in MAGIC_NUMBERS:
        raise PcapValidationError("INVALID_PCAP: unrecognized magic bytes")

    digest = sha256_of_file(path)
    return PcapValidationResult(sha256=digest, size_bytes=size)
