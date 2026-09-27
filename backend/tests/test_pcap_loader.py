import pytest
from pathlib import Path

from app.parsing.pcap_loader import validate_pcap, PcapValidationError


def test_valid_pcap_magic(tmp_path):
    p = tmp_path / "sample.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    result = validate_pcap(p, "sample.pcap")
    assert len(result.sha256) == 64


def test_valid_pcapng_magic(tmp_path):
    p = tmp_path / "sample.pcapng"
    p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)
    result = validate_pcap(p, "sample.pcapng")
    assert len(result.sha256) == 64


def test_empty_pcap_rejected(tmp_path):
    p = tmp_path / "empty.pcap"
    p.write_bytes(b"")
    with pytest.raises(PcapValidationError, match="EMPTY_PCAP"):
        validate_pcap(p, "empty.pcap")


def test_corrupted_pcap_rejected(tmp_path):
    p = tmp_path / "bad.pcap"
    p.write_bytes(b"NOTAPCAP" + b"\x00" * 20)
    with pytest.raises(PcapValidationError, match="INVALID_PCAP"):
        validate_pcap(p, "bad.pcap")


def test_wrong_extension_rejected(tmp_path):
    p = tmp_path / "sample.txt"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    with pytest.raises(PcapValidationError, match="extension"):
        validate_pcap(p, "sample.txt")


def test_sha256_is_deterministic(tmp_path):
    p = tmp_path / "sample.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"hello world" * 10)
    r1 = validate_pcap(p, "sample.pcap")
    r2 = validate_pcap(p, "sample.pcap")
    assert r1.sha256 == r2.sha256
