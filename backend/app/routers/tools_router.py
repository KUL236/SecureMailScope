"""
Backs the Tools page's "Packet export" card. SHA-256 hashing and
certificate lookup for that page reuse existing endpoints/client-side
crypto and don't need routes here.
"""
import uuid
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app import models
from app.auth import get_current_user

router = APIRouter(prefix="/api", tags=["tools"])


@router.get("/investigations/{investigation_id}/pcap/download")
def download_original_pcap(investigation_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    inv = db.query(models.Investigation).get(investigation_id)
    if not inv or not inv.pcap:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No PCAP stored for this investigation")
    path = Path(inv.pcap.stored_path)
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Stored PCAP file is missing on disk")
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=inv.pcap.filename)


@router.get("/findings/{finding_id}/packet-export")
def export_finding_packets(finding_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Export just the packets belonging to this finding's session, filtered
    from the original capture by 5-tuple (either direction). Falls back to
    the full original capture when the finding has no linked session, and
    returns 501 if scapy isn't installed in this environment (see
    /api/system/dependencies)."""
    finding = db.query(models.Finding).get(finding_id)
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")

    inv = db.query(models.Investigation).get(finding.investigation_id)
    if not inv or not inv.pcap:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No PCAP stored for this investigation")
    src_path = Path(inv.pcap.stored_path)
    if not src_path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Stored PCAP file is missing on disk")

    session = None
    if finding.network_session_id:
        session = db.query(models.NetworkSession).get(finding.network_session_id)

    if not session:
        # No linked session to filter by -- hand back the full capture
        # rather than guessing at a filter.
        return FileResponse(
            src_path, media_type="application/vnd.tcpdump.pcap",
            filename=f"finding-{finding_id}-full-capture{src_path.suffix}",
        )

    try:
        from scapy.all import PcapReader, PcapWriter, TCP, IP  # deferred import, see tcp_reassembly.py
    except ImportError:
        raise HTTPException(
            status.HTTP_501_NOT_IMPLEMENTED,
            "scapy is not installed in this environment, so packets can't be filtered. "
            "Check /api/system/dependencies.",
        )

    tuple_a = (session.src_ip, session.src_port, session.dst_ip, session.dst_port)
    tuple_b = (session.dst_ip, session.dst_port, session.src_ip, session.src_port)

    tmp_path = Path(tempfile.gettempdir()) / f"finding-{finding_id}-{uuid.uuid4().hex[:8]}.pcap"
    matched = 0
    try:
        with PcapReader(str(src_path)) as reader, PcapWriter(str(tmp_path), append=False, sync=True) as writer:
            for pkt in reader:
                if IP in pkt and TCP in pkt:
                    ip_layer = pkt[IP]
                    tcp_layer = pkt[TCP]
                    this_tuple = (ip_layer.src, tcp_layer.sport, ip_layer.dst, tcp_layer.dport)
                    if this_tuple == tuple_a or this_tuple == tuple_b:
                        writer.write(pkt)
                        matched += 1
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    if matched == 0:
        tmp_path.unlink(missing_ok=True)
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "No packets in the original capture matched this session's endpoints",
        )

    return FileResponse(
        tmp_path, media_type="application/vnd.tcpdump.pcap",
        filename=f"finding-{finding_id}-session-packets.pcap",
    )
