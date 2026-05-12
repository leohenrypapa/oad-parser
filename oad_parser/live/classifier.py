"""Live frame classification for the production ECG service path."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from oad_parser.ingest.ethernet import UdpFrame, parse_ipv4_udp_frame
from oad_parser.live.metrics import LiveMetrics
from oad_parser.live.records import LiveCaptureFrame
from oad_parser.parsers.ecg import looks_like_ecg_payload


OUTCOME_NON_IPV4_OR_NON_UDP = "non_ipv4_or_non_udp"
OUTCOME_NON_ECG_PAYLOAD = "non_ecg_payload"
OUTCOME_ECG_CANDIDATE = "ecg_candidate"


@dataclass(frozen=True)
class LiveFrameClassification:
    """Classifier result for one live capture frame."""

    outcome: str
    capture_frame: LiveCaptureFrame
    udp_frame: Optional[UdpFrame] = None
    ecg_payload: Optional[bytes] = None
    packet_metadata: Dict[str, Any] = None
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        if self.packet_metadata is None:
            object.__setattr__(self, "packet_metadata", {})


def classify_live_frame(
    capture_frame: LiveCaptureFrame,
    metrics: Optional[LiveMetrics] = None,
) -> LiveFrameClassification:
    """Classify a live frame into non-UDP, non-ECG, or ECG-candidate outcome."""

    if metrics is not None:
        metrics.increment("packets_received")

    udp_frame = parse_ipv4_udp_frame(capture_frame.frame_bytes)
    if udp_frame is None:
        if metrics is not None:
            metrics.increment("non_ipv4_or_non_udp")
        return LiveFrameClassification(
            outcome=OUTCOME_NON_IPV4_OR_NON_UDP,
            capture_frame=capture_frame,
            reason="frame could not be classified as Ethernet/IPv4/UDP",
        )

    if metrics is not None:
        metrics.increment("packets_parsed")

    metadata = packet_metadata_from_udp_frame(udp_frame)

    if not looks_like_ecg_payload(udp_frame.payload):
        if metrics is not None:
            metrics.increment("non_ecg")
        return LiveFrameClassification(
            outcome=OUTCOME_NON_ECG_PAYLOAD,
            capture_frame=capture_frame,
            udp_frame=udp_frame,
            packet_metadata=metadata,
            reason="UDP payload does not match ECG envelope structure",
        )

    if metrics is not None:
        metrics.increment("ecg_candidates")

    return LiveFrameClassification(
        outcome=OUTCOME_ECG_CANDIDATE,
        capture_frame=capture_frame,
        udp_frame=udp_frame,
        ecg_payload=udp_frame.payload,
        packet_metadata=metadata,
    )


def packet_metadata_from_udp_frame(udp_frame: UdpFrame) -> Dict[str, Any]:
    """Return packet metadata that can be reused by events and error records."""

    return {
        "source_ip": udp_frame.source_ip,
        "source_port": udp_frame.source_port,
        "destination_ip": udp_frame.destination_ip,
        "destination_port": udp_frame.destination_port,
        "ip_total_length": udp_frame.total_length,
    }
