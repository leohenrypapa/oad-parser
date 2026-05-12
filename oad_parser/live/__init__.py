"""Production live ECG parser support modules.

The live package contains streaming-service support code that is kept separate
from bounded pcap replay and bounded live capture behavior.
"""

from oad_parser.live.classifier import (
    OUTCOME_ECG_CANDIDATE,
    OUTCOME_NON_ECG_PAYLOAD,
    OUTCOME_NON_IPV4_OR_NON_UDP,
    LiveFrameClassification,
    classify_live_frame,
    packet_metadata_from_udp_frame,
)
from oad_parser.live.metrics import LiveMetrics
from oad_parser.live.records import (
    EcgAuditRecord,
    EcgOutputRecord,
    EcgParseErrorRecord,
    EcgStatusSnapshot,
    LiveCaptureFrame,
    StoragePolicy,
    format_utc_timestamp,
    sha256_hex,
)

__all__ = [
    "packet_metadata_from_udp_frame",
    "classify_live_frame",
    "LiveFrameClassification",
    "OUTCOME_NON_IPV4_OR_NON_UDP",
    "OUTCOME_NON_ECG_PAYLOAD",
    "OUTCOME_ECG_CANDIDATE",
    "EcgAuditRecord",
    "EcgOutputRecord",
    "EcgParseErrorRecord",
    "EcgStatusSnapshot",
    "LiveCaptureFrame",
    "LiveMetrics",
    "StoragePolicy",
    "format_utc_timestamp",
    "sha256_hex",
]
