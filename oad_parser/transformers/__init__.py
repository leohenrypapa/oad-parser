"""Record transformers for parser output compatibility."""

from oad_parser.transformers.legacy_ecg import (
    legacy_error_fields,
    legacy_fields_for_envelope,
    transform_envelope_to_legacy_record,
    transform_parse_error_to_legacy_record,
    transform_parse_result_to_legacy_records,
)

__all__ = [
    "legacy_error_fields",
    "legacy_fields_for_envelope",
    "transform_envelope_to_legacy_record",
    "transform_parse_error_to_legacy_record",
    "transform_parse_result_to_legacy_records",
]
