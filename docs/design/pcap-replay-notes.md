# PCAP Replay Notes

## Purpose

PCAP replay supports controlled parser development and regression checks against approved local captures.

## Customer-safe command shape

    python3 -m oad_parser inspect-pcap PATH_TO_APPROVED_PCAP
    python3 -m oad_parser extract-ecg-messages PATH_TO_APPROVED_PCAP --jsonl
    python3 -m oad_parser compare-legacy-envelope PATH_TO_APPROVED_PCAP

## Timestamp policy

PCAP replay uses packet timestamps for deterministic and auditable replay output.

Live capture may use runtime timestamps depending on capture path and caller behavior.

## Evidence rule

Replay results from private or local captures are internal validation evidence only unless the captures and resulting reports are sanitized and approved for release. Do not publish local file paths, capture names, observed addresses, ports, or traffic statistics as customer-facing evidence.
