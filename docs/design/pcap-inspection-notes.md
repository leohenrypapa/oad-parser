# PCAP Inspection Notes

## Purpose

`python3 -m oad_parser inspect-pcap` provides a standard-library-only inspection path for approved local pcaps when external packet tools are unavailable.

## Customer-safe command shape

    python3 -m oad_parser inspect-pcap PATH_TO_APPROVED_PCAP

## Current inspection fields

- total packets
- Ethernet/IPv4/UDP packets
- candidate ECG payload count
- top UDP source/destination pair counts
- top UDP payload lengths
- first candidate ECG packet numbers

## Handling rule

Use this only with approved sanitized or private local captures. Do not commit captures or generated inspection reports. Do not include local paths, capture names, observed addresses, or traffic-shape details in customer handoff material unless explicitly sanitized and approved.
