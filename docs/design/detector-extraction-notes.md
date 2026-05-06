# Detector Extraction Notes

## Purpose

Detector state is separated from parser core.

The parser extracts normalized records and envelope metadata. Detector logic processes records in order and applies stateful rules.

## Current detector rule categories

- RTQC message detection scaffolding
- duplicate fingerprint detection
- unknown site after discovery window
- sequence delta
- router timestamp delta
- radar timestamp delta
- range limit
- azimuth jump

## CLI integration

Detection is optional for approved local replay workflows:

    python3 -m oad_parser extract-ecg-messages PATH_TO_APPROVED_INPUT --decoder raw12

Keep local capture names, paths, and generated reports out of customer-facing release material unless sanitized and approved.

## Design rule

Detector state must remain outside parser core.

Parser core:

    bytes -> parsed records and envelopes

Detector engine:

    parsed record stream -> parsed record stream with alert fields

Output adapter:

    parsed record stream -> JSONL
