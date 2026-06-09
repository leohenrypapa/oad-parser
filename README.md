# OAD Parser Customer Runtime

This repository mirrors the current OAD Parser customer runtime and publishes the installable customer pack as a GitHub Release asset.

## Latest customer pack

Release tag:
customer-pack-20260609T224136Z-862cea33d1c2

Asset:
oad-parser-customer-runtime-20260609T224136Z-862cea33d1c2.tar.gz

SHA256:
69738643129c149e6ab287c833d51cf3ae689c3e55a893ecb0179d8646dcd12b

Source commit:
862cea33d1c2d1a483df912aedd57fa7cc90116d

## Sensor5 compact-output fix markers

Expected runtime markers:

- oad_parser/live/writer.py
  - COMPACT_EVENT_DROP_FIELDS
  - COMPACT_EVENT_RENAME_FIELDS
  - def _compact_live_event_record
  - def _should_emit_live_event

- oad_parser/live/service.py
  - skipped zero-byte compact records do not increment emitted counters

- oad_parser/transformers/legacy_ecg.py
  - per-message fingerprint
  - projected live radar fields

## Acceptance boundary

Publication does not claim target-site acceptance. Confirm Sensor5 live output separately before operational closure.
