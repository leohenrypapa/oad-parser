# Live Capture Notes

## Purpose

Live capture is now available as a thin ingest adapter. Parser core remains pure.

## Command

Safe bounded test:

    sudo python3 -m oad_parser capture --interface eth0 --output /tmp/oad-live.jsonl --detect --max-frames 1000

Continuous capture:

    sudo python3 -m oad_parser capture --interface eth0 --output /data/ecg/events.jsonl --detect

## Privilege requirement

Linux raw sockets normally require root privileges or an equivalent capability.

## Design rule

Live capture must remain an adapter:

    live socket frame -> parser core -> optional detector engine -> JSONL output

Do not put socket handling inside `oad_parser.parsers.ecg`.
## Sprint 2 live capture adapter contract

- The bounded `iter_live_frames` helper remains available for legacy capture and tests, returning raw frame bytes.
- The production live path should use `iter_live_capture_frames` or `iter_live_capture_frames_from_config` so each frame carries interface, UTC capture timestamp, frame length, and sequence_number metadata.
- The adapter applies configured `receive_buffer_bytes` with SO_RCVBUF when provided.
- Unit tests use a mock socket factory. They do not open raw sockets and do not require root privileges.

