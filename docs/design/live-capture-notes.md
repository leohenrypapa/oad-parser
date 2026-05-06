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
