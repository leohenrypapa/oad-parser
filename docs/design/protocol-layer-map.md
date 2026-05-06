# Protocol Layer Map

## Observed legacy path

    Ethernet/IP/UDP frame
      -> ECG wrapper/parser logic
      -> surveillance message fields
      -> detector state
      -> JSONL or CSV output
      -> Filebeat/Kibana/Security Onion consumption

## CD2 guide role

The CD2 Programmer's Guide describes CD2 client/ICP protocol details:

- MSB/MSW ordering
- 13-bit CD2 data words
- parity handling
- idle word recognition
- receive framing
- receive frame size
- link configuration
- error status behavior

This platform should use the guide to document and validate protocol assumptions. The first parser implementation should still be extracted from the field-tested ECG script path because that is what the kit currently runs.

## Parser module direction

- `oad_parser.parsers.ecg`: field wrapper and message extraction behavior from legacy `ecg.py`.
- `oad_parser.parsers.cd2`: CD2 word/parity/framing helpers informed by DC 900-1607F.
- `oad_parser.ingest.pcap`: pcap replay adapter.
- `oad_parser.ingest.raw_bytes`: byte fixture adapter.
- `oad_parser.ingest.live_socket`: later live capture adapter.
