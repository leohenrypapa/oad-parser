# CD2 CLI and profile notes

## New command

The parser now includes a CD2 troubleshooting command:

    python3 -m oad_parser.cli decode-cd2-words 0x03ff 0x0002 0x0004 0x03ff

Expected shape:

    frame_count=1
    frame 0: words=2 start=1 end=2 extended_error_status=0x0000 errors=none data_words=0x001 0x002

## Profile file

Use this example as a starting point:

    config/oad-cd2-profile.example.ini

The `[cd2]` section controls protocol-layer assumptions:

- `add_remove_parity`
- `receive_frame_size_words`
- `error_screening`
- `data_inversion`
- `parity_mode`

## Why this matters

This gives operators and developers a small, testable entry point for the new CD2 layer before it is wired into the full ECG/pcap parser path. It also creates a practical place to validate fielded link assumptions against sanitized captures.

## Decoder discovery

List available decoders:

    python3 -m oad_parser.cli decode-cd2-words --list-decoders

A profile may also set a default decoder:

    [cd2]
    decoder = raw12

The same profile can drive ECG envelope extraction:

    python3 -m oad_parser.cli extract-ecg-messages payload.bin --raw-payload --config config/oad-cd2-profile.example.ini

CLI `--decoder` overrides `[cd2] decoder` from the profile.

Write ECG envelope output to a file:

    python3 -m oad_parser.cli extract-ecg-messages payload.bin --raw-payload --output envelopes.json

For JSONL output:

    python3 -m oad_parser.cli extract-ecg-messages payload.bin --raw-payload --jsonl --output envelopes.jsonl
