# CD2 decoder registry notes

## Purpose

The CD2 framing layer should not hard-code radar message semantics. The decoder registry provides a controlled extension point for adding semantic decoders after the team validates message formats against sanitized captures and authoritative references.

## Current decoders

### raw12

Exposes framed 12-bit data words and frame diagnostics.

Example:

    python3 -m oad_parser.cli decode-cd2-words --decoder raw12 0x03ff 0x0002 0x0004 0x03ff

### beacon-candidate

Applies the field positions already used by the legacy parser to framed 12-bit CD2 data words.

This decoder is intentionally marked provisional. It is useful for development, but it should not be treated as authoritative until validated against sanitized captures and message-format references.

Fields currently extracted when enough words are present:

- `range_nm`
- `acp`
- `azimuth_degrees`
- `mode_3_code`
- `altitude_feet`

## Next decoder candidates

- search-candidate
- rtqc-candidate
- site-specific compatibility decoder

Each semantic decoder should be added with tests and at least one sanitized or synthetic golden vector.

## ECG envelope bridge

`extract_ecg_messages` exposes ECG message metadata and payload words without applying plot semantics. This creates a safe bridge from pcap/live ECG traffic into future CD2 and radar-message decoders while preserving the current legacy parser behavior.

## ECG envelope CLI

Use the envelope extractor to inspect ECG-wrapped message metadata before applying semantic decoders:

    python3 -m oad_parser.cli extract-ecg-messages sample.pcap

For a raw ECG payload file:

    python3 -m oad_parser.cli extract-ecg-messages payload.bin --raw-payload

Attach provisional decoder output to each ECG envelope:

    python3 -m oad_parser.cli extract-ecg-messages payload.bin --raw-payload --decoder beacon-candidate

For pcap input with attached decoder output:

    python3 -m oad_parser.cli extract-ecg-messages sample.pcap --decoder beacon-candidate

## Legacy comparison

Use the comparison command before adding more semantic decoders:

    python3 -m oad_parser.cli compare-legacy-envelope sample.pcap

For raw ECG payloads:

    python3 -m oad_parser.cli compare-legacy-envelope payload.bin --raw-payload

The command compares legacy `parse_frame` output against an ECG envelope legacy projection and reports match/mismatch counts. This is separate from `beacon-candidate`, which remains provisional.

## Corpus validation

Use corpus validation before adding more semantic decoders:

    python3 -m oad_parser.cli validate-corpus samples/sanitized --output corpus-report.json

Supported inputs currently include `.pcap`, `.cap`, `.bin`, `.payload`, and `.ecg` files. The command reports files scanned, comparison count, match count, mismatch count, and file-level errors.

Summarize a saved corpus report:

    python3 -m oad_parser.cli summarize-corpus-report corpus-report.json

Include matched files:

    python3 -m oad_parser.cli summarize-corpus-report corpus-report.json --show-matches

## Golden fixtures

Export a stable regression fixture from a raw ECG payload:

    python3 -m oad_parser.cli export-golden-fixture sample.bin --raw-payload --output fixtures/sample.golden.json

Check for parser drift later:

    python3 -m oad_parser.cli check-golden-fixture fixtures/sample.golden.json

Use `--input` to check the fixture against a different local sample path.

## Synthetic fixture samples

Generate non-sensitive deterministic samples for developer handoff and regression checks:

    python3 -m oad_parser.cli generate-fixture-samples --output-dir samples/fixtures

Generated files include a raw ECG payload, pcap, golden fixtures, corpus report, and compact corpus summary.

## Platform validation

Run a local end-to-end health check:

    python3 -m oad_parser.cli validate-platform

Keep generated artifacts for inspection:

    python3 -m oad_parser.cli validate-platform --output-dir samples/fixtures/platform-check

Include unittest discovery:

    python3 -m oad_parser.cli validate-platform --run-tests
