# Parser Platform Operator Handbook

## Purpose

This handbook gives operators and developers a safe way to use the parser platform without needing real or sanitized operational captures.

The current platform supports:

- Legacy ECG parser behavior
- Spec-backed CD2 word/framing helpers
- ECG message envelope extraction
- Provisional decoder output
- Legacy-vs-envelope comparison
- Corpus validation
- Corpus report summarization
- Golden fixture export and check
- Synthetic fixture generation
- End-to-end platform validation

## Safety and scope

Do not commit real operational captures, sensitive packet captures, credentials, tokens, or environment-specific data.

Use synthetic fixtures for development and handoff. Use sanitized captures only when approved.

The `beacon-candidate` decoder is provisional. It is useful for development and exploratory validation, but it should not be treated as authoritative radar truth until validated against sanitized captures and authoritative message-format references.

## Current architecture

The parser platform separates concerns:

    ingest -> ECG envelope -> CD2/frame helpers -> decoder registry -> validation/reporting

Key modules:

- `oad_parser.parsers.ecg` - legacy ECG parser plus ECG envelope extraction
- `oad_parser.parsers.cd2` - CD2 word/framing/parity helpers
- `oad_parser.decoders.registry` - decoder extension point
- `oad_parser.decoders.cd2_radar` - raw and provisional decoder scaffolds
- `oad_parser.compare` - legacy-vs-envelope compatibility comparison
- `oad_parser.corpus` - corpus validation
- `oad_parser.corpus_report` - compact report summaries
- `oad_parser.golden` - golden fixture export/check
- `oad_parser.fixture_samples` - deterministic synthetic sample generation
- `oad_parser.platform_validation` - local end-to-end health check

## Recommended local validation command

Run this before and after parser changes:

    python3 -m oad_parser.cli validate-platform --run-tests

Expected result:

- `Passed: true`
- Golden checks match
- Corpus validation has zero mismatches
- Unit tests pass

To keep generated validation artifacts:

    python3 -m oad_parser.cli validate-platform --output-dir samples/fixtures/platform-check

To emit JSON:

    python3 -m oad_parser.cli validate-platform --json

## Synthetic fixture workflow

Generate non-sensitive fixtures:

    python3 -m oad_parser.cli generate-fixture-samples --output-dir samples/fixtures

Generated files:

- `sample.bin` - raw synthetic ECG payload
- `sample.pcap` - synthetic Ethernet/IPv4/UDP/ECG pcap
- `sample.raw-payload.golden.json` - golden fixture for raw payload
- `sample.pcap.golden.json` - golden fixture for pcap
- `corpus-report.json` - corpus validation report
- `corpus-summary.txt` - compact corpus summary
- `README.md` - generated fixture notes

## ECG envelope extraction

Extract ECG message envelopes from a raw ECG payload:

    python3 -m oad_parser.cli extract-ecg-messages sample.bin --raw-payload

Write JSON output:

    python3 -m oad_parser.cli extract-ecg-messages sample.bin --raw-payload --output envelopes.json

Write JSONL output:

    python3 -m oad_parser.cli extract-ecg-messages sample.bin --raw-payload --jsonl --output envelopes.jsonl

Extract from pcap:

    python3 -m oad_parser.cli extract-ecg-messages sample.pcap

Attach provisional decoder output:

    python3 -m oad_parser.cli extract-ecg-messages sample.pcap --decoder beacon-candidate

Use profile-selected decoder behavior:

    python3 -m oad_parser.cli extract-ecg-messages sample.bin --raw-payload --config config/oad-cd2-profile.example.ini

## CD2 troubleshooting

Decode hand-entered CD2 13-bit words:

    python3 -m oad_parser.cli decode-cd2-words 0x03ff 0x0002 0x0004 0x03ff

List available decoders:

    python3 -m oad_parser.cli decode-cd2-words --list-decoders

Use raw 12-bit decoder:

    python3 -m oad_parser.cli decode-cd2-words --decoder raw12 0x03ff 0x0002 0x0004 0x03ff

Use provisional beacon decoder:

    python3 -m oad_parser.cli decode-cd2-words --decoder beacon-candidate 0x03ff 0x0000 0x00a0 0x0800 0x0000 0x0538 0x0000 0x003c 0x03ff

## Legacy-vs-envelope comparison

Use this before changing parser semantics:

    python3 -m oad_parser.cli compare-legacy-envelope sample.pcap

For raw ECG payloads:

    python3 -m oad_parser.cli compare-legacy-envelope sample.bin --raw-payload

Write JSONL output:

    python3 -m oad_parser.cli compare-legacy-envelope sample.bin --raw-payload --jsonl --output comparison.jsonl

This command compares legacy `parse_frame` output against an ECG envelope legacy projection. It is a compatibility regression check and is separate from `beacon-candidate`.

## Corpus validation

Validate a folder of supported samples:

    python3 -m oad_parser.cli validate-corpus samples/fixtures --output corpus-report.json

Supported file types:

- `.pcap`
- `.cap`
- `.bin`
- `.payload`
- `.ecg`

Summarize a saved report:

    python3 -m oad_parser.cli summarize-corpus-report corpus-report.json

Include matched files:

    python3 -m oad_parser.cli summarize-corpus-report corpus-report.json --show-matches

Write summary to a text file:

    python3 -m oad_parser.cli summarize-corpus-report corpus-report.json --output corpus-summary.txt

## Golden fixtures

Export a golden fixture from a raw ECG payload:

    python3 -m oad_parser.cli export-golden-fixture sample.bin --raw-payload --output sample.raw-payload.golden.json

Export a golden fixture from pcap:

    python3 -m oad_parser.cli export-golden-fixture sample.pcap --output sample.pcap.golden.json

Check a golden fixture:

    python3 -m oad_parser.cli check-golden-fixture sample.raw-payload.golden.json

Check a fixture against a different local sample path:

    python3 -m oad_parser.cli check-golden-fixture sample.raw-payload.golden.json --input other-sample.bin

## Safe development workflow

Use this sequence for parser changes:

1. Run the platform check.

       python3 -m oad_parser.cli validate-platform --run-tests

2. Generate synthetic fixtures if needed.

       python3 -m oad_parser.cli generate-fixture-samples --output-dir samples/fixtures

3. Make the parser change.

4. Run unit tests.

       python3 -m unittest discover -s oad_parser/tests -p "test_*.py"

5. Run legacy-vs-envelope comparison on available samples.

       python3 -m oad_parser.cli compare-legacy-envelope samples/fixtures/sample.pcap

6. Run corpus validation.

       python3 -m oad_parser.cli validate-corpus samples/fixtures --output corpus-report.json

7. Summarize the corpus report.

       python3 -m oad_parser.cli summarize-corpus-report corpus-report.json --show-matches

8. Check golden fixtures.

       python3 -m oad_parser.cli check-golden-fixture samples/fixtures/sample.raw-payload.golden.json
       python3 -m oad_parser.cli check-golden-fixture samples/fixtures/sample.pcap.golden.json

9. Commit only intended files. Do not add scratch files such as `demo.sh`.

## Interpreting results

Good result:

- Platform validation says `Passed: true`
- Unit tests pass
- Golden fixture checks return `"match": true`
- Corpus validation has `files_with_errors: 0`
- Corpus validation has `mismatch_count: 0`

Investigate result:

- Any parser exception
- Any corpus file error
- Any mismatch in legacy-vs-envelope comparison
- Golden fixture `difference_count` greater than 0
- A semantic decoder result that disagrees with legacy projection

## Decoder policy

Current decoders:

- `raw12` - safe raw 12-bit word exposure
- `beacon-candidate` - provisional beacon-style field extraction

Before adding more semantic decoders:

1. Keep legacy-vs-envelope comparison green.
2. Add synthetic or sanitized golden fixtures.
3. Add corpus validation coverage.
4. Document the evidence for every field interpretation.
5. Keep provisional decoders labeled provisional until validated.

Potential future decoders:

- `search-candidate`
- `rtqc-candidate`
- site-specific compatibility decoders

## Current limitation

The platform foundation is strong, but final semantic radar interpretation still requires sanitized captures or authoritative message-format references.

Do not treat synthetic fixture success as proof of operational correctness. Treat it as regression protection and development confidence.

## Source-pack handoff

Create a safe source-pack archive for AI or developer handoff:

    python3 -m oad_parser.cli create-source-pack --output dist/source-packs/oad-parser-source-pack.tar.gz

Use tracked files only:

    python3 -m oad_parser.cli create-source-pack --tracked-only --output dist/source-packs/oad-parser-source-pack.tar.gz

The source pack includes code, tests, config, and design docs. It excludes local scratch files, `.git`, caches, generated reports, packet captures, raw payloads, and archives.

## Sprint 2 operator alignment

Operators should use the implemented `oad_parser live` path for the Sprint 2 live parser baseline.

Target deployment references:

- Config: `/etc/oad-parser/ecg_conf.ini`
- Active output: `/nsm/ecg/ecg-current.json` JSON Lines output
- Audit output: `/nsm/ecg/ecg-audit.jsonl`
- Status output: `/nsm/ecg/ecg-status.json`
- Systemd template: `deploy/systemd/ecg-parser@.service`
- Instance pattern: `ecg-parser@<interface>.service`

`eno1` through `eno5` may be documented as expected interface names, but validation passes only for connected ECG interfaces. Filebeat/Elastic Agent handoff is bounded to parser-owned output files and requires SIEM owner confirmation for final site config.
