# Parser Platform Release Note

## Release baseline

This release note describes the local parser-platform baseline after the CD2 and ECG parser foundation work.

Current local baseline:

- Platform validation passes.
- Unit tests pass.
- Source-pack generation succeeds.
- Source-pack manifest includes code, tests, config, and design documentation.
- Local scratch files such as `demo.sh` are excluded from the source pack.
- Generated packet captures, raw payloads, reports, archives, caches, and `.git` internals are excluded from the source pack.

## Current capability

The parser platform now supports:

- Legacy ECG parser behavior.
- Spec-backed CD2 word, parity, idle, framing, and EOM helpers.
- CD2 profile settings.
- CD2 troubleshooting CLI.
- ECG message envelope extraction from raw payloads and pcaps.
- Decoder registry with:
  - `raw12`
  - `beacon-candidate`
- Legacy-vs-envelope comparison.
- Corpus validation.
- Corpus report summarization.
- Golden fixture export and check.
- Synthetic non-sensitive fixture generation.
- End-to-end platform validation.
- Safe source-pack generation for AI or developer handoff.

## Main operator commands

Run local platform validation:

    python3 -m oad_parser.cli validate-platform --run-tests

Generate synthetic non-sensitive fixtures:

    python3 -m oad_parser.cli generate-fixture-samples --output-dir samples/fixtures

Validate a corpus folder:

    python3 -m oad_parser.cli validate-corpus samples/fixtures --output corpus-report.json

Summarize a corpus report:

    python3 -m oad_parser.cli summarize-corpus-report corpus-report.json --show-matches

Compare legacy parser output against ECG envelope output:

    python3 -m oad_parser.cli compare-legacy-envelope samples/fixtures/sample.pcap

Export a golden fixture:

    python3 -m oad_parser.cli export-golden-fixture samples/fixtures/sample.bin --raw-payload --output samples/fixtures/sample.raw-payload.golden.json

Check a golden fixture:

    python3 -m oad_parser.cli check-golden-fixture samples/fixtures/sample.raw-payload.golden.json

Create a source pack:

    python3 -m oad_parser.cli create-source-pack --output dist/source-packs/oad-parser-source-pack.tar.gz

## Verified source-pack behavior

The generated source pack is intended for AI and developer handoff.

It includes:

- `README.md`
- parser source code under `oad_parser/`
- tests under `oad_parser/tests/`
- config examples under `config/`
- design documentation under `docs/design/`
- source-pack manifest: `SOURCE-PACK-MANIFEST.json`

It excludes:

- `demo.sh`
- `.git`
- caches
- generated corpus reports
- generated summaries
- packet captures
- raw payload files
- archive files

## Validation backbone

The current validation strategy is:

1. Synthetic fixture generation creates deterministic, non-sensitive sample inputs.
2. Golden fixture checks detect parser drift.
3. Legacy-vs-envelope comparison verifies that the new ECG envelope path stays compatible with the existing parser.
4. Corpus validation scales that comparison across folders.
5. Corpus report summarization provides a compact operator-facing review.
6. Platform validation ties the workflow together.

## Known limitations

The platform foundation is strong, but final semantic radar interpretation is not complete.

The `beacon-candidate` decoder remains provisional. It is useful for development and exploratory validation, but it should not be treated as authoritative until validated against sanitized captures and authoritative message-format references.

Do not treat synthetic fixture success as proof of operational correctness. Treat it as regression protection and development confidence.

## Recommended next work

Do not add deeper semantic radar decoding until one of the following is available:

- sanitized or approved sample captures
- authoritative message-format references for CD-2, CD-ASR, MAR, RTQC, or site-specific formats

Until then, safe work includes:

- documentation cleanup
- handoff package refinement
- CLI polish
- test readability improvements
- fixture and validation usability improvements

## Handoff guidance

For AI or developer handoff, provide:

- the source pack tarball
- this release note
- the operator handbook
- the current commit hash
- a statement that `beacon-candidate` is provisional
- a statement that no sensitive captures are included

## Sprint 2 release-note alignment

The Sprint 2 live parser foundation is implemented and merged through the release-hardening closeout baseline.

Release-facing highlights:

- `oad_parser live` is implemented.
- Systemd template support exists at `deploy/systemd/ecg-parser@.service`.
- Filebeat/Elastic Agent handoff documentation exists at `docs/ops/filebeat-elastic-agent-handoff.md`.
- Active output is `/nsm/ecg/ecg-current.json`, containing JSON Lines despite the `.json` suffix.
- Audit output is `/nsm/ecg/ecg-audit.jsonl`.
- Status output is `/nsm/ecg/ecg-status.json`.
- Internal engineering source-pack workflows remain separate from future customer runtime/operator package workflows.
