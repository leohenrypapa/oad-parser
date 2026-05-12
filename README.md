# OAD Parser

`oad-parser` is a Python ECG/CD2 parser platform for pcap replay, raw ECG payload inspection, CD2 word/framing validation, corpus regression checks, golden fixtures, and clean customer-safe source-pack handoff. Start with `START_HERE.md` for release scope and reading order.

## Current baseline

This baseline is a platform foundation for deeper OAD/CD2 parser work. It includes:

- ECG envelope extraction while preserving legacy `parse_frame` behavior
- CD2 protocol-layer helpers for 13-bit words, idle sync, parity, EOM, frame size, inversion, and profile-driven behavior
- Decoder registry with `raw12` and provisional `beacon-candidate` decoders
- Legacy-vs-envelope comparison
- Corpus validation and corpus report summarization
- Golden fixture export/check
- Synthetic fixture generation
- End-to-end platform validation
- Source-pack generator for developer and AI handoff

The `beacon-candidate` decoder is provisional. Do not treat its fields as authoritative radar semantics without sanitized captures or authoritative message-format references.

## Repository layout

    oad_parser/
      cli.py                 Command-line interface
      config.py              INI config loading
      compare.py             Legacy-vs-envelope comparison
      corpus.py              Corpus validation
      corpus_report.py       Corpus report summary rendering
      fixture_samples.py     Synthetic fixture generation
      golden.py              Golden fixture export/check
      platform_validation.py End-to-end platform health check
      source_pack.py         Source-pack generation
      ingest/                PCAP, Ethernet/IP/UDP, raw bytes, live socket helpers
      parsers/               ECG and CD2 parser helpers
      decoders/              Decoder registry and provisional decoder scaffolds
      detectors/             Stateful detector scaffolding
      tests/                 Unit tests

    config/
      oad-parser.example.ini      Runtime config example
      oad-cd2-profile.example.ini CD2 profile example

    START_HERE.md              Customer-safe release entrypoint
    USER_MANUAL.md             Plain-English guide for operators
    AI_CONTEXT.md              Guardrails for AI-assisted continuation
    CHANGELOG.md               Curated release history

    docs/release/
      RELEASE_CHECKLIST.md
      CUSTOMER_HANDOFF.md
      STANDARDS_ADOPTION_CHECKLIST.md

    docs/adr/
      0001-platform-foundation-scope.md

    docs/design/
      parser-platform-operator-handbook.md
      cd2-parser-roadmap.md
      input-output-contract.md
      protocol-layer-map.md
      TRACEABILITY_MATRIX.md
      additional design and extraction notes

## Important file policy

Do not commit pcaps, raw payloads, generated corpus reports, archives, caches, or local scratch files.

The source-pack generator is intentionally conservative and excludes:

- `.git` internals
- packet captures and raw payloads
- generated corpus reports and summaries
- archives
- Python caches
- virtual environments
- local demo scripts

## Install

Minimum:

    Python 3.9.2 or newer

Recommended customer validation runtime:

    python3.9

Optional developer workflow:

    poetry install

The parser core primarily uses the Python standard library.

## Quick check

Run from the repo root:

    bash scripts/verify.sh

For a smaller manual check:

    python3 -m unittest discover -s oad_parser/tests -p "test_*.py"
    python3 -m oad_parser --help
    python3 -m oad_parser validate-platform

Expected:

    OK

Generated verification evidence is written under `reports/` and is not committed by default.

## CD2 profile example

    python3 -m oad_parser decode-cd2-words --config config/oad-cd2-profile.example.ini 0x0fff 0x0001 0x0fff

## ECG envelope extraction

From raw ECG payload bytes:

    python3 -m oad_parser extract-ecg-messages sample.bin --raw-payload --jsonl

From pcap:

    python3 -m oad_parser extract-ecg-messages sample.pcap --jsonl

## Legacy compatibility check

    python3 -m oad_parser compare-legacy-envelope sample.bin --raw-payload

This checks the legacy parser projection separately from provisional semantic decoder output.

## Corpus validation

    python3 -m oad_parser validate-corpus samples/sanitized --output /tmp/corpus-report.json
    python3 -m oad_parser summarize-corpus-report /tmp/corpus-report.json

Use sanitized local corpora only. Synthetic fixture success does not prove operational correctness.

## Golden fixtures

    python3 -m oad_parser export-golden-fixture sample.bin --raw-payload --output /tmp/fixture.json
    python3 -m oad_parser check-golden-fixture /tmp/fixture.json

Use this to detect parser drift across code changes.

## Synthetic platform validation

    python3 -m oad_parser validate-platform

This generates synthetic fixtures in a temporary directory, checks golden fixture behavior, validates corpus behavior, and prints a compact health report.

## Source-pack handoff

Create a clean source pack from the current repo root:

    python3 -m oad_parser create-source-pack --output /tmp/oad-parser-source-pack.tar.gz

The source-pack generator defaults to tracked files only. Use `--include-untracked` only for internal experiments, not customer release packs.

Recommended handoff reading order:

1. `START_HERE.md`
2. `USER_MANUAL.md`
3. `README.md`
4. `docs/release/CUSTOMER_HANDOFF.md`
5. `docs/release/RELEASE_CHECKLIST.md`
6. `docs/design/TRACEABILITY_MATRIX.md`
7. `docs/adr/0001-platform-foundation-scope.md`
8. `AI_CONTEXT.md`
9. `SOURCE-PACK-MANIFEST.json` inside the generated source pack

## Release helper scripts

Release helper scripts are intended for a Git checkout of the release repository. Extracted source packs can run unit tests and `python3 -m oad_parser validate-platform`; repo release gates need `.git` metadata.

The `scripts/` directory contains operator convenience wrappers around the current CLI:

- `scripts/make_source_pack.sh` creates and validates a clean source pack.
- `scripts/validate_sanitized_release.sh` runs sanitized release checks without requiring private pcaps.
- `scripts/validate_release_readiness.sh` runs the full release-readiness gate and accepts an optional local pcap path.
- `scripts/validate_local_pcaps.sh` validates one or more local sanitized/private pcaps.
- `scripts/inspect_pcap.sh` provides optional packet-inspection support when `tshark` or `capinfos` are installed.

## Release posture

This is a good stopping point for platform handoff if tests pass and the source pack excludes unsafe artifacts. It is not yet a claim of authoritative radar message semantics.

Python 3.9.2 or newer is supported for customer runtime validation.

## Python 3.9.2 customer handoff notes

- Target runtime validation must be run with Python 3.9.2 before customer handoff.
- Recommended validation commands:
  - python3.9 -m unittest discover -s oad_parser/tests -p "test_*.py"
  - python3.9 -m oad_parser --help
  - python3.9 -m oad_parser validate-platform
  - python3.9 -m oad_parser create-source-pack --output /tmp/oad-parser-source-pack.tar.gz
- The `capture` command requires bounded capture with `--max-frames` or `[capture] max_frames` in config. Continuous capture is not enabled for JSONL handoff output.
- `validate-corpus` returns nonzero when parser errors, mismatches, or zero-comparison files are present.
- A zero-comparison file means the file was scanned but did not produce parser comparisons. Treat this as a validation failure until the input format and parser selection are confirmed.
- Source-pack generation rejects included symlinks and excludes local/private capture artifacts by policy. In extracted source packs, tracked-only mode is constrained by SOURCE-PACK-MANIFEST.json; use --include-untracked only for internal local snapshots.
## Sprint 2 live parser systemd template

The live parser systemd template is provided at `deploy/systemd/ecg-parser@.service` with operator guidance in `docs/ops/systemd-live-parser.md`.
The template runs `python3.9 -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface %i` as root for interface-specific instances such as `ecg-parser@eno1.service`.

