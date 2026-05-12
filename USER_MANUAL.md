# OAD Parser User Manual

## Who this manual is for

This manual is for an operator who needs to run the OAD parser release, check that it works, and understand the output at a basic level.

You do not need to modify Python code to use this release.

## What this tool does

The OAD parser platform helps inspect and process approved OAD/ECG/CD2 data files.

It can:

- inspect a pcap file
- extract ECG message envelopes
- decode CD2 words for troubleshooting
- compare current parser output against legacy-style output
- validate a folder of approved files
- generate synthetic sample files for training and regression checks
- run a built-in platform health check

## What this tool does not prove

This release does not prove operational radar semantic correctness.

The `beacon-candidate` decoder is provisional. Treat it as a development aid, not as authoritative radar truth.

Synthetic samples, golden fixtures, corpus checks, and platform validation prove regression or self-consistency only. They do not prove that real-world radar message fields are semantically correct.

## Before you start

Supported runtime:

    Python 3.9.2 or newer

Confirm you are in the repository folder:

    cd ~/OAD/oad-parser

Run the extraction-safe quickstart check:

    ./scripts/quickstart_check.sh

For a deeper check that also runs unit tests:

    ./scripts/quickstart_check.sh --with-tests

Confirm Python can run the tool. In the customer Python 3.9.2 environment, prefer `python3.9`:

    python3.9 -m oad_parser --help

Run the basic health check:

    python3.9 -m oad_parser validate-platform

Expected result:

    Parser platform validation
    Passed: true

If `Passed: true` appears, the local tool installation is working. If a command fails, see `docs/TROUBLESHOOTING.md`.

## Basic command examples

### Inspect an approved pcap

Use this only with approved local or sanitized pcap files.

    python3 -m oad_parser inspect-pcap PATH_TO_APPROVED_FILE.pcap

This prints a summary of packets and candidate ECG payloads.

Do not share the output externally unless it has been sanitized. Inspection output can include file paths, traffic counts, addresses, or ports.

### Extract ECG messages from a pcap

    python3 -m oad_parser extract-ecg-messages PATH_TO_APPROVED_FILE.pcap --jsonl

This prints JSON Lines output to the terminal.

To write output to a file:

    python3 -m oad_parser extract-ecg-messages PATH_TO_APPROVED_FILE.pcap --jsonl --output output.jsonl

Do not commit generated `.jsonl` files unless a maintainer explicitly says they are sanitized and approved.

### Decode CD2 words

    python3 -m oad_parser decode-cd2-words 0x0fff 0x0001 0x0fff

This is mainly for troubleshooting word framing and decoder behavior.

### Run a folder validation

    python3 -m oad_parser validate-corpus PATH_TO_APPROVED_FOLDER --output corpus-report.json

This checks parser behavior across a folder of approved files.

Do not treat this as proof of operational semantic correctness. It is a compatibility and regression check.

### Summarize a corpus report

    python3 -m oad_parser summarize-corpus-report corpus-report.json

This prints a short human-readable summary from a corpus report.

### Generate synthetic samples

    python3 -m oad_parser generate-fixture-samples --output-dir /tmp/oad-parser-samples

This creates non-sensitive synthetic sample files. Synthetic samples are useful for training and regression checks.

## How to read common outputs

### `Passed: true`

The health check completed successfully.

### `Raw golden match: true`

The current parser output matched the expected synthetic raw-payload fixture.

### `Pcap golden match: true`

The current parser output matched the expected synthetic pcap fixture.

### `Corpus matches`

The parser output matched the comparison expectation for files in the test corpus.

### `Corpus mismatches`

A mismatch means parser behavior changed or the comparison expectation was not met. A developer or maintainer should review it.

## Production live parser notes

Sprint 2 live parser work keeps the existing bounded `capture` command separate from the planned production `live` command. The production command will use the active runtime output path `/nsm/ecg/ecg-current.json`. That file keeps the `.json` suffix for legacy/runtime familiarity, but its content is JSON Lines: one JSON object per line.

Closed rotated output files use UTC timestamped `.jsonl` names such as `/nsm/ecg/ecg-current-YYYYmmddTHHMMSSZ.jsonl`. If a rotated filename already exists, the writer appends a numeric suffix such as `-0001`.

Storage protection prunes only closed rotated output files. It does not delete the active output file, active audit file, active status file, or unrelated operator files. At or above 75 percent disk usage, the service should prune closed files and block output if still above threshold. At or above 95 percent, the service should emit best-effort evidence and exit nonzero for systemd failure handling.

Valid ECG event records may include `parse_warnings` when the parser can emit the event but also detects a non-fatal parse issue such as an unmapped ECG message code. Parse warnings include `code`, `message`, and `parser_stage`. Parse warnings do not convert the event into an `ecg_parse_error`. Malformed ECG-looking payloads still emit `ecg_parse_error` records.

MVP Filebeat/Elastic Agent handoff collects append-style files only: `/nsm/ecg/ecg-current.json` and `/nsm/ecg/ecg-audit.jsonl`. `/nsm/ecg/ecg-status.json` is local-only for operators unless a later requirement adds central status ingestion.

`/nsm/ecg/ecg-audit.jsonl` is JSON Lines audit output. `/nsm/ecg/ecg-status.json` is replaced as a single JSON object and is intended for local operator checks, not MVP central ingestion.

Filebeat and Elastic Agent handoff guidance is available at `docs/ops/filebeat-elastic-agent-handoff.md`. MVP central collection uses append-style files only: `/nsm/ecg/ecg-current.json` and `/nsm/ecg/ecg-audit.jsonl`.

Live command smoke example:

    python3.9 -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface eno1 --max-frames 10

The `--max-frames` option is for test and smoke runs only. Do not use it in the production systemd service.

Systemd template documentation is available at `docs/ops/systemd-live-parser.md`. The template service is `deploy/systemd/ecg-parser@.service` and should be installed as `/etc/systemd/system/ecg-parser@.service`.

## What files are safe to share

Usually safe to share:

- source code in this release source pack
- `START_HERE.md`
- `USER_MANUAL.md`
- `README.md`
- `docs/release/CUSTOMER_HANDOFF.md`
- `docs/release/RELEASE_CHECKLIST.md`
- `docs/design/TRACEABILITY_MATRIX.md`
- `AI_CONTEXT.md`

Do not share unless approved and sanitized:

- private pcaps
- raw payloads
- generated JSONL files
- generated corpus reports
- local validation reports
- local paths
- observed IP addresses or ports from real traffic

## Recommended operator workflow

1. Open a terminal.
2. Go to the repo:

       cd ~/OAD/oad-parser

3. Run the health check:

       python3 -m oad_parser validate-platform

4. If using a pcap, confirm it is approved for local use.
5. Inspect the pcap:

       python3 -m oad_parser inspect-pcap PATH_TO_APPROVED_FILE.pcap

6. Extract messages only if needed:

       python3 -m oad_parser extract-ecg-messages PATH_TO_APPROVED_FILE.pcap --jsonl --output output.jsonl

7. Keep generated outputs local unless they are reviewed and approved for sharing.

## When to ask for developer help

Ask a developer or maintainer if:

- `validate-platform` does not show `Passed: true`
- a command prints a Python traceback
- corpus validation shows mismatches
- you need to interpret `beacon-candidate` fields
- you need to add support for a new message type
- you need to share pcap-derived outputs externally
- you are unsure whether data is sanitized

## Release limitations

This release is ready for customer handoff as a parser-platform foundation after Python 3.9.2 validation evidence is collected.

It is not a final operational semantic decoder. Semantic expansion requires approved sanitized captures or authoritative message-format references.

Supported runtime: Python 3.9.2 or newer. See `START_HERE.md` for the exact customer handoff validation commands and `docs/TROUBLESHOOTING.md` for common failure recovery.
