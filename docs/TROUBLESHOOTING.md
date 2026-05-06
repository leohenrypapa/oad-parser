# OAD Parser Troubleshooting

Use this guide when a first-run, validation, or handoff command fails.

## First command to run

From the repository root or extracted source-pack root:

    ./scripts/quickstart_check.sh

For a deeper check that also runs unit tests:

    ./scripts/quickstart_check.sh --with-tests

The quickstart script does not require `.git` metadata and does not use private pcaps.

## Wrong Python version

Symptom:

    ERROR: Python 3.9.2 or newer is required

Fix:

    python3.9 --version
    python3.9 -m oad_parser validate-platform

The supported runtime is Python 3.9.2 or newer. In the customer Python 3.9.2 environment, prefer `python3.9` explicitly.

## Not in the repository root

Symptom:

    No module named oad_parser

Fix:

    cd PATH_TO_EXTRACTED_OR_CLONED_OAD_PARSER
    python3.9 -m oad_parser --help

You can also run the quickstart script from anywhere by using its full path.

## Extracted source pack has no .git directory

Symptom:

    ERROR: this validation requires a Git checkout with .git metadata

Cause:

Release-readiness scripts are Git-checkout gates. Extracted source packs intentionally exclude `.git` metadata.

Use these extraction-safe commands instead:

    ./scripts/quickstart_check.sh
    python3.9 -m unittest discover -s oad_parser/tests -p "test_*.py"
    python3.9 -m oad_parser validate-platform

## Missing or invalid input path

Symptom:

    No such file or directory

Fix:

- Confirm the file exists.
- Use only approved local or sanitized pcaps.
- Do not place private pcaps, raw payloads, JSONL outputs, or local validation reports in the source pack.

## No pcap is available

You can still validate the platform with synthetic non-sensitive samples:

    python3.9 -m oad_parser validate-platform
    python3.9 -m oad_parser generate-fixture-samples --output-dir /tmp/oad-parser-samples

Synthetic samples prove parser regression and self-consistency only. They do not prove operational radar semantic correctness.

## Malformed input or unexpected parser output

Use the smallest safe command first:

    python3.9 -m oad_parser inspect-pcap PATH_TO_APPROVED_FILE.pcap

If the input is a raw ECG payload, use:

    python3.9 -m oad_parser extract-ecg-messages PATH_TO_RAW_PAYLOAD --raw-payload --jsonl

Do not share command output externally until it has been reviewed for local paths, addresses, ports, or other sensitive details.

## validate-corpus returns nonzero

`validate-corpus` returns nonzero when parser errors, mismatches, or zero-comparison files are present.

A zero-comparison file means the file was scanned but did not produce parser comparisons. Treat it as a validation failure until the input format and parser selection are confirmed.

Next steps:

    python3.9 -m oad_parser summarize-corpus-report corpus-report.json

Then ask a maintainer to review the mismatches, parser errors, or zero-comparison files.

## Beacon-candidate output looks wrong or incomplete

The `beacon-candidate` decoder is provisional and non-authoritative. Do not treat it as operational radar truth without approved sanitized captures or authoritative message-format references.

## When to contact a maintainer

Contact a maintainer if:

- `validate-platform` does not show `Passed: true`.
- A command prints a Python traceback.
- Corpus validation shows mismatches or zero-comparison files.
- You need to interpret `beacon-candidate` fields.
- You need to share pcap-derived output externally.
- You are unsure whether data is sanitized.
