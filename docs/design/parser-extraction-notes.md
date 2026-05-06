# Parser Extraction Notes

## Purpose

This note records the extraction boundary for the platform foundation. Current release authority comes from the code, tests, release docs, and approved validation commands, not from private legacy file paths.

## First extracted behavior

The parser-platform foundation supports:

- raw ECG payload bytes
- Ethernet/IPv4/UDP frames containing ECG payloads
- ECG envelope extraction
- CD2 framing helpers
- legacy-vs-envelope comparison
- detector scaffolding outside parser core
- JSONL-oriented output workflows

## Intentional boundaries

The parser core should not:

- open raw sockets directly
- depend on local private config files
- write private captures or generated reports into the repository
- run detector state inside low-level parsing
- claim new radar semantics without approved evidence

## Next extraction step

Future extraction should remain evidence-gated and should add tests before changing semantic behavior.
