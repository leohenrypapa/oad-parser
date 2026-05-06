# Changelog

## 0.1.0 - Foundation release candidate

### Added

- ECG/CD2 parser-platform foundation.
- CD2 protocol helper layer.
- Decoder registry with `raw12` and provisional `beacon-candidate` decoder.
- Legacy-vs-envelope comparison workflow.
- Corpus validation and corpus summary workflow.
- Golden fixture export and check workflow.
- Synthetic fixture generation.
- End-to-end platform validation command.
- Source-pack generator and release helper scripts.
- Customer release handoff guardrails: `START_HERE.md`, `AI_CONTEXT.md`, release checklist, customer handoff note, traceability matrix, and scope ADR.

### Changed

- Source-pack generation defaults to tracked files only.
- Source-pack manifest no longer stores operator-local absolute repository or output paths.
- Release helper scripts inspect source-pack manifest contents for local path leakage.

### Security and release hygiene

- Customer source packs exclude captures, raw payloads, generated reports, caches, archives, and Git internals.
- Historical design notes are customer-sanitized and should not be treated as operational evidence.

### Known limitations

- `beacon-candidate` is provisional and non-authoritative.
- Synthetic, golden, corpus, and platform validation prove regression or self-consistency only.
- No sanitized operational capture corpus is included.
