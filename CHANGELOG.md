# Changelog

## Sprint 3 Documentation Alignment - Issue #39

- Aligned customer-facing and release-facing docs with the implemented Sprint 2 `oad_parser live` path.
- Documented `/nsm/ecg/ecg-current.json` as JSON Lines despite the `.json` suffix.
- Documented `/nsm/ecg/ecg-audit.jsonl`, `/nsm/ecg/ecg-status.json`, `/etc/oad-parser/ecg_conf.ini`, and `deploy/systemd/ecg-parser@.service`.
- Clarified Filebeat/Elastic Agent handoff boundaries and SIEM owner confirmation requirements.
- Clarified that internal engineering source-pack, corpus, golden-fixture, TEVV, and AI/dev workflows are not customer-required operational steps.


## Sprint 2 Closeout - Live Parser Foundation

- Recorded v0.3.0 release baseline at `ec77682`.
- Confirmed Sprint 2 MRs !10 through !23 merged and Sprint 2 issues #22 through #35 closed.
- Recorded Python 3.9.2 target and final validation evidence: 252 tests passed, platform validation passed, non-root live smoke passed using `/tmp` output paths, 6100 PPS synthetic acceptance passed, release readiness passed, and sanitized release validation passed.
- Confirmed final source pack includes `deploy/systemd/ecg-parser@.service`, `docs/ops/systemd-live-parser.md`, and `docs/ops/filebeat-elastic-agent-handoff.md`.
- Identified remaining release-hardening gates for Oracle Linux Server 9.6, target Python 3.9.2, root runtime/systemd, `/nsm/ecg`, connected `eno1` through `eno5` ECG interfaces as applicable, Filebeat/Elastic Agent 8.17.3 confirmation, and customer runtime/operator package validation.
- Recorded protected release tag `v0.3.0-live-parser-foundation` targeting `ec77682`; target-site operational acceptance remains pending.


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
