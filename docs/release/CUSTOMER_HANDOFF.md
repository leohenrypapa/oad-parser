# Customer Handoff Note

## Deliverable

The deliverable is a customer-safe source pack for the OAD parser platform foundation.

It includes source code, tests, example configuration, design notes, release guardrails, and helper scripts needed to continue parser-platform work without private capture data.

## Release positioning

This is a foundation handoff for parser development and regression validation. It is suitable for code review, continuation, and controlled validation.

It is not a final operational semantic radar decoder release.

## Validation evidence

Supported release-validation runtime: Python 3.9.2 exactly.

Expected release evidence:

- Unit tests pass.
- `python3 -m oad_parser validate-platform` passes.
- Sanitized release validation passes without private pcaps.
- Release readiness validation passes.
- Final source pack is generated and inspected.

This evidence supports platform readiness and regression harness readiness. It does not independently validate real-world radar message semantics.

## Data handling

The source pack intentionally excludes:

- Private pcaps
- Raw payload files
- Generated JSONL outputs
- Generated corpus reports
- Local validation reports
- Archives and caches
- Git internals

Local pcap validation scripts are provided for authorized internal use only. Reports from those scripts may contain local paths or traffic-shape details and must be sanitized before customer or AI handoff.

## Provisional decoder rule

`beacon-candidate` is a provisional decoder. Its output may support development and comparison workflows, but it must not be used as authoritative radar truth without approved sanitized captures or authoritative message-format references.

## Recommended customer review path

1. Read `START_HERE.md`.
2. Use `USER_MANUAL.md` for operator guidance.
3. Review `README.md` for capabilities and command examples.
4. Review `docs/design/TRACEABILITY_MATRIX.md` for capability-to-evidence mapping.
5. Review `docs/adr/0001-platform-foundation-scope.md` for release scope boundaries.
6. Run the validation commands in `docs/release/RELEASE_CHECKLIST.md`.

## Known limitations

- No sanitized operational capture corpus is included.
- No SBOM, signature, or formal provenance bundle is included unless generated separately by the release operator.
- Semantic decoder expansion requires approved evidence.
- Version `0.1.0` should be treated as a foundation baseline.

## Python 3.9.2 customer handoff notes

- Target runtime validation must be run with Python 3.9.2 before customer handoff.
- Recommended validation commands:
  - .venv/bin/python -m unittest discover -s oad_parser/tests -p "test_*.py"
  - .venv/bin/python -m oad_parser --help
  - .venv/bin/python -m oad_parser validate-platform
  - PYTHON_BIN=.venv/bin/python bash scripts/make_source_pack.sh /tmp/oad-parser-source-pack.tar.gz
- The `capture` command requires bounded capture with `--max-frames` or `[capture] max_frames` in config. Continuous capture is not enabled for JSONL handoff output.
- `validate-corpus` returns nonzero when parser errors, mismatches, or zero-comparison files are present.
- A zero-comparison file means the file was scanned but did not produce parser comparisons. Treat this as a validation failure until the input format and parser selection are confirmed.
- Source-pack generation rejects included symlinks and excludes local/private capture artifacts by policy. In extracted source packs, tracked-only mode is constrained by SOURCE-PACK-MANIFEST.json; use --include-untracked only for internal local snapshots.
## Live parser SIEM handoff

For Sprint 2 MVP, Filebeat or Elastic Agent 8.17.3 should collect append-style parser files only:

    /nsm/ecg/ecg-current.json
    /nsm/ecg/ecg-audit.jsonl

`/nsm/ecg/ecg-status.json` remains local-only for operator inspection. See `docs/ops/filebeat-elastic-agent-handoff.md`.

## Customer handoff alignment

The default customer handoff posture is a runtime/operator package, not the broad internal engineering source pack.

Customer-facing operational content should focus on:

- `oad_parser live`
- `/etc/oad-parser/ecg_conf.ini`
- `/nsm/ecg/ecg-current.json` JSON Lines output
- `/nsm/ecg/ecg-audit.jsonl`
- `/nsm/ecg/ecg-status.json`
- `deploy/systemd/ecg-parser@.service`
- `docs/ops/systemd-live-parser.md`
- `docs/ops/filebeat-elastic-agent-handoff.md`

The internal engineering source pack may retain tests, source-pack logic, corpus/golden-fixture tooling, TEVV automation, and AI/dev context. Those workflows should not be presented as customer-required operator steps.

Filebeat/Elastic Agent 8.17.3 remains the expected customer assumption, but final site-specific version, endpoint, index, credentials, certificates, and deployment configuration must be confirmed by the SIEM owner outside this repo.

## Customer runtime/operator pack profile

The repository includes the customer runtime/operator handoff pack profile.

Generate the customer pack with:

    bash scripts/make_customer_pack.sh /tmp/oad-parser-customer-runtime.tar.gz

This customer pack is separate from the internal engineering source pack produced by `scripts/make_source_pack.sh` or `oad_parser create-source-pack`.

The customer pack includes runtime/operator content required for:

- `python -m oad_parser --help`
- `python -m oad_parser live --help`
- `/etc/oad-parser/ecg_conf.ini`
- `/nsm/ecg/ecg-current.json` JSON Lines output
- `/nsm/ecg/ecg-audit.jsonl`
- `/nsm/ecg/ecg-status.json`
- `deploy/systemd/ecg-parser@.service`
- `docs/ops/systemd-live-parser.md`
- `docs/ops/filebeat-elastic-agent-handoff.md`

The customer pack excludes internal/dev-only CI, tests, source-pack tooling, corpus/golden-fixture tooling, TEVV development evidence, generated reports, archives, caches, PCAPs, raw payloads, secrets, local runtime outputs, and site-specific SIEM values by default.

The package contains `CUSTOMER-PACK-MANIFEST.json`, which records the package profile, included files, hashes, operational path notes, and exclusion posture.

The repository includes a dedicated customer-pack validation script. Release operators should validate the generated pack and inspect the manifest before handoff.

## Customer-pack validation

Validate the generated customer runtime/operator pack before handoff:

    .venv/bin/python scripts/validate_customer_pack.py --pack /tmp/oad-parser-customer-runtime.tar.gz --output-json /tmp/oad-customer-pack-validation.json

The validation report records required-entry checks, forbidden-entry checks, manifest checks, unsafe-artifact checks, limitations, and an overall `status`.

A valid generated customer pack should return exit code 0 and report `"status": "passed"`.

## Target validation checklist reference

Use `docs/release/target-environment-validation.md` for target validation before operational acceptance.

The checklist separates parser-owned `/nsm/ecg` outputs from SIEM-owned Filebeat/Elastic Agent configuration and documents that pass/fail live validation applies only to connected ECG interfaces.

## Customer pack target-validation checklist inclusion

The customer runtime/operator handoff pack includes `docs/release/target-environment-validation.md`.

This checklist is customer-facing operator guidance for Oracle Linux Server 9.6, Python 3.9.2, root/systemd runtime validation, `/nsm/ecg` outputs, connected ECG interface validation, and Filebeat/Elastic Agent SIEM handoff assumptions.
