# Sprint 2 Closeout - Live Parser Foundation

## Purpose

This closeout records the Sprint 2 live parser foundation and the later v0.3.0 release-hardening baseline used for customer-pack-ready handoff planning.

## Final Sprint 2 baseline

- Release baseline commit: `ec77682`
- Release tag: `v0.3.0-live-parser-foundation` (created and pushed; targets `ec77682`)
- Python target: 3.9.2
- Sprint 2 MRs merged: !10 through !23
- Sprint 2 implementation issues closed: #22 through #35

## Final validation evidence

The following Sprint 2 evidence is recorded as the final merged baseline:

- Full unit suite passed: 252 tests
- Platform validation passed
- Non-root live smoke passed using `/tmp` output paths
- 6100 PPS synthetic acceptance passed
- Release readiness passed
- Sanitized release validation passed

## Final source pack contents confirmed

The final Sprint 2 source pack includes the required operator and handoff artifacts:

- `deploy/systemd/ecg-parser@.service`
- `docs/ops/systemd-live-parser.md`
- `docs/ops/filebeat-elastic-agent-handoff.md`

Final source pack copy recorded:

- `/mnt/c/Users/you43/Downloads/oad-parser-sprint2-final-source-pack.tar.gz`

## Scope boundary

This closeout does not claim target-environment operational acceptance. It records the validated local engineering and customer-pack-ready release baseline only.

Sprint 2 preserves the existing parser behavior and does not add new radar semantics. The `beacon-candidate` path remains provisional and must not be treated as authoritative radar interpretation.

## Remaining release-hardening gates

The following gates remain before final customer handoff:

- Oracle Linux Server 9.6 target validation
- Python 3.9.2 target validation on the customer or target-like host
- Root runtime and systemd validation
- `/nsm/ecg` output path validation
- Connected ECG interface validation for `eno1` through `eno5` as applicable
- Filebeat/Elastic Agent 8.17.3 handoff confirmation by the SIEM owner
- Customer runtime/operator handoff package generation
- Customer-pack validation

## Packaging posture

The internal engineering source pack remains separate from the customer runtime/operator handoff package.

The CLI can keep development and maintenance commands for now. Sanitization is handled through documentation and package profiles rather than hiding CLI commands.

## Follow-on tracking

Sprint 3 release-hardening work is tracked in issues #36 through #42.
