# Target-Environment Validation Result Template

## Purpose

Use this template to record sanitized target-site validation results for the OAD ECG/CD2 parser platform.

This template does not replace `docs/release/target-environment-validation.md`. It records operator-run results after the checklist is executed on an approved target or target-like host.

Do not commit completed target-site result files unless they have been sanitized, reviewed, and approved for release records.

## Result status

Select one:

- `PASS`
- `PASS WITH LIMITATIONS`
- `FAIL`
- `DEFERRED`
- `NOT RUN`

Overall result:

    <PASS | PASS WITH LIMITATIONS | FAIL | DEFERRED | NOT RUN>

Target-site operational acceptance claimed:

    No

Reason if not accepted:

    Target-site operational acceptance requires release authority review of sanitized evidence.

## Run control

| Field | Sanitized value |
|---|---|
| Run date | `<YYYY-MM-DD>` |
| Release tag under validation | `v0.3.0-live-parser-foundation` |
| Commit under validation | `ec77682` |
| Operator or reviewer role | `<role only>` |
| Target profile | `<approved target or target-like profile>` |
| Evidence package location | `<controlled record reference only>` |
| Sanitization reviewer | `<role only>` |

## Environment checks

| Gate | Result | Evidence reference | Notes |
|---|---|---|---|
| Oracle Linux Server 9.6 confirmed | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Do not include machine identifiers. |
| Python 3.9.2 confirmed | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Record interpreter path only if sanitized. |
| Repo or customer pack integrity confirmed | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Include checksum reference if approved. |
| Required config path present | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Do not include site values. |
| Required output path present | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Do not include runtime output content. |

## Runtime checks

| Gate | Result | Evidence reference | Notes |
|---|---|---|---|
| Root execution validated where required | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Do not include command history with sensitive values. |
| systemd unit installed or staged | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Use sanitized service status only. |
| systemd start/stop/restart behavior validated | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Do not include raw journal exports. |
| Config loading validated | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Redact site-specific values. |
| Output files created as expected | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Record paths only, not operational records. |
| Storage high-water behavior validated | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Use synthetic or sanitized evidence. |
| Critical storage threshold behavior validated | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Use synthetic or sanitized evidence. |

## Interface and data-flow checks

| Gate | Result | Evidence reference | Notes |
|---|---|---|---|
| Approved ECG interface selected | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Do not include site-specific mappings. |
| Connected ECG interface validation completed | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Do not include raw payloads. |
| Parser emits expected JSONL files | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Do not include operational records. |
| Audit/status behavior validated | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Use sanitized excerpts only if approved. |
| SIEM owner confirms Filebeat or Elastic Agent handoff | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<sanitized reference>` | Do not include endpoint values. |

## Local engineering evidence cross-reference

| Evidence | Result | Reference |
|---|---|---|
| Unit suite | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<controlled reference>` |
| Platform validation | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<controlled reference>` |
| TEVV local suite | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<controlled reference>` |
| Customer pack validation | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<controlled reference>` |
| Source pack validation | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<controlled reference>` |
| 6100 PPS synthetic acceptance | `<PASS | FAIL | DEFERRED | NOT RUN>` | `<controlled reference>` |

## Defects, deviations, and limitations

| ID | Severity | Description | Disposition |
|---|---|---|---|
| `<TV-001>` | `<low | medium | high | blocker>` | `<sanitized description>` | `<open | mitigated | accepted | fixed | deferred>` |

## Sanitization checklist

Confirm before sharing outside the target environment:

- No real PCAPs.
- No raw operational payloads.
- No runtime JSONL records.
- No unsanitized logs.
- No machine identifiers.
- No network addresses.
- No endpoint values.
- No credentials, tokens, certificates, private keys, or secret-like values.
- No customer-specific interface mappings.
- No SIEM index names or site configuration values.
- No generated archives unless explicitly approved for the controlled release record.

Sanitization reviewer decision:

    <APPROVED | REWORK REQUIRED | NOT REVIEWED>

## Recommendation

Select one:

- Proceed with customer operational acceptance review.
- Proceed with limitations listed above.
- Hold for defect correction.
- Defer target-site validation.
- Do not proceed.

Recommendation:

    <selected recommendation>

Reviewer notes:

    <sanitized notes>
