# CI/CD Release Workflow

## Scope

This workflow documents the local engineering and GitLab CI/CD gates for the OAD ECG/CD2 parser platform.

It does not claim target-site operational acceptance. Oracle Linux Server 9.6 validation, root/systemd runtime validation, connected ECG interface validation, and final Filebeat/Elastic Agent site configuration confirmation remain target-site gates.

## Branch and tag model

Use protected `main` plus protected release tags.

Do not create separate long-lived customer and developer release branches by default. Customer and internal deliverables are separated by package profile:

- Customer runtime/operator handoff pack
- Internal engineering source pack

Create a release or hotfix branch only when a defect must be patched against an existing release tag while `main` moves forward.

Recommended hotfix pattern:

- Branch from the release tag, for example `hotfix/v0.3.0-<short-defect>`
- Patch the minimum verified defect
- Run local and CI gates
- Run target-relevant validation if the defect affects target execution
- Merge or cherry-pick back to `main`
- Create a new tag only after explicit approval

## Pipeline types

| Pipeline context | Jobs | Purpose | Blocks |
|---|---|---|---|
| Merge request | `verify`, `tevv_local`, `customer_pack`, `source_pack` | Validate proposed changes before merge | Yes |
| Default branch | `verify`, `tevv_local`, `customer_pack`, `source_pack` | Preserve release-readiness on `main` | Yes |
| Protected `v*` tag | `verify`, `tevv_local`, `customer_pack`, `source_pack`, `release_artifacts` | Publish release evidence and package artifacts | Yes |
| Web pipeline | `verify` | Manual baseline validation | Yes for that pipeline only |
| Scheduled pipeline | `verify`, `tevv_local`, `customer_pack`, `source_pack` | Periodic drift check for runner/image/package behavior | Yes for that scheduled pipeline only |

## Job summary

| Job | Stage | Command focus | Artifacts | Expiration |
|---|---|---|---|---|
| `verify` | `verify` | Runs `scripts/verify.sh` | JUnit, platform validation, source-pack smoke reports, standards report | 14 days |
| `tevv_local` | `tevv` | Runs `scripts/run_tevv_suite.py --profile local` | `reports/tevv/`, JUnit, validation reports, source-pack reports, customer-pack reports | 30 days |
| `customer_pack` | `package` | Generates and validates the customer runtime/operator pack | Customer pack tarball and validation JSON | 30 days |
| `source_pack` | `package` | Generates and validates the internal engineering source pack | Source pack tarball and manifest validation JSON | 30 days |
| `release_artifacts` | `release` | Runs tag-only release evidence generation for `v*` tags | Release checksums, customer pack, source pack, TEVV reports, validation reports, JUnit | 1 year |

## Scheduled drift-check behavior

Optional scheduled pipelines can be configured on the protected default branch to run the same local engineering/package-readiness gates used for merge request and default-branch validation.

Scheduled pipelines are not target-site operational validation. They detect CI runner, image, package, and validation drift.

## Release artifact behavior

For protected release tags matching `v*`, the `release_artifacts` job produces:

- `reports/release/SHA256SUMS-<tag>.txt`
- `reports/customer-pack/oad-parser-customer-runtime-<tag>.tar.gz`
- `reports/customer-pack/customer-pack-validation-<tag>.json`
- `reports/source-pack/oad-parser-source-pack-<tag>.tar.gz`
- `reports/source-pack/source-pack-manifest-check-<tag>.json`
- `reports/tevv/tevv-report.json`
- `reports/tevv/tevv-report.md`
- `reports/tevv/tevv-evidence-manifest.json`
- `reports/tests/junit.xml`
- `reports/validation/`

These artifacts are release evidence for local engineering and package readiness. They are not target-site operational acceptance evidence.

## Required interpreter posture

Release and validation scripts are expected to run with Python 3.9.2.

For local work, use:

    /home/yyou/rapid-capabilities-oad-parser/.venv/bin/python

Local release validation must use Python 3.9.2 exactly. GitLab CI uses the pinned Iron Bank `python39` image and may report a newer Python 3.9 patch version; CI jobs set `OAD_ALLOW_CI_PY39_PATCH_DRIFT=1` so CI validates Python 3.9.x behavior without weakening the local 3.9.2 release-validation requirement.

## Customer and internal artifact separation

The customer runtime/operator pack is intended for customer handoff. It excludes internal development, CI, standards, source-pack, corpus, and test-only content.

The internal engineering source pack is intended for development, review, and release engineering context. It is not the customer runtime/operator handoff package.

## Target-site evidence boundary

Do not commit target-site logs, raw payloads, real PCAPs, hostnames, IP addresses, SIEM endpoints, tokens, certificates, private keys, runtime outputs, or site-specific values.

Target-site validation should be recorded in sanitized form only after review and approval.
