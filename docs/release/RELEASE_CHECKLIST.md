# Release Checklist

## Sprint 2 closeout reference

Before executing Sprint 3 release-hardening gates, review:

- `docs/release/sprint-2-closeout.md`
- `docs/release/ci-cd-release-workflow.md`
- `docs/release/target-environment-validation-result-template.md`

The closeout records the Sprint 2 live parser foundation and the protected release tag `v0.3.0-live-parser-foundation` at `ec77682`, validation evidence, included systemd and SIEM handoff artifacts, and remaining target/customer-handoff gates.


## Scope gate

- Release is described as a parser-platform foundation.
- `beacon-candidate` is labeled provisional and non-authoritative.
- Synthetic, golden, corpus, and platform validation are described as regression or self-consistency checks only.
- No claim is made that operational radar semantics are proven.

## Repository gate

- Working tree has only intentional release-finish changes before commit.
- No private captures, raw payloads, generated JSONL, generated corpus reports, archives, caches, or virtual environments are tracked.
- Historical notes have been scrubbed of local paths, private pcap names, observed IPs, ports, and operator-machine details.

## Validation gate

Supported runtime: Python 3.9.2 or newer.

Run from the repository root:

    git status --short
    bash scripts/verify.sh
    python3.9 -m unittest discover -s oad_parser/tests -p "test_*.py"
    python3.9 -m oad_parser validate-platform
    scripts/validate_sanitized_release.sh
    scripts/validate_release_readiness.sh
    scripts/make_source_pack.sh ~/Downloads/oad-parser-source-pack-final.tar.gz

## Source-pack gate

- `SOURCE-PACK-MANIFEST.json` contains no `repo_root` or `output_path` fields.
- Manifest paths are relative repository paths only.
- `file_count` means packaged files excluding `SOURCE-PACK-MANIFEST.json`.
- Source pack includes `START_HERE.md`, `AI_CONTEXT.md`, `CHANGELOG.md`, release docs, traceability matrix, and ADR.
- Source pack excludes captures, raw payloads, generated reports, archives, caches, and Git internals.

## Handoff gate

- Customer handoff note is present.
- AI context guide is present.
- Known limitations are present and consistent across docs.
- Final source pack path and commit hash are recorded in the release message.

## Standards adoption gate

- CODEOWNERS exists but placeholder owners must be replaced before enforcing approvals.
- `standards-manifest.json` indexes repo-local commands, generated evidence, key files, and manual/platform controls.
- GitLab settings for protected main, protected v* tags, MR approvals, CODEOWNERS approval, passing pipelines, protected/masked variables, approved Registry1 pinned CI image, and release restrictions are manual/platform controls.
- Generated `reports/` evidence is attached to controlled review or release records when required; it is not committed by default.

## TEVV evidence requirements

Before customer handoff, release evidence should be organized by the TEVV matrix in `docs/design/acceptance-test.md`.

Minimum evidence expectations:

- Local compile/syntax check result.
- Full unit test result.
- CLI compatibility result for `oad_parser` and `oad_parser live`.
- Platform validation JSON showing `"passed": true`.
- Static validation for systemd and Filebeat/Elastic handoff documentation.
- Internal source-pack hygiene result.
- Customer-pack hygiene result from the generated customer runtime/operator pack and `scripts/validate_customer_pack.py`.
- Short 6100 PPS synthetic acceptance result.
- Target-environment checklist result after Oracle Linux Server 9.6 validation is executed.
- Target-site validation results should be recorded with `docs/release/target-environment-validation-result-template.md` after checklist execution and sanitization review.
- SIEM handoff confirmation by the SIEM owner.

Evidence handling requirements:

- Generated evidence under `reports/` is not committed by default.
- Target evidence must be reviewed for site-sensitive values before sharing.
- Do not commit real PCAPs, raw operational payloads, secrets, local runtime outputs, hostnames, IPs, tokens, certificates, keys, or site-specific SIEM values.
- Do not claim Oracle Linux Server 9.6 target validation has passed until target evidence exists.
- Keep the internal engineering source pack separate from the customer runtime/operator handoff package.
- Treat optional one-hour 6100 PPS acceptance as P1 and not a blocker for the initial customer handoff package.

## TEVV suite runner gate

For the local release-hardening evidence bundle, run:

    .venv/bin/python scripts/run_tevv_suite.py --profile local --report-dir reports/tevv

Expected generated evidence:

- `reports/tevv/tevv-report.json`
- `reports/tevv/tevv-report.md`
- `reports/tevv/tevv-evidence-manifest.json`

The TEVV runner is an orchestration tool for local gates and manual target gates. It does not replace Oracle Linux Server 9.6 target validation, root runtime/systemd validation, or SIEM owner handoff confirmation.

## CI/CD release workflow gate

Review `docs/release/ci-cd-release-workflow.md` before release packaging or protected tag review.

Minimum CI/CD expectations:

- Merge request and default branch pipelines run `verify`, `tevv_local`, `customer_pack`, and `source_pack`.
- Protected `v*` tag pipelines run `release_artifacts` and publish release checksums, TEVV reports, customer-pack artifacts, and source-pack artifacts.
- CI/CD artifacts support local engineering and package-readiness evidence only.
- Target-site operational acceptance remains pending until target evidence exists.

## Sprint 2 documentation alignment gate

For Issue #39, customer-facing and release-facing docs must reflect the final Sprint 2 live parser implementation:

- `oad_parser live` is implemented.
- `/nsm/ecg/ecg-current.json` contains JSON Lines despite the `.json` suffix.
- `/nsm/ecg/ecg-audit.jsonl` and `/nsm/ecg/ecg-status.json` are documented.
- `deploy/systemd/ecg-parser@.service` and `ecg-parser@<interface>.service` usage are documented.
- `/etc/oad-parser/ecg_conf.ini` is documented as the target config path.
- Filebeat/Elastic Agent handoff boundaries are documented, with final SIEM version/site config confirmed by the SIEM owner.
- Internal engineering source pack workflows remain separate from the customer runtime/operator handoff pack.
- Source-pack, corpus, golden-fixture, TEVV, and AI/dev workflows are not required customer operational steps.

## Customer runtime/operator pack generation gate

Generate the customer runtime/operator handoff pack before customer release:

    bash scripts/make_customer_pack.sh /tmp/oad-parser-customer-runtime.tar.gz

Minimum customer-pack content expectations:

- `CUSTOMER-PACK-MANIFEST.json` is present.
- `config/ecg_conf.example.ini` is present.
- `deploy/systemd/ecg-parser@.service` is present.
- `docs/ops/systemd-live-parser.md` is present.
- `docs/ops/filebeat-elastic-agent-handoff.md` is present.
- `USER_MANUAL.md` is present.
- `AI_CONTEXT.md`, `.gitlab-ci.yml`, `CODEOWNERS`, `standards-manifest.json`, `oad_parser/tests/`, and internal source-pack scripts are absent.
- Generated reports, runtime outputs, archives, PCAPs, raw payloads, secrets, and site-specific values are absent.

The customer runtime/operator pack is separate from the internal engineering source pack. Do not replace or degrade `scripts/make_source_pack.sh` or `oad_parser create-source-pack`.

## Customer-pack validation gate

Automated customer-pack validation is available through `scripts/validate_customer_pack.py`:

    .venv/bin/python scripts/validate_customer_pack.py --pack /tmp/oad-parser-customer-runtime.tar.gz --output-json /tmp/oad-customer-pack-validation.json

The validator must pass before customer handoff. It checks:

- Required runtime/operator entries.
- Forbidden internal/dev-only entries and prefixes.
- Forbidden entry suffixes for PCAPs, raw payloads, generated reports, archives, and secret-like files.
- `CUSTOMER-PACK-MANIFEST.json` presence and parseability.
- Manifest file hashes and sizes when present.

The validator inspects entries inside the archive. It does not reject the outer pack path because the pack itself is a `.tar.gz` file.

## Target-environment validation gate

Before customer operational acceptance, complete or explicitly defer the target-environment validation checklist:

    docs/release/target-environment-validation.md

The gate covers Oracle Linux Server 9.6, Python 3.9.2, root runtime/systemd validation, `/etc/oad-parser/ecg_conf.ini`, `/nsm/ecg`, connected ECG interface selection for `eno1` through `eno5` as applicable, output file checks, storage behavior validation, and Filebeat/Elastic Agent 8.17.3 SIEM owner confirmation.

Do not commit target logs, runtime outputs, real PCAPs, raw payloads, hostnames, IP addresses, SIEM endpoints, tokens, certificates, private keys, index names, customer-specific interface mappings, or unsanitized systemd journal exports.

## Customer pack target-validation checklist inclusion

Before tag readiness, confirm the customer runtime/operator handoff pack includes:

    docs/release/target-environment-validation.md

The customer-pack validator requires this file and must report `"status": "passed"` before handoff.
