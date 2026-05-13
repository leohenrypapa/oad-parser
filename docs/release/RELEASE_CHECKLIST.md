# Release Checklist

## Sprint 2 closeout reference

Before executing Sprint 3 release-hardening gates, review:

- `docs/release/sprint-2-closeout.md`

The closeout records the final Sprint 2 merged baseline at `0277f30`, the proposed but uncreated tag `v0.3.0-live-parser-foundation`, validation evidence, included systemd and SIEM handoff artifacts, and remaining target/customer-handoff gates.


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
- Customer-pack hygiene result after the customer pack generator and validator exist.
- Short 6100 PPS synthetic acceptance result.
- Target-environment checklist result after Oracle Linux Server 9.6 validation is executed.
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

The TEVV runner is an orchestration tool for local gates and planned/manual target gates. It does not replace Oracle Linux Server 9.6 target validation, root runtime/systemd validation, SIEM owner handoff confirmation, customer-pack generation, or customer-pack validation.

## Sprint 2 documentation alignment gate

For Issue #39, customer-facing and release-facing docs must reflect the final Sprint 2 live parser implementation:

- `oad_parser live` is implemented.
- `/nsm/ecg/ecg-current.json` contains JSON Lines despite the `.json` suffix.
- `/nsm/ecg/ecg-audit.jsonl` and `/nsm/ecg/ecg-status.json` are documented.
- `deploy/systemd/ecg-parser@.service` and `ecg-parser@<interface>.service` usage are documented.
- `/etc/oad-parser/ecg_conf.ini` is documented as the target config path.
- Filebeat/Elastic Agent handoff boundaries are documented, with final SIEM version/site config confirmed by the SIEM owner.
- Internal engineering source pack workflows remain separate from the future customer runtime/operator handoff pack.
- Source-pack, corpus, golden-fixture, TEVV, and AI/dev workflows are not required customer operational steps.

## Customer runtime/operator pack generation gate

Generate the customer runtime/operator handoff pack before customer release:

    bash scripts/make_customer_pack.sh /tmp/oad-parser-customer-runtime.tar.gz

Minimum manual checks until Issue #41 adds the customer-pack validator:

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

Issue #41 adds automated customer-pack validation:

    .venv/bin/python scripts/validate_customer_pack.py --pack /tmp/oad-parser-customer-runtime.tar.gz --output-json /tmp/oad-customer-pack-validation.json

The validator must pass before customer handoff. It checks:

- Required runtime/operator entries.
- Forbidden internal/dev-only entries and prefixes.
- Forbidden entry suffixes for PCAPs, raw payloads, generated reports, archives, and secret-like files.
- `CUSTOMER-PACK-MANIFEST.json` presence and parseability.
- Manifest file hashes and sizes when present.

The validator inspects entries inside the archive. It does not reject the outer pack path because the pack itself is a `.tar.gz` file.
