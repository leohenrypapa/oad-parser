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
