# OAD Parser - Start Here

## Customer operator start point

For the Sprint 2 live parser baseline, start with the live parser operator path:

1. Review `USER_MANUAL.md`.
2. Review `docs/ops/systemd-live-parser.md`.
3. Review `docs/ops/filebeat-elastic-agent-handoff.md`.
4. Review `docs/release/sprint-2-closeout.md`.
5. Review `docs/design/acceptance-test.md` for TEVV gate definitions.

Operational live parser files:

- `/etc/oad-parser/ecg_conf.ini`
- `/nsm/ecg/ecg-current.json` JSON Lines output, despite the `.json` suffix
- `/nsm/ecg/ecg-audit.jsonl`
- `/nsm/ecg/ecg-status.json`
- `deploy/systemd/ecg-parser@.service`
- `ecg-parser@eno1.service` through `ecg-parser@eno5.service`, as applicable to connected ECG interfaces

Internal engineering source-pack, corpus, golden-fixture, and AI/dev workflows remain available for maintainers but are not customer-required operational steps.

## Release purpose

This repository is a Python ECG/CD2 parser-platform foundation for continued OAD parser work. It provides replay, extraction, comparison, corpus regression, golden fixture, synthetic fixture, and source-pack handoff capabilities.

This release is not an authoritative radar semantic decoder release. The `beacon-candidate` decoder is provisional and must not be treated as operational truth without approved sanitized captures or authoritative message-format references.

## What is included

- Python package under `oad_parser/`
- Unit tests under `oad_parser/tests/`
- Example configuration under `config/`
- Operator and design notes under `docs/`
- Release helper scripts under `scripts/`
- Source-pack generator with customer-safe manifest metadata

## What is intentionally excluded

- Private packet captures
- Raw payloads and generated JSONL outputs
- Generated corpus reports and local validation reports
- Archives, caches, virtual environments, and Git internals
- Any claim that synthetic validation proves real-world semantic correctness

## Recommended reading order

1. `START_HERE.md`
2. `USER_MANUAL.md` for operators
3. `docs/TROUBLESHOOTING.md` if any command fails
4. `README.md`
5. `docs/release/CUSTOMER_HANDOFF.md`
6. `docs/release/RELEASE_CHECKLIST.md`
7. `docs/design/TRACEABILITY_MATRIX.md`
8. `docs/adr/0001-platform-foundation-scope.md`
9. `AI_CONTEXT.md` for AI-assisted continuation
10. `SOURCE-PACK-MANIFEST.json` inside the generated source pack

## First-run validation from an extracted source pack

Run from the extracted source-pack root:

    ./scripts/quickstart_check.sh

For a deeper check that also runs unit tests:

    ./scripts/quickstart_check.sh --with-tests

The quickstart script auto-selects `python3.9`, then `python3`, then `python`. Python 3.9.2 or newer is required. In the customer Python 3.9.2 environment, prefer explicit `python3.9` commands when collecting handoff evidence.

Expected success marker:

    == PASS: oad-parser quickstart check complete ==

These checks prove the local package, CLI command surface, synthetic fixture path, and validation harness run. They do not prove operational message semantics.

## Manual Python 3.9.2 validation evidence

Collect this evidence before customer handoff in the target Python 3.9.2 environment:

    python3.9 --version
    python3.9 -m compileall -q oad_parser
    python3.9 -m unittest discover -s oad_parser/tests -p "test_*.py"
    python3.9 -m oad_parser --help
    python3.9 -m oad_parser validate-platform
    python3.9 -m oad_parser generate-fixture-samples --output-dir /tmp/oad-parser-samples
    python3.9 -m oad_parser create-source-pack --output /tmp/oad-parser-source-pack.tar.gz

## Git-checkout release validation

The release helper scripts below are repo-checkout gates and require `.git` metadata. They are expected to fail from an extracted source pack.

Run from a Git checkout only:

    scripts/validate_sanitized_release.sh
    scripts/validate_release_readiness.sh
    scripts/make_source_pack.sh ~/Downloads/oad-parser-source-pack-final.tar.gz

Equivalent Make targets from a Git checkout:

    make quickstart
    make release-check
    make source-pack

## Supported command posture

Use `python3 -m oad_parser` as the canonical no-install invocation form in documentation and validation.

After installing the package, the configured console script is also available as:

    oad-parser --help

Supported for foundation handoff:

- `validate-platform`
- `create-source-pack`
- `extract-ecg-messages`
- `compare-legacy-envelope`
- `validate-corpus`
- `summarize-corpus-report`
- `export-golden-fixture`
- `check-golden-fixture`
- `generate-fixture-samples`

Use local pcap inspection and local pcap validation only with approved sanitized or private captures. Do not place those captures or generated private reports in the repository or customer source pack.

## Known limitations

- `beacon-candidate` is provisional and non-authoritative.
- Synthetic fixtures prove self-consistency and regression behavior only.
- Golden and corpus workflows detect drift and compatibility changes only.
- No sanitized operational capture corpus is included in this source pack.
- Live capture behavior depends on Linux raw-socket permissions and local network configuration.
- Version `0.1.0` is a foundation baseline, not a stable public API commitment.

## Safe next steps

- Add approved sanitized capture fixtures if release authority permits.
- Add authoritative message-format references before expanding semantic decoders.
- Add checksum, SBOM, and provenance automation if required by the receiving organization.
- Expand integration tests only with customer-safe data.

## Troubleshooting

Use `docs/TROUBLESHOOTING.md` for common first-run, Python version, missing `.git`, missing input, malformed input, and corpus validation failures.
