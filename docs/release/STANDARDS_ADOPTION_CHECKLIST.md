# Standards Adoption Checklist

This repo adopts the standards baseline as a parser-project. It does not become a standards-repository clone.

## Automated repo controls

- `bash scripts/verify.sh` is the local and CI verification entry point.
- Python package compile check runs without private data.
- Unit tests run through `unittest` and emit `reports/tests/junit.xml`.
- CLI help load check runs through `python3 -m oad_parser --help`.
- Synthetic platform validation runs through `python3 -m oad_parser validate-platform --json`.
- Quickstart validation runs through `scripts/quickstart_check.sh`.
- Source-pack smoke generation runs without private captures.
- Source-pack manifest validation checks included paths, exclusions, hashes, validation metadata, and manual controls.

## Manual and platform controls

These controls are not enforced by repository files alone:

- Replace CODEOWNERS placeholder groups with approved GitLab users or groups.
- Protect `main` in GitLab.
- Protect `v*` release tags in GitLab.
- Enable merge request approvals.
- Enable CODEOWNERS approval in GitLab after owners are real.
- Require passing pipelines before merge.
- Keep CI variables protected and masked where applicable.
- Set `OAD_PARSER_CI_IMAGE` to an approved Registry1 Python 3.9 image pinned by digest.
- Restrict release and publish permissions to approved maintainers.
- Approve data classification and controlled-data handling before customer, release, or external AI handoff.
- Approve SBOM, signing, and provenance tooling before claiming those controls are automated.

## Release handoff checks

- Do not claim `beacon-candidate` is authoritative radar semantics.
- Do not include private pcaps, raw payloads, generated JSONL, reports, archives, caches, virtual environments, credentials, tokens, private keys, or controlled data in source packs.
- Attach generated `reports/` evidence to the controlled review or release record when required; do not commit generated evidence by default.
