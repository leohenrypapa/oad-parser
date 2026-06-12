# Customer pack policy

## Purpose

The customer runtime pack is the operator deliverable. It is generated from the internal source repo, but it is not a mirror of the internal source tree.

## Required release behavior

- Generate the customer pack from the dev repo source of truth.
- Validate the generated archive before handoff or publication.
- Rebuild and revalidate the customer pack whenever any customer-pack input changes.
- Publish external evidence beside the archive: SHA256SUMS, customer-pack-validation.json, and customer-pack-release-evidence.json.
- Preserve the runtime boundary: include operator runtime files and customer docs only.
- Exclude tests, CI internals, source-pack tooling, corpus/golden-fixture tooling, PCAPs, raw payloads, local reports, secrets, credentials, runtime outputs, and internal AI/workflow context.

## Default runtime output contract

The default SIEM handoff is a single newline-delimited JSON file:

    /nsm/ecg/ecg-current.json

The .json suffix is retained for operator compatibility, but the file is JSON Lines. Audit and status outputs are optional observability paths and are not default SIEM handoff files under /nsm/ecg.

## Validation boundary

Customer-pack validation proves archive structure, manifest consistency, runtime importability, customer CLI surface, customer documentation consistency, and basic content safety. It does not prove target-site acceptance, SIEM ingestion, or site-specific operational readiness.
