# Customer handoff

## Handoff contents

The customer runtime/operator pack contains runtime code, configuration examples, systemd template, operator documentation, and a customer pack manifest.

It intentionally excludes internal development tests, corpus tooling, golden-fixture tooling, source-pack tooling, platform-control tooling, CI files, AI workflow context, and local validation reports.

Release/version identifiers are mapped in `docs/release/RELEASE_VERSION_MAPPING.md`. The current source-level mapping is Operator UI `0.9.0-rc4`, API contract `2026-06-17.8`, parser package `0.3.0`, and customer release line `oad-parser-customer-delivery v0.9.0-rc4`. Customer pack SHA256 must remain unset unless produced by the actual release packaging process.

## Required pre-handoff evidence

Release owners must validate the customer pack before handoff. Evidence should include:

- Customer pack manifest parseability.
- Manifest hash and size consistency.
- Manifest provenance fields.
- Runtime importability from outside the extracted pack root after installation.
- Customer CLI denylist check.
- Customer documentation consistency check.

## Customer runtime install

From the extracted customer pack root:

    sudo python3.9 scripts/install_customer_runtime.py --source . --prefix /opt/oad-parser --force

Then verify outside the extracted pack root:

    cd /
    /opt/oad-parser/venv/bin/python -c "import oad_parser; print(oad_parser.__version__)"
    /opt/oad-parser/venv/bin/python -m oad_parser --help
    /opt/oad-parser/venv/bin/python -m oad_parser live --help

## Systemd command

The customer systemd template uses:

    /opt/oad-parser/venv/bin/python -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface %i

For this release, the site/default instance is `ecg-parser@eno2.service` using interface `eno2`, OAD dataset `radar.oad.new`, and handoff file `/nsm/ecg/ecg-current.json`. Generic `%i` examples remain placeholders only; do not substitute `eno1` for this release unless a site-approved change record says to do so.

## Acceptance boundary

Customer handoff does not claim target-site acceptance. Target-site validation remains pending until executed on the target host with site configuration, connected interface evidence, root/systemd evidence, storage evidence, and SIEM handoff evidence.

## ECG SIEM handoff contract

The default live ECG operator handoff is a single newline-delimited JSON file at /nsm/ecg/ecg-current.json. The .json suffix is retained for the legacy/operator path, but each line is one JSON object. Rotation and audit/status sidecars are forced off by the target parser runtime.

## Limited RC Operator UI Safety Boundary

- RC4/customer acceptance is not claimed by source readiness, local tests, packaging readiness, or this UI safety pass.
- Target-site validation and site-owner acceptance are separate gates.
- The offline laptop must use the packaged Windows EXE customer delivery path. Do not use source-tree Python batch files as the customer runtime.
- Supported in this release through typed, allowlisted, preview/apply/backup/audit-gated controls: field policy v2 optional-field suppression; deterministic ordering for known fields; non-protected field aliases with SIEM-safe names; validated SIEM remap metadata; alert policy v2 repo-confirmed knobs; allowlisted per-alert enable/disable and severity overrides; allowlisted service boot status/enable/disable routes.
- Still unsupported or blocked: arbitrary field removal; protected, mandatory, or operator-required field removal; unsafe field aliases; unsupported parser runtime or detection behavior changes; per-alert cooldown; per-alert suppression; alert evidence-field mutation; raw shell execution; arbitrary service-name controls; target-site validation or customer acceptance claims from local/offline checks.
- Alert examples are not site-approved policies. Placeholder/example values such as `SITE_A`, `SITE_*`, and `EXAMPLE_*` are blocked until site-approved values are supplied.
- Output-volume policy changes require release-authority and SIEM-owner approval.
- Boot persistence status, enable, and disable are implemented only through allowlisted typed Operator UI service boot routes.
- Legacy `ecg.service` mutation is danger-gated and requires advanced mode plus explicit site-owner approval.
