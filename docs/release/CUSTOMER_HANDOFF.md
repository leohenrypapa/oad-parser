# Customer handoff

## Handoff contents

The customer runtime/operator pack contains runtime code, configuration examples, systemd template, operator documentation, and a customer pack manifest.

It intentionally excludes internal development tests, corpus tooling, golden-fixture tooling, source-pack tooling, platform-control tooling, CI files, AI workflow context, and local validation reports.

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

## Acceptance boundary

Customer handoff does not claim target-site acceptance. Target-site validation remains pending until executed on the target host with site configuration, connected interface evidence, root/systemd evidence, storage evidence, and SIEM handoff evidence.

## ECG SIEM handoff contract

The default live ECG operator handoff is a single newline-delimited JSON file at /nsm/ecg/ecg-current.json. The .json suffix is retained for the legacy/operator path, but each line is one JSON object. Rotation is disabled by default, and audit/status files are not written under /nsm/ecg by default. Enable rotation or observability only by explicit config.

## Limited RC Operator UI Safety Boundary

- RC4/customer acceptance is not claimed by source readiness, local tests, packaging readiness, or this UI safety pass.
- Target-site validation and site-owner acceptance are separate gates.
- The offline laptop must use the packaged Windows EXE customer delivery path. Do not use source-tree Python batch files as the customer runtime.
- Unsupported in this release: field naming, field order, SIEM/ECS remap, arbitrary field removal, per-alert severity, per-alert enable/disable, cooldown, suppression, and alert evidence mutation.
- Alert examples are not site-approved policies. Placeholder/example values such as `SITE_A`, `SITE_*`, and `EXAMPLE_*` are blocked until site-approved values are supplied.
- Output-volume policy changes require release-authority and SIEM-owner approval.
- Boot persistence is not implemented as an Operator UI action in this release.
- Legacy `ecg.service` mutation is danger-gated and requires advanced mode plus explicit site-owner approval.
