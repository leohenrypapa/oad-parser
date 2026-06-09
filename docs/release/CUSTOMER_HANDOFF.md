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
