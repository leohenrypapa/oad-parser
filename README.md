# OAD parser customer runtime pack

This repository builds the OAD parser customer runtime/operator pack. The customer pack is a runtime deliverable for ECG/CD2 parser operation and troubleshooting. It is separate from internal development, corpus, golden-fixture, source-pack, CI, and platform-control workflows.

## Customer runtime install model

The runtime must be installed into a service-owned Python environment. Do not rely on running from the extracted pack directory.

From the extracted customer pack root:

    sudo python3.9 scripts/install_customer_runtime.py --source . --prefix /opt/oad-parser --force

Verify from outside the extracted pack root:

    cd /
    /opt/oad-parser/venv/bin/python -c "import oad_parser; print(oad_parser.__version__)"
    /opt/oad-parser/venv/bin/python -m oad_parser --help
    /opt/oad-parser/venv/bin/python -m oad_parser live --help

The systemd unit uses the installed interpreter:

    /opt/oad-parser/venv/bin/python -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface %i

## Customer/operator commands

The customer runtime profile exposes operator commands only:

- inspect-pcap
- parse-pcap
- capture
- live
- decode-cd2-words
- extract-ecg-messages
- compare-legacy-envelope
- validate

Development-only corpus, golden-fixture, source-pack, fixture-generation, and platform-validation commands are intentionally not exposed in the customer runtime pack.

## Common paths

- Config: /etc/oad-parser/ecg_conf.ini
- Default SIEM handoff: /nsm/ecg/ecg-current.json
- Optional audit output, only when explicitly enabled: /var/log/oad-parser/ecg-audit.jsonl
- Optional local status output, only when explicitly enabled: /run/oad-parser/ecg-status.json
- Systemd unit source in pack: deploy/systemd/ecg-parser@.service

The ecg-current.json file uses a .json suffix for legacy/runtime familiarity, but it is JSON Lines: one JSON object per line. The default operator handoff writes only this active file under /nsm/ecg.

## Operator documentation

Read these customer-included files before installation or validation:

1. START_HERE.md
2. USER_MANUAL.md
3. docs/ops/systemd-live-parser.md
4. docs/ops/filebeat-elastic-agent-handoff.md
5. docs/TROUBLESHOOTING.md
6. docs/release/CUSTOMER_HANDOFF.md
7. docs/release/target-environment-validation.md

## Validation boundary

Local customer-pack validation proves archive structure, manifest consistency, customer CLI surface, documentation consistency, and runtime importability through the approved venv install model. It does not prove target-site acceptance.

Target-site acceptance must be run separately on the approved target host with site-owned configuration, connected interfaces, root/systemd checks, storage checks, and SIEM handoff checks.

## Source and customer command surfaces

This source checkout intentionally includes developer validation, governance, CI, and source-pack commands. The customer runtime pack is the authoritative external runtime surface and intentionally excludes development-only tests, CI, source-pack tooling, platform-control tooling, AI handoff context, and local validation reports.
