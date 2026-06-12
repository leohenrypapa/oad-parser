# OAD parser user manual

## Purpose

The customer runtime pack provides OAD parser operator commands for ECG/CD2 packet replay, live capture, service operation, and JSONL output validation.

## Runtime install

Install the pack into the service runtime environment:

    sudo python3.9 scripts/install_customer_runtime.py --source . --prefix /opt/oad-parser --force

Verify from outside the extracted pack root:

    cd /
    /opt/oad-parser/venv/bin/python -c "import oad_parser; print(oad_parser.__version__)"
    /opt/oad-parser/venv/bin/python -m oad_parser --help
    /opt/oad-parser/venv/bin/python -m oad_parser live --help

## Operator commands

Use the installed interpreter for customer runtime commands:

    /opt/oad-parser/venv/bin/python -m oad_parser inspect-pcap APPROVED_INPUT.pcap
    /opt/oad-parser/venv/bin/python -m oad_parser parse-pcap APPROVED_INPUT.pcap --output ./oad-output.jsonl
    /opt/oad-parser/venv/bin/python -m oad_parser extract-ecg-messages APPROVED_INPUT.pcap --jsonl
    /opt/oad-parser/venv/bin/python -m oad_parser decode-cd2-words 0x100 0x101 0x102
    /opt/oad-parser/venv/bin/python -m oad_parser validate ./oad-output.jsonl
    /opt/oad-parser/venv/bin/python -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface eno1 --max-frames 0

Use only approved, non-sensitive local inputs for troubleshooting.

## Live service

The systemd template runs one service instance per interface:

    sudo systemctl start ecg-parser@eno1.service
    sudo systemctl status ecg-parser@eno1.service --no-pager
    sudo journalctl -u ecg-parser@eno1.service -n 100 --no-pager

Production systemd service commands must not add --max-frames. That option is only for bounded smoke runs outside production service operation.

## Runtime files

- /nsm/ecg/ecg-current.json contains the default SIEM JSON Lines handoff records.
- /var/log/oad-parser/ecg-audit.jsonl is optional audit output only when observability is explicitly enabled.
- /run/oad-parser/ecg-status.json is optional local status output only when observability is explicitly enabled.

The default customer/operator handoff writes only /nsm/ecg/ecg-current.json under /nsm/ecg.

## Troubleshooting

Use docs/TROUBLESHOOTING.md for import, config, service, and output checks.

## Acceptance boundary

This manual does not claim target-site acceptance. Acceptance requires target-host validation of OS, Python, systemd, root/runtime permissions, connected ECG interfaces, storage paths, and SIEM handoff assumptions.
