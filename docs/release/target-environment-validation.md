# Target environment validation

This checklist is for target Oracle Linux Server 9.6 validation. It is not completed by customer-pack generation alone.

## Preconditions

- Customer runtime pack is already validated by the release owner.
- Site config exists at /etc/oad-parser/ecg_conf.ini.
- Runtime output directory exists at /nsm/ecg.
- Selected ECG interface is physically present and connected to approved traffic.
- Operator has approval to run root/systemd validation on the target host.

## Legacy service conflict check

Before validating OAD Parser, confirm the target host is not still running the legacy ECG script service:

    systemctl cat ecg.service --no-pager || true
    systemctl status ecg.service --no-pager || true

If the service command contains `/usr/bin/ecg.py`, it is legacy target-host software and not the OAD Parser customer runtime. Do not treat stack traces from `/usr/bin/ecg.py` as OAD Parser failures. Stop or isolate that legacy service before starting `ecg-parser@<interface>.service`, according to site authority direction:

    sudo systemctl stop ecg.service || true
    sudo systemctl disable ecg.service || true

Record only sanitized evidence that the active OAD Parser service command uses `/opt/oad-parser/venv/bin/python -m oad_parser live`.

## Runtime install

From the extracted customer pack root:

    sudo python3.9 scripts/install_customer_runtime.py --source . --prefix /opt/oad-parser --force

Verify from outside the extracted pack root:

    cd /
    /opt/oad-parser/venv/bin/python -c "import oad_parser; print(oad_parser.__version__)"
    /opt/oad-parser/venv/bin/python -m oad_parser --help
    /opt/oad-parser/venv/bin/python -m oad_parser live --help

## Systemd validation

Install and inspect the unit:

    sudo install -m 0644 deploy/systemd/ecg-parser@.service /etc/systemd/system/ecg-parser@.service
    sudo systemctl daemon-reload
    systemctl cat ecg-parser@eno1.service

Start only an approved connected interface:

    sudo systemctl start ecg-parser@eno1.service
    sudo systemctl status ecg-parser@eno1.service --no-pager
    sudo journalctl -u ecg-parser@eno1.service -n 100 --no-pager

Stop after validation if directed:

    sudo systemctl stop ecg-parser@eno1.service

## Bounded non-production smoke check

When approved, a bounded smoke check may be run outside production systemd operation:

    sudo /opt/oad-parser/venv/bin/python -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface eno1 --max-frames 1

## Evidence to collect

- Python version used for runtime installation.
- Runtime import/help output from outside the extracted pack root.
- systemctl cat output showing the /opt/oad-parser venv interpreter.
- Service start/status/log snippets.
- /nsm/ecg file listing and permissions.
- Confirmation that ecg-current.json is JSON Lines.
- SIEM owner confirmation for Filebeat or Elastic Agent handoff assumptions.

## Claims not made by this checklist template

This file is a validation template. It does not itself claim target-site acceptance, platform-control closure, or SIEM production acceptance.
