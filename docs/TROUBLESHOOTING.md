# Troubleshooting

## Python cannot import oad_parser

The customer runtime must be installed before service use:

    sudo python3.9 scripts/install_customer_runtime.py --source . --prefix /opt/oad-parser --force

Then verify from outside the extracted pack root:

    cd /
    /opt/oad-parser/venv/bin/python -c "import oad_parser; print(oad_parser.__version__)"

If this fails, reinstall the runtime pack and confirm Python is at least 3.9.2.

## Customer help shows unexpected development commands

Run:

    /opt/oad-parser/venv/bin/python -m oad_parser --help

The customer pack should show only operator commands. If development-only commands appear, stop and request a regenerated customer pack.

## Legacy ecg.service stack trace

A stack trace that shows this command is from the legacy target-host service, not from the packaged OAD Parser runtime:

    /usr/bin/python3 /usr/bin/ecg.py eno4

Common legacy trace locations include `receive_net_frames` and `process_frame` inside `/usr/bin/ecg.py`. Treat that as a site service conflict until proven otherwise. Confirm the active service command:

    systemctl cat ecg.service --no-pager || true
    systemctl cat ecg-parser@eno4.service --no-pager || true

The expected OAD Parser command is:

    /opt/oad-parser/venv/bin/python -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface eno4

If site authority approves replacement on interface `eno4`, stop the legacy service before starting the OAD Parser template instance:

    sudo systemctl stop ecg.service || true
    sudo systemctl disable ecg.service || true
    sudo systemctl start ecg-parser@eno4.service
    sudo systemctl status ecg-parser@eno4.service --no-pager

## Systemd service does not start

Check the installed service command:

    systemctl cat ecg-parser@eno1.service

Expected interpreter:

    /opt/oad-parser/venv/bin/python

Check logs:

    sudo journalctl -u ecg-parser@eno1.service -n 100 --no-pager

## Configuration missing or invalid

Confirm the site config exists:

    test -f /etc/oad-parser/ecg_conf.ini

Confirm the selected interface is configured and physically connected to approved ECG traffic.

## Output files missing

Confirm /nsm/ecg exists and is writable by the service runtime:

    ls -ld /nsm/ecg

Expected default file after live operation:

- /nsm/ecg/ecg-current.json

Optional observability files appear only when explicitly enabled:

- /var/log/oad-parser/ecg-audit.jsonl
- /run/oad-parser/ecg-status.json

## Bounded live smoke check

A non-production smoke check can run with max frames set to zero:

    /opt/oad-parser/venv/bin/python -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface eno1 --max-frames 0

Do not add --max-frames to the production systemd template.
