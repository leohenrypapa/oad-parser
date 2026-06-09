# Start here

Use this file as the customer/operator entrypoint for the OAD parser runtime pack.

## 1. Extract the customer runtime pack

Extract the pack into a working directory selected by the operator. Do not operate the service directly from that directory.

## 2. Install the runtime package

From the extracted pack root:

    sudo python3.9 scripts/install_customer_runtime.py --source . --prefix /opt/oad-parser --force

This creates /opt/oad-parser/venv and installs the oad_parser package into that runtime environment.

## 3. Verify import and help from another directory

Run these commands outside the extracted pack root:

    cd /
    /opt/oad-parser/venv/bin/python -c "import oad_parser; print(oad_parser.__version__)"
    /opt/oad-parser/venv/bin/python -m oad_parser --help
    /opt/oad-parser/venv/bin/python -m oad_parser live --help

The customer help output should show only operator commands.

## 4. Install the systemd unit

Copy the service template and reload systemd:

    sudo install -m 0644 deploy/systemd/ecg-parser@.service /etc/systemd/system/ecg-parser@.service
    sudo systemctl daemon-reload

The template uses:

    /opt/oad-parser/venv/bin/python -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface %i

## 5. Prepare runtime directories and configuration

Confirm these target paths before starting the service:

- /etc/oad-parser/ecg_conf.ini exists and is site-appropriate.
- /nsm/ecg exists with approved ownership and permissions.
- The selected interface is connected to approved ECG UDP/IPv4 radar traffic.

## 6. Start one interface

Example for eno1:

    sudo systemctl start ecg-parser@eno1.service
    sudo systemctl status ecg-parser@eno1.service --no-pager
    sudo journalctl -u ecg-parser@eno1.service -n 100 --no-pager

Only start interfaces that are physically present and approved for the site.

## 7. Target validation boundary

The customer pack does not claim target-site acceptance by itself. Target validation must be performed on the site host and recorded using docs/release/target-environment-validation.md.
