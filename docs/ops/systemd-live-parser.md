# Systemd live parser service

This template supports one live ECG parser service instance per configured capture interface.

## Template path

Install the template as:

    /etc/systemd/system/ecg-parser@.service

Repository source path:

    deploy/systemd/ecg-parser@.service

## Runtime command

The template runs:

    /usr/bin/python3.9 -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface %i

The `%i` token is the systemd instance name. For example, `ecg-parser@eno1.service` runs the live parser for interface `eno1`.

## Runtime user

The MVP service runs as `root`.

Reason: Linux raw socket capture normally requires root privileges or equivalent packet-capture capabilities. Non-root capability hardening is out of scope for this Sprint 2 systemd template.

## Supported interface instances

Expected live parser instances are interface-specific, for example:

    ecg-parser@eno1.service
    ecg-parser@eno2.service
    ecg-parser@eno3.service
    ecg-parser@eno4.service
    ecg-parser@eno5.service

Only enable interfaces that are physically present and assigned to ECG UDP/IPv4 radar traffic.

## Install

Copy the template:

    sudo install -m 0644 deploy/systemd/ecg-parser@.service /etc/systemd/system/ecg-parser@.service

Reload systemd:

    sudo systemctl daemon-reload

## Start one interface

Start `eno1`:

    sudo systemctl start ecg-parser@eno1.service

Check status:

    sudo systemctl status ecg-parser@eno1.service --no-pager

View logs:

    sudo journalctl -u ecg-parser@eno1.service -n 100 --no-pager

## Enable one interface at boot

Enable `eno1`:

    sudo systemctl enable ecg-parser@eno1.service

Start after enabling:

    sudo systemctl start ecg-parser@eno1.service

## Stop one interface

Stop `eno1`:

    sudo systemctl stop ecg-parser@eno1.service

Disable at boot:

    sudo systemctl disable ecg-parser@eno1.service

## Production note about --max-frames

Do not use `--max-frames` in the production systemd template.

`--max-frames` is only for test and smoke runs such as:

    python3.9 -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface eno1 --max-frames 10

## Restart behavior

The service uses:

    Restart=on-failure
    RestartSec=10s
    StartLimitIntervalSec=300
    StartLimitBurst=5

This allows systemd to mark the service failed when the parser exits nonzero, while reducing the risk of a tight restart loop.

## Runtime files

The live parser uses these default runtime files:

    /nsm/ecg/ecg-current.json
    /nsm/ecg/ecg-audit.jsonl
    /nsm/ecg/ecg-status.json

`ecg-current.json` keeps the `.json` suffix for legacy/runtime familiarity, but it is JSON Lines: one JSON object per line.

`ecg-status.json` is local-only for MVP operator inspection.

## Verification

After installation, use:

    sudo systemctl daemon-reload
    systemctl cat ecg-parser@eno1.service
    sudo systemctl start ecg-parser@eno1.service
    sudo systemctl status ecg-parser@eno1.service --no-pager
    sudo journalctl -u ecg-parser@eno1.service -n 100 --no-pager

For a non-production smoke run without systemd:

    python3.9 -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface eno1 --max-frames 0
