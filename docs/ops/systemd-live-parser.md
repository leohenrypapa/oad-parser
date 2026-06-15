# Systemd live parser service

This template supports one live ECG parser service instance per configured capture interface.

## Template path

Install the template as:

    /etc/systemd/system/ecg-parser@.service

Repository source path:

    deploy/systemd/ecg-parser@.service

## Runtime command

The template runs:

    /opt/oad-parser/venv/bin/python -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface %i

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

## Runtime install

From the extracted customer pack root, install the runtime package into the service environment:

    sudo python3.9 scripts/install_customer_runtime.py --source . --prefix /opt/oad-parser --force

This makes the service interpreter independent of the current working directory. Verify from another directory:

    cd /
    /opt/oad-parser/venv/bin/python -c "import oad_parser; print(oad_parser.__version__)"
    /opt/oad-parser/venv/bin/python -m oad_parser --help
    /opt/oad-parser/venv/bin/python -m oad_parser live --help

## Install systemd unit

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

## Uninstall and rollback

Stop and disable the interface instance:

    sudo systemctl stop ecg-parser@eno1.service
    sudo systemctl disable ecg-parser@eno1.service

Remove the template unit and reload systemd:

    sudo rm -f /etc/systemd/system/ecg-parser@.service
    sudo systemctl daemon-reload

Remove the installed runtime only after preserving any needed evidence:

    sudo rm -rf /opt/oad-parser

The `/nsm/ecg` directory contains runtime output evidence. Preserve or remove it only under site evidence-retention direction:

    sudo ls -ld /nsm/ecg

## Production note about --max-frames

Do not use `--max-frames` in the production systemd template.

`--max-frames` is only for test and smoke runs such as:

    /opt/oad-parser/venv/bin/python -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface eno1 --max-frames 10

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
    /var/log/oad-parser/ecg-audit.jsonl
    /run/oad-parser/ecg-status.json

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

    /opt/oad-parser/venv/bin/python -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface eno1 --max-frames 0

## Sprint 2 target validation boundary

The systemd template service is implemented at `deploy/systemd/ecg-parser@.service`.

Target validation may document `eno1` through `eno5`, but pass/fail validation applies only to connected ECG interfaces. For example, `ecg-parser@eno1.service` is valid only when `eno1` is the selected connected ECG interface.

Systemd validation must confirm:

- `/etc/oad-parser/ecg_conf.ini` exists and is site-appropriate.
- `/nsm/ecg` exists with correct ownership and permissions.
- `/nsm/ecg/ecg-current.json` is written as JSON Lines despite the `.json` suffix.
- `/var/log/oad-parser/ecg-audit.jsonl` is written as audit JSON Lines.
- `/run/oad-parser/ecg-status.json` is written as the local status snapshot.

## Target-environment validation checklist reference

Use `docs/release/target-environment-validation.md` for the target Oracle Linux Server 9.6 validation checklist.

The checklist covers Python 3.9.2, root runtime, `/etc/oad-parser/ecg_conf.ini`, `/nsm/ecg`, connected ECG interface selection, `eno1` through `eno5` examples, `ecg-parser@enoX.service` start/status/stop checks, output file checks, storage behavior validation, and evidence that must not be committed.

### Live MVP detection-scope note

The `oad_parser live` service currently emits parser/transformer records and service health telemetry. Detection configuration flags such as `check_range`, `check_altitude`, `check_azimuth`, `check_site_discovery`, `check_time_delta`, and `check_fingerprint` are retained for parser-profile compatibility and offline/corpus workflows, but they are not an operational live-alerting authority in this pre-site release. Treat live `alert` and `alert_details` fields as legacy-compatible placeholders unless a later release explicitly wires and validates `DetectionEngine` behavior against approved evidence.

### Live record metadata fields

Live JSONL, audit, and status records include `parser_name`, `parser_version`, `record_schema_version`, and `package_profile`. These fields identify the parser release and live-record schema for operator troubleshooting and SIEM ingestion mapping. They do not certify target-site validation or authoritative OAD semantic decoding.

## ECG SIEM handoff contract

The default live ECG operator handoff is a single newline-delimited JSON file at /nsm/ecg/ecg-current.json. The .json suffix is retained for the legacy/operator path, but each line is one JSON object. Rotation is disabled by default, and audit/status files are not written under /nsm/ecg by default. Enable rotation or observability only by explicit config.

## 2026-06-12 ECG output-volume tuning update

Marker: 2026-06-12 ECG output-volume tuning update

For validated `eno4` deployment, keep boot persistence disabled until the operator and SIEM owner accept sampled output. The second-patch evidence run intentionally stopped `ecg-parser@eno4.service` after collection to freeze evidence.


## Mode 1 analysis policy

For early operator analysis, OAD uses radar.oad.new on eno2 with normal_record_sample_rate=1, emit_parse_warning_alerts=True, and emit_modec_altitude_missing_alerts=True. The only intentional output suppression allowed in this mode is exact duplicate suppression, which must be reflected by parser.duplicate.* and parser.accounting.* fields. Production sampling and non-actionable-wrapper suppression are deferred until analysts approve the policy.

For offline PCAP replay into the same duplicate-suppressed Mode 1 JSONL shape, use:

    python -m oad_parser replay-pcap-live INPUT.pcap --output mode1-replay.jsonl --interface eno2

Add `--max-frames N` for bounded smoke replay. This command streams the PCAP through the live classifier, live pipeline, and live JSONL writer, then appends a parser_accounting snapshot. It does not run live capture, systemd, storage pruning, or writer blocking.

## Sensor1 current service map - 2026-06-12

| Service | Current role | Expected state during OAD Mode 1 |
|---|---|---|
| ecg-parser@eno2.service | OAD live parser on current site interface | active |
| ecg-parser@eno4.service | historical OAD instance | inactive |
| ecg.service | legacy parser | unchanged unless operator approves side-by-side comparison |

Boot persistence remains disabled unless the operator explicitly approves enabling services.

Legacy was found running /usr/bin/python3 /usr/bin/ecg.py eno4. Therefore, legacy is not a valid side-by-side comparator for current eno2 traffic unless the site approves changing legacy to eno2.
