# Filebeat and Elastic Agent handoff

This document describes the MVP handoff boundary between the OAD ECG live parser and Filebeat or Elastic Agent.

## Version assumption

The MVP handoff assumes:

    Elastic Agent or Filebeat 8.17.3
    Logstash downstream collection

This repository does not provide site-specific Elastic Agent, Filebeat, or Logstash configuration.

## MVP collection scope

MVP central collection uses append-style files only:

    /nsm/ecg/ecg-current.json
    /var/log/oad-parser/ecg-audit.jsonl

Do not centrally collect this local-only file for MVP:

    /run/oad-parser/ecg-status.json

`ecg-status.json` is replaced as one local JSON object for operator checks. If central status ingestion is required later, add status snapshots to `ecg-audit.jsonl` or add a separate append-style `ecg-status.jsonl`.

## Active event output

The active runtime event file is:

    /nsm/ecg/ecg-current.json

Important: this file keeps the `.json` suffix for legacy/runtime familiarity, but the content is JSON Lines. Each line is one complete JSON object.

Parser records may include:

    ecg_event
    ecg_parse_error

Valid ECG events may include a `parse_warnings` list. Warnings do not convert the event into `ecg_parse_error`.

## Audit output

The audit output file is:

    /var/log/oad-parser/ecg-audit.jsonl

This file is JSON Lines. Each line is one complete JSON object with `record_type` equal to `ecg_audit`.

Audit is intended for aggregate operational evidence such as startup, shutdown, storage pruning, writer block, critical storage, and status-summary style events. The parser should not emit one audit record per parse warning by default.

## Local status output

The local status file is:

    /run/oad-parser/ecg-status.json

This is a single JSON object replaced by the parser. It is not JSON Lines and is not part of MVP central collection.

The status file is intended for local operator inspection.

## Rotation and pruning behavior

The active event output remains:

    /nsm/ecg/ecg-current.json

Closed rotated event files use UTC timestamped JSONL names:

    /nsm/ecg/ecg-current-YYYYmmddTHHMMSSZ.jsonl

If a rotated filename already exists, a numeric suffix is appended:

    /nsm/ecg/ecg-current-YYYYmmddTHHMMSSZ-0001.jsonl

Storage protection prunes only closed rotated output files. It must not delete:

    /nsm/ecg/ecg-current.json
    /var/log/oad-parser/ecg-audit.jsonl
    /run/oad-parser/ecg-status.json
    unrelated operator files

## Parser and SIEM ownership boundary

Parser-owned behavior:

    Create append-style event JSONL records
    Create append-style audit JSONL records
    Maintain local status JSON
    Rotate and prune closed parser output files
    Avoid secrets, raw operational payload dumps, and site-specific values in repository docs

Filebeat or Elastic Agent owned behavior:

    Tail append-style files
    Track file offsets
    Forward records downstream
    Apply site-managed certificates, endpoints, credentials, and enrollment settings

Logstash or SIEM owned behavior:

    Parse downstream records
    Route records to site indexes
    Apply site-specific enrichment, retention, dashboards, and alerting

## Sanitization rule

Do not commit any of the following to this repository:

    Elastic enrollment tokens
    API keys
    Logstash hosts
    Certificates or private keys
    Site-specific index names
    Site IP addresses or hostnames
    Operational packet captures
    Raw operational ECG payloads

## Example operator checks

Check active output is JSON Lines:

    sudo tail -n 5 /nsm/ecg/ecg-current.json

Check audit output is JSON Lines:

    sudo tail -n 20 /var/log/oad-parser/ecg-audit.jsonl

Check local status:

    sudo cat /run/oad-parser/ecg-status.json

Check service logs for one interface:

    sudo journalctl -u ecg-parser@eno1.service -n 100 --no-pager

## Handoff validation checklist

Before enabling central collection, verify:

    /nsm/ecg/ecg-current.json exists or will be created by live service
    /nsm/ecg/ecg-current.json is parsed as JSON Lines, not as one JSON document
    /var/log/oad-parser/ecg-audit.jsonl is parsed as JSON Lines
    /run/oad-parser/ecg-status.json is not configured for MVP central collection
    downstream Logstash ownership and index routing are documented outside this repository
    no secrets or site-specific endpoints are committed to this repository

## Sprint 2 SIEM handoff boundary

The parser owns these output files:

- `/nsm/ecg/ecg-current.json`
  - JSON Lines active output despite the `.json` suffix.
- `/var/log/oad-parser/ecg-audit.jsonl`
  - Audit JSON Lines.
- `/run/oad-parser/ecg-status.json`
  - Local status snapshot; not the primary MVP central collection stream.

Filebeat/Elastic Agent 8.17.3 remains the expected customer assumption, but final version and site-specific configuration must be confirmed by the SIEM owner. Do not commit SIEM endpoints, tokens, certificates, private keys, hostnames, IPs, index names, or other site-specific values.

## Target validation reference

Use `docs/release/target-environment-validation.md` during target handoff.

The parser owns the default SIEM handoff file `/nsm/ecg/ecg-current.json`; audit and status files are disabled for the operator default and, when explicitly enabled, should use non-handoff paths such as `/var/log/oad-parser` and `/run/oad-parser`. The SIEM owner owns Filebeat/Elastic Agent version confirmation, endpoint, index, certificate, token, pipeline, and deployment configuration. Filebeat/Elastic Agent 8.17.3 remains the expected assumption until the SIEM owner confirms the final site version and configuration.

## ECG SIEM handoff contract

The default live ECG operator handoff is a single newline-delimited JSON file at /nsm/ecg/ecg-current.json. The .json suffix is retained for the legacy/operator path, but each line is one JSON object. Rotation is disabled by default, and audit/status files are not written under /nsm/ecg by default. Enable rotation or observability only by explicit config.
