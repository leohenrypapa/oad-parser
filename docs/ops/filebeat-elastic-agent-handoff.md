# Filebeat and Elastic Agent handoff

This document describes the MVP handoff boundary between the OAD ECG live parser and Filebeat or Elastic Agent.

## Version assumption

The MVP handoff assumes:

    Elastic Agent or Filebeat 8.17.3
    Logstash downstream collection

This repository does not provide site-specific Elastic Agent, Filebeat, or Logstash configuration.

## MVP collection scope

MVP central collection uses one append-style file:

    /nsm/ecg/ecg-current.json

The target parser does not create these legacy compatibility sidecar paths:

    /var/log/oad-parser/ecg-audit.jsonl
    /run/oad-parser/ecg-status.json

If central status ingestion is required later, add a new append-style status stream through an approved change.

## Active event output

The active runtime event file is:

    /nsm/ecg/ecg-current.json

Important: this file keeps the `.json` suffix for legacy/runtime familiarity, but the content is JSON Lines. Each line is one complete JSON object.

Parser records may include:

    ecg_event
    ecg_parse_error

Valid ECG events may include a `parse_warnings` list. Warnings do not convert the event into `ecg_parse_error`.

## Legacy audit/status compatibility paths

The config schema retains legacy path keys:

    /var/log/oad-parser/ecg-audit.jsonl
    /run/oad-parser/ecg-status.json

The live parser loader parses those keys for backward compatibility, but target runtime forces `output_status` off and does not create audit/status sidecars. Operator UI readiness and runbooks must not require those files.

## Rotation and pruning behavior

The active event output remains:

    /nsm/ecg/ecg-current.json

Older designs used UTC timestamped rotated JSONL names:

    /nsm/ecg/ecg-current-YYYYmmddTHHMMSSZ.jsonl

If a rotated filename already existed, a numeric suffix was appended:

    /nsm/ecg/ecg-current-YYYYmmddTHHMMSSZ-0001.jsonl

The target live parser loader parses rotation settings for compatibility, but forces `rotation_enabled` off. The parser must not create rotated JSONL files on the target.

Storage protection must not delete:

    /nsm/ecg/ecg-current.json
    unrelated operator files

## Parser and SIEM ownership boundary

Parser-owned behavior:

    Create append-style event JSONL records
    Keep parser-owned target output limited to /nsm/ecg/ecg-current.json
    Avoid secrets, raw operational payload dumps, and site-specific values in repository docs

Filebeat or Elastic Agent owned behavior:

    Tail /nsm/ecg/ecg-current.json
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

Check sidecars are absent:

    test ! -e /var/log/oad-parser/ecg-audit.jsonl
    test ! -e /run/oad-parser/ecg-status.json
    test -z "$(find /nsm/ecg -maxdepth 1 -name 'ecg-current-*.jsonl' -print -quit)"

Check service logs for one interface:

    sudo journalctl -u ecg-parser@eno2.service -n 100 --no-pager

## Handoff validation checklist

Before enabling central collection, verify:

    /nsm/ecg/ecg-current.json exists or will be created by live service
    /nsm/ecg/ecg-current.json is parsed as JSON Lines, not as one JSON document
    /var/log/oad-parser/ecg-audit.jsonl is not created by the target parser
    /run/oad-parser/ecg-status.json is not created by the target parser
    /nsm/ecg/ecg-current-*.jsonl rotated archives are not created by the target parser
    downstream Logstash ownership and index routing are documented outside this repository
    no secrets or site-specific endpoints are committed to this repository

## Sprint 2 SIEM handoff boundary

The parser owns this output file:

- `/nsm/ecg/ecg-current.json`
  - JSON Lines active output despite the `.json` suffix.

Filebeat/Elastic Agent 8.17.3 remains the expected customer assumption, but final version and site-specific configuration must be confirmed by the SIEM owner. Do not commit SIEM endpoints, tokens, certificates, private keys, hostnames, IPs, index names, or other site-specific values.

## Target validation reference

Use `docs/release/target-environment-validation.md` during target handoff.

The parser owns the default SIEM handoff file `/nsm/ecg/ecg-current.json`; audit/status sidecars and rotated archives are forced off by the target runtime. The SIEM owner owns Filebeat/Elastic Agent version confirmation, endpoint, index, certificate, token, pipeline, and deployment configuration. Filebeat/Elastic Agent 8.17.3 remains the expected assumption until the SIEM owner confirms the final site version and configuration.

## ECG SIEM handoff contract

The default live ECG operator handoff is a single newline-delimited JSON file at /nsm/ecg/ecg-current.json. The .json suffix is retained for the legacy/operator path, but each line is one JSON object. Rotation and audit/status sidecars are forced off by the target parser runtime.

## 2026-06-12 ECG output-volume tuning update

Marker: 2026-06-12 ECG output-volume tuning update

Validated live ECG defaults:

```text
normal_record_sample_rate = 1000
emit_parse_warning_alerts = False
emit_modec_altitude_missing_alerts = False
```

`/nsm/ecg/ecg-current.json` remains JSON Lines. Normal accepted traffic is sampled. Parser warnings remain in `parser.validation.warnings`, but accepted parse warnings and accepted Mode C altitude-missing conditions are not emitted as SIEM alert objects by default.


## 2026-06-12 operator comparison dataset update

Legacy ECG output remains routed by the SIEM owner to dataset radar.oad. OAD ECG output must identify itself as dataset radar.oad.new using `event.dataset` so operators can compare the two streams without mixing records. `data_stream.type` and `data_stream.dataset` are SIEM-managed fields and are suppressed by the parser default field policy unless an explicit target field policy re-enables them. The parser-owned default event file remains /nsm/ecg/ecg-current.json. SIEM routing, namespace, and index or data-stream creation remain SIEM-owner responsibilities.


## Mode 1 analysis policy

For early operator analysis, OAD uses radar.oad.new on eno2 with normal_record_sample_rate=1, emit_parse_warning_alerts=True, and emit_modec_altitude_missing_alerts=True. The only intentional output suppression allowed in this mode is exact duplicate suppression, which must be reflected by parser.duplicate.* and parser.accounting.* fields. Production sampling and non-actionable-wrapper suppression are deferred until analysts approve the policy.

Field-policy v2 must not alias or remove canonical SIEM event fields, parser accounting fields, accounting snapshot-only fields, `record_type`, event kind/category/action, duplicate fields, hash fields, parser validation fields, `event.dataset`, `service.name`, or `alerts`. `data_stream.type` and `data_stream.dataset` are optional SIEM-managed fields. Valid ECG candidates with outer `ecg_message != 1` are emitted as compact rejected metadata records with `parser.validation.drop_reason=ecg_outer_message_not_surveillance`; they are collectible parser-validation evidence, not active standalone cyber alerts.

## Sensor1 dataset split - 2026-06-12

Sensor1 uses a dataset split so operators can compare legacy and OAD output without mixing records.

| Source | Dataset |
|---|---|
| Legacy parser | radar.oad |
| OAD parser | radar.oad.new |

OAD records must include:

- event.dataset = radar.oad.new
- service.name = oad-ecg-parser
- observer.ingress.interface = eno2

If `data_stream.type` or `data_stream.dataset` appear because a target field policy re-enabled them, they must match `logs` and `radar.oad.new` respectively. The repo default parser output omits them because the downstream SIEM can supply data-stream metadata.

Target-side JSON validation proves OAD emits these fields. It does not prove Elastic or Fleet ingestion. SIEM-side confirmation must be performed by an operator or SIEM engineer.
