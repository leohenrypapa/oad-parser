# Input and Output Contract

## Inputs

MVP input order:

1. Sanitized raw byte fixtures.
2. Local private pcap replay.
3. Live interface capture later.

## Pcap policy

Raw pcaps are local/private by default.

Ignored paths and patterns:

- `*.pcap`
- `*.pcapng`
- `samples/private/*`

The repository may keep tiny sanitized fixtures only after review.

## Default output

Default runtime output is JSONL: one normalized event per line.

## Default schema

Default schema is ECS-style dotted keys because the newer Security Onion/Filebeat-oriented legacy script appears to use fields such as:

- `source.ip`
- `source.port`
- `destination.ip`
- `destination.port`

Recommended normalized output fields:

- `@timestamp`
- `source.ip`
- `source.port`
- `destination.ip`
- `destination.port`
- `observer.interface`
- `tot.bytes`
- `artcc`
- `site_id`
- `sequence`
- `sequence_delta`
- `channel`
- `message`
- `type`
- `router_timestamp`
- `router_time_delta`
- `radar_timestamp`
- `radar_time_delta`
- `range_nm`
- `mode_3_code`
- `acp`
- `azimuth_degrees`
- `altitude_feet`
- `fingerprint`
- `alert`
- `alert_details`

## Compatibility schema

Legacy compatibility output should be optional and map dotted ECS fields to older names where required:

- `source.ip` -> `source_ip`
- `destination.ip` -> `destination_ip`
- `source.port` -> `source_port`
- `destination.port` -> `destination_port`
- `observer.interface` -> `interface`

## Sprint 2 live parser I/O alignment

The implemented live parser writes operational outputs under `/nsm/ecg` by default when configured for the target environment:

- `/nsm/ecg/ecg-current.json`
  - Active parser output.
  - Contains JSON Lines records even though the file name ends in `.json`.
- `/nsm/ecg/ecg-audit.jsonl`
  - Append-only audit JSON Lines.
- `/nsm/ecg/ecg-status.json`
  - Local status snapshot.

Config is expected at `/etc/oad-parser/ecg_conf.ini` for target deployment. Systemd execution uses `deploy/systemd/ecg-parser@.service` with instance names such as `ecg-parser@eno1.service`.

This document does not add new radar semantics. `beacon-candidate` remains provisional.
