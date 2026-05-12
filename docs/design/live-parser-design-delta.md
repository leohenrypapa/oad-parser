# OAD ECG live parser baseline and design delta

Generated: 2026-05-12T14:37:49Z

Related GitLab issue: #1

## Purpose

This document captures the current repository behavior before adding the production live ECG parser path.

The live parser work must be added beside the existing bounded parser and capture workflows. Existing PCAP replay, ECG extraction, CD2 helpers, validation, and source-pack behavior must remain backward compatible unless a later issue explicitly changes that behavior.

## Baseline command inventory

### Top-level command

    usage: oad-parser [-h] [--version]
                      {inspect-pcap,parse-pcap,capture,decode-cd2-words,extract-ecg-messages,compare-legacy-envelope,validate-corpus,summarize-corpus-report,export-golden-fixture,check-golden-fixture,generate-fixture-samples,validate-platform,create-source-pack,validate}
                      ...
    
    OAD parser platform for ECG/CD2 pcap replay, live capture, and JSONL output.
    
    positional arguments:
      {inspect-pcap,parse-pcap,capture,decode-cd2-words,extract-ecg-messages,compare-legacy-envelope,validate-corpus,summarize-corpus-report,export-golden-fixture,check-golden-fixture,generate-fixture-samples,validate-platform,create-source-pack,validate}
        inspect-pcap        Inspect a pcap with stdlib parsing.
        parse-pcap          Replay a pcap and emit JSONL.
        capture             Capture from a Linux interface and emit JSONL.
        decode-cd2-words    Decode and frame CD2 13-bit words for troubleshooting.
        extract-ecg-messages
                            Extract ECG message envelopes from pcap or raw ECG
                            payload bytes.
        compare-legacy-envelope
                            Compare legacy parse_frame output against ECG envelope
                            decoder output.
        validate-corpus     Validate a corpus of pcap and raw ECG payload files
                            against legacy/envelope comparison.
        summarize-corpus-report
                            Print a compact human-readable summary of a validate-
                            corpus JSON report.
        export-golden-fixture
                            Export a golden fixture from a pcap or raw ECG
                            payload.
        check-golden-fixture
                            Check current parser output against a golden fixture.
        generate-fixture-samples
                            Generate deterministic non-sensitive parser fixture
                            samples.
        validate-platform   Run a local end-to-end parser platform health check.
        create-source-pack  Create a safe source-pack tar.gz for AI/developer
                            handoff.
        validate            Validate JSONL output.
    
    optional arguments:
      -h, --help            show this help message and exit
      --version             show program's version number and exit

### parse-pcap

    usage: oad-parser parse-pcap [-h] [--config CONFIG] [--output OUTPUT]
                                 [--schema {ecs,legacy}] [--detect]
                                 [--discovery-window-records DISCOVERY_WINDOW_RECORDS]
                                 [--max-sequence-delta MAX_SEQUENCE_DELTA]
                                 [--max-range-nm MAX_RANGE_NM]
                                 [--max-azimuth-jump-degrees MAX_AZIMUTH_JUMP_DEGREES]
                                 [--max-router-time-delta-seconds MAX_ROUTER_TIME_DELTA_SECONDS]
                                 [--max-radar-time-delta-seconds MAX_RADAR_TIME_DELTA_SECONDS]
                                 [--interface INTERFACE]
                                 input
    
    positional arguments:
      input                 Input pcap path.
    
    optional arguments:
      -h, --help            show this help message and exit
      --config CONFIG       Optional INI config path.
      --output OUTPUT       Output JSONL path.
      --schema {ecs,legacy}
      --detect              Run detector state.
      --discovery-window-records DISCOVERY_WINDOW_RECORDS
      --max-sequence-delta MAX_SEQUENCE_DELTA
      --max-range-nm MAX_RANGE_NM
      --max-azimuth-jump-degrees MAX_AZIMUTH_JUMP_DEGREES
      --max-router-time-delta-seconds MAX_ROUTER_TIME_DELTA_SECONDS
      --max-radar-time-delta-seconds MAX_RADAR_TIME_DELTA_SECONDS
      --interface INTERFACE
                            Observer interface name.

### capture

    usage: oad-parser capture [-h] [--config CONFIG] [--output OUTPUT]
                              [--schema {ecs,legacy}] [--detect]
                              [--discovery-window-records DISCOVERY_WINDOW_RECORDS]
                              [--max-sequence-delta MAX_SEQUENCE_DELTA]
                              [--max-range-nm MAX_RANGE_NM]
                              [--max-azimuth-jump-degrees MAX_AZIMUTH_JUMP_DEGREES]
                              [--max-router-time-delta-seconds MAX_ROUTER_TIME_DELTA_SECONDS]
                              [--max-radar-time-delta-seconds MAX_RADAR_TIME_DELTA_SECONDS]
                              [--interface INTERFACE] [--max-frames MAX_FRAMES]
    
    optional arguments:
      -h, --help            show this help message and exit
      --config CONFIG       Optional INI config path.
      --output OUTPUT       Output JSONL path.
      --schema {ecs,legacy}
      --detect              Run detector state.
      --discovery-window-records DISCOVERY_WINDOW_RECORDS
      --max-sequence-delta MAX_SEQUENCE_DELTA
      --max-range-nm MAX_RANGE_NM
      --max-azimuth-jump-degrees MAX_AZIMUTH_JUMP_DEGREES
      --max-router-time-delta-seconds MAX_ROUTER_TIME_DELTA_SECONDS
      --max-radar-time-delta-seconds MAX_RADAR_TIME_DELTA_SECONDS
      --interface INTERFACE
                            Linux interface to capture from.
      --max-frames MAX_FRAMES
                            Stop after N frames. Required for bounded JSONL
                            output.

### extract-ecg-messages

    usage: oad-parser extract-ecg-messages [-h] [--config CONFIG] [--raw-payload]
                                           [--jsonl] [--output OUTPUT]
                                           [--decoder {raw12,beacon-candidate}]
                                           input
    
    positional arguments:
      input                 Input pcap path, or raw ECG payload path with --raw-
                            payload.
    
    optional arguments:
      -h, --help            show this help message and exit
      --config CONFIG       Optional INI config path.
      --raw-payload         Treat input as raw ECG payload bytes instead of a
                            pcap.
      --jsonl               Emit one JSON object per line.
      --output OUTPUT       Optional output path for JSON or JSONL.
      --decoder {raw12,beacon-candidate}
                            Optionally attach decoder output to each ECG envelope.

### validate

    usage: oad-parser validate [-h] input
    
    positional arguments:
      input       Input JSONL path.
    
    optional arguments:
      -h, --help  show this help message and exit

### validate-platform

    usage: oad-parser validate-platform [-h] [--output-dir OUTPUT_DIR]
                                        [--run-tests] [--json]
    
    optional arguments:
      -h, --help            show this help message and exit
      --output-dir OUTPUT_DIR
                            Optional directory to keep generated validation
                            artifacts.
      --run-tests           Run unittest discovery as part of the platform
                            validation.
      --json                Emit validation report as JSON.

### create-source-pack

    usage: oad-parser create-source-pack [-h] --output OUTPUT [--tracked-only]
                                         [--include-untracked] [--json]
    
    optional arguments:
      -h, --help           show this help message and exit
      --output OUTPUT      Output .tar.gz path.
      --tracked-only       Use tracked-only source-pack mode. This is the default
                           for release safety.
      --include-untracked  Include untracked files. Internal use only; do not use
                           for customer release packs.
      --json               Emit source-pack result as JSON.

## Current bounded behavior to preserve

- Existing pcap replay and bounded capture commands remain available.
- The existing capture command remains bounded and must not silently become the production unbounded service path.
- Existing JSONL validation and platform validation commands remain available.
- Existing source-pack generation remains available.
- Existing tests and golden fixture behavior remain the baseline for regression protection.

## Planned production live command

A later issue will add a separate production live command with the intended shape:

    python3.9 -m oad_parser live --config /etc/oad-parser/ecg_conf.ini --interface eno1

The live command may also support --max-frames as a documented test/smoke option. It is not for production systemd use.

The Sprint 2 service skeleton consumes finite LiveCaptureFrame iterables for unit testing. This keeps raw socket capture, JSONL writing, audit writing, status writing, and systemd integration separated into later implementation issues.

The systemd template will call the same module command by instance name:

    ecg-parser@eno1.service
    ecg-parser@eno2.service

The planned command is intentionally separate from the current bounded capture command.

## Live parser design delta

The production live path will add:

- Continuous live socket parsing for configured interfaces such as eno1 through eno5.
- UDP/IPv4 frame classification.
- ECG discrimination.
- Non-ECG metric counting without normal event output.
- ECG parse-error records for malformed ECG-looking payloads.
- ECG parse warnings remain attached to valid ECG event records as parse_warnings objects with code, message, and parser_stage. Warnings do not convert an event into an ecg_parse_error. LiveMetrics tracks warning count. Audit receives aggregate warning summaries through periodic status, not one audit event per warning by default.
- Legacy-compatible JSONL records written to /nsm/ecg/ecg-current.json. The active file keeps the .json suffix for legacy/runtime familiarity but uses JSON Lines behavior: one JSON object per line.
- Rotated closed output files use UTC timestamped JSONL names such as /nsm/ecg/ecg-current-YYYYmmddTHHMMSSZ.jsonl. Name collisions append a numeric suffix such as -0001.
- The Sprint 2 rotating writer preserves existing active file content by appending records and rotates only non-empty active files.
- UTC @timestamp based on packet or event time.
- JSON null for known fields that exist but cannot be parsed.
- unknown only for categorical legacy compatibility fields.
- SHA-256 of ECG payload for valid and error ECG records.
- Rotating append-mode writer.
- Time and disk based pruning of closed files only. At disk use >=75 percent, prune closed files and block output if pruning cannot reduce below high-water. At disk use >=95 percent, emit best-effort critical audit/status evidence and exit nonzero for systemd failure handling.
- Audit JSONL and local status JSON outputs. MVP Filebeat/Elastic Agent handoff collects append-style files only: /nsm/ecg/ecg-current.json and /nsm/ecg/ecg-audit.jsonl. /nsm/ecg/ecg-status.json remains local-only for operators.
- 6100 PPS peak acceptance evidence.

## Source-pack and artifact policy

The repository must not commit or package:

- Real PCAP data.
- Raw operational payloads.
- Secrets.
- Site-sensitive data.
- Generated live output files.
- Runtime audit logs.
- Runtime status files.
- Benchmark output reports unless explicitly approved as sanitized evidence.

The source pack should include source code, tests, operator documentation, service templates, example configs, and validation scripts. Runtime outputs under /nsm/ecg are operational artifacts and must remain outside the repository.

## Issue sequencing note

Issue #1 is documentation and baseline evidence only. It must not implement live parser behavior.
