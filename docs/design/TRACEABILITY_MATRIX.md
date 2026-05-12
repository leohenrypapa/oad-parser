# Traceability Matrix

| Capability | Primary files | Tests | Validation command | Release status | Confidence and caveat |
|---|---|---|---|---|---|
| CLI entrypoint | `oad_parser/cli.py`, `oad_parser/__main__.py` | `oad_parser/tests/test_cli*.py` | `python3 -m oad_parser --help` | Included | High for command dispatch. |
| ECG envelope extraction | `oad_parser/parsers/ecg.py`, `oad_parser/ingest/*` | `test_ecg*.py`, `test_pcap.py`, `test_ethernet.py` | `python3 -m oad_parser validate-platform` | Included | Foundation behavior only; operational corpus not included. |
| CD2 protocol helpers | `oad_parser/parsers/cd2.py` | `test_cd2.py`, `test_cli_cd2.py` | CD2 CLI tests and unit tests | Included | Protocol framing helpers; not a complete semantic decoder. |
| DC-900-1607F CD2 constants | `oad_parser/protocols/cd2_spec.py`, `oad_parser/protocols/cd2_link_options.py` | `test_protocol_constants.py` | Protocol constant tests and full unit suite | Included | Manual-derived protocol facts only; excludes provisional radar-message semantics. |
| Decoder registry | `oad_parser/decoders/registry.py`, `oad_parser/decoders/cd2_radar.py` | `test_decoders_registry.py`, `test_cli_cd2_decoder.py` | Unit tests | Included | `raw12` is structural; `beacon-candidate` is provisional. |
| Legacy-vs-envelope comparison | `oad_parser/compare.py` | `test_compare.py`, `test_cli_compare.py` | `compare-legacy-envelope` on approved inputs | Included | Regression and compatibility check only. |
| Corpus validation | `oad_parser/corpus.py`, `oad_parser/corpus_report.py` | `test_corpus*.py` | `validate-corpus`, `summarize-corpus-report` | Included | Requires sanitized or approved local corpora. |
| Golden fixtures | `oad_parser/golden.py` | `test_golden.py`, `test_cli_golden.py` | `export-golden-fixture`, `check-golden-fixture` | Included | Drift detection only; not semantic proof. |
| Synthetic fixtures | `oad_parser/fixture_samples.py` | `test_fixture_samples.py`, `test_cli_fixture_samples.py` | `generate-fixture-samples` | Included | Self-consistency and regression only. |
| Platform validation | `oad_parser/platform_validation.py` | `test_platform_validation.py`, `test_cli_platform_validation.py` | `python3 -m oad_parser validate-platform` | Included | End-to-end synthetic health check only. |
| Source-pack generation | `oad_parser/source_pack.py`, `scripts/make_source_pack.sh` | `test_source_pack.py`, `test_cli_source_pack.py` | `scripts/make_source_pack.sh` | Included | Customer-safe metadata and tracked-only default. |
| Release guardrails | `scripts/validate_sanitized_release.sh`, `scripts/validate_release_readiness.sh`, `docs/release/*` | Script syntax checks | Release checklist commands | Included | Handoff hygiene guardrail; not a security certification. |

## Live ECG parser production MVP traceability

Related GitLab issues: #1 through #8.

This section maps the production live ECG parser MVP requirements to planned implementation areas. It is intentionally traceability-only and does not implement live runtime behavior.

| Requirement | Planned area | Planned issue coverage | Evidence expectation |
|---|---|---|---|
| Preserve existing bounded parser, pcap replay, validation, and source-pack behavior. | CLI, config, tests | #1, #2 | Existing tests pass; compatibility guard tests cover command visibility and bounded capture behavior. |
| Add production live command beside existing capture command. | CLI, live service | Later live CLI issue | Existing capture remains bounded; production service enters through separate live command. |
| Support configured Linux interfaces including eno1 through eno5. | Live config, systemd | Live config and systemd issues | Example config and ecg-parser@.service document interface instance model. |
| Inspect Ethernet/IPv4/UDP frames from interface traffic. | Ingest, classifier | #6 | Synthetic frame tests validate UDP/IPv4 classification without root socket access. |
| Drop non-ECG from normal output and count it in metrics. | Classifier, metrics | #6 | Metrics tests cover non_ipv4_or_non_udp and non_ecg counters. |
| Emit error records for malformed ECG-looking packets. | ECG envelope parser, transformer | #7, #8 | Malformed ECG-looking fixtures produce ecg_parse_error records. |
| Preserve legacy field names where applicable. | Legacy transformer | #8 | Transformer tests validate legacy-compatible field names. |
| Write runtime output as JSONL to /nsm/ecg/ecg-current.json. | Output writer | Later writer issue | Writer tests validate one JSON object per line and active file naming. |
| Document that ecg-current.json has JSONL behavior. | Operator docs, output docs | Later docs issue | README and operator guide explicitly state one JSON object per line. |
| Keep CSV disabled for MVP. | Config, output | Live config and writer issues | Config tests confirm output_csv is false by default. |
| Use UTC @timestamp based on packet or event timestamp. | Records, transformer | Live records and transformer issues | Timestamp tests validate UTC Z behavior where live schema requires it. |
| Use JSON null for existing fields that cannot be parsed. | Transformer | #8 | Transformer tests validate None serialization for known unparsed fields. |
| Use unknown only for categorical compatibility fields. | Transformer | #8 | Transformer tests validate unknown is limited to categorical fields such as message_type or site_id. |
| Use SHA-256 of ECG payload for valid and error ECG records. | Transformer | #8 | Hash tests validate ECG payload hash only, not full frame hash. |
| Keep detector checks configurable and inline. | Config, detector integration | Later detector issue | Detector integration tests validate alert and alert_details fields. |
| Rotate active JSONL output by 900 seconds or 512 MB. | Rotating writer | Later writer issue | Writer tests validate time and size rotation triggers. |
| Prune closed files older than 12 hours and oldest closed files at 75 percent disk use. | Storage policy | Later storage issue | Mocked storage tests validate age and high-water pruning. |
| Never delete active output or active audit file. | Storage policy | Later storage issue | Active-file protection tests validate deletion exclusions. |
| Block writer if pruning cannot lower disk use below high-water threshold. | Storage, service | Later failure behavior issue | Failure behavior tests validate writer_blocked_disk_high and drop counters. |
| Fatal alert or nonzero exit at critical disk threshold, default 95 percent. | Storage, service, audit | Later failure behavior issue | Mocked critical-threshold tests validate fatal audit and nonzero result. |
| Emit audit JSONL and status JSON. | Audit, metrics | Later audit issue | Audit/status tests validate ecg-audit.jsonl and ecg-status.json. |
| Provide Filebeat/Elastic Agent handoff assumptions. | SIEM docs | Later Filebeat docs issue | Handoff doc includes ndjson parser guidance and ownership boundary. |
| Add 6100 PPS peak one-hour acceptance path. | Benchmark, reports | Later benchmark issue | Benchmark command and acceptance report capture received, dropped, parsed, emitted, and malformed counters. |
| Avoid real PCAP, raw operational payloads, secrets, and site-sensitive artifacts in repo. | Fixtures, source-pack, docs | #1 and later source-pack issue | Source-pack tests and docs maintain sanitized artifact policy. |
