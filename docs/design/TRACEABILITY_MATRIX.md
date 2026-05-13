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
| Process ECG candidates through classify, parse, transform, and metrics flow without duplicate Ethernet/UDP parsing. | Classifier, live pipeline, parser, legacy transformer, metrics | Sprint 2 pipeline issue | Pipeline tests validate valid, warning, malformed, and non-ECG paths plus packet metadata reuse. |
| Run a finite synthetic-frame live service skeleton before raw socket production binding. | Live service, classifier, pipeline, metrics | Sprint 2 service issue | Service tests validate synthetic frames, max_frames smoke limit, injectable sinks, audit/status callbacks, and output drop accounting. |
| Capture live raw-socket frames with interface metadata, UTC timestamps, sequence counters, and receive-buffer setting. | Live socket adapter, LiveCaptureFrame | Sprint 2 live capture adapter issue | Socket tests validate timestamped LiveCaptureFrame output, preserved raw-byte iter_live_frames behavior, receive-buffer setsockopt, config helper, and sequence_number metadata. |
| Expose production live service through oad_parser live with config loading, interface override, and max_frames smoke option. | CLI, live config, service, capture adapter, writer, audit/status writers | Sprint 2 live CLI issue | CLI tests validate help output, zero-frame smoke execution without opening raw sockets, config failure behavior, audit/status output, and preservation of bounded capture behavior. |
| Provide interface-specific systemd template service for live parser operations. | Systemd template, operator docs | Sprint 2 systemd issue | Static tests validate ecg-parser@.service, root runtime, Restart=on-failure, restart limits, ExecStart live command, interface instance token, and operator commands. |
| Emit error records for malformed ECG-looking packets. | ECG envelope parser, transformer | #7, #8, Sprint 2 hardening | Malformed ECG-looking fixtures produce ecg_parse_error records without raw payload exposure. |
| Preserve legacy field names where applicable. | Legacy transformer | #8, Sprint 2 warning policy | Transformer tests validate legacy-compatible field names and attach parse_warnings only to valid event records with warnings. |
| Write runtime output as JSONL to /nsm/ecg/ecg-current.json. | Rotating JSONL writer | Sprint 2 writer issue | Writer tests validate append mode, one JSON object per line, active file naming despite the .json suffix, and existing-content preservation. |
| Document that ecg-current.json has JSONL behavior. | Operator docs, output docs | Later docs issue | README and operator guide explicitly state one JSON object per line. |
| Keep CSV disabled for MVP. | Config, output | Live config and writer issues | Config tests confirm output_csv is false by default. |
| Use UTC @timestamp based on packet or event timestamp. | Records, transformer | Live records and transformer issues | Timestamp tests validate UTC Z behavior where live schema requires it. |
| Use JSON null for existing fields that cannot be parsed. | Transformer | #8 | Transformer tests validate None serialization for known unparsed fields. |
| Use unknown only for categorical compatibility fields. | Transformer | #8 | Transformer tests validate unknown is limited to categorical fields such as message_type or site_id. |
| Use SHA-256 of ECG payload for valid and error ECG records. | Transformer | #8 | Hash tests validate ECG payload hash only, not full frame hash. |
| Keep detector checks configurable and inline. | Config, detector integration | Later detector issue | Detector integration tests validate alert and alert_details fields. |
| Rotate active JSONL output by 900 seconds or 512 MB. | Rotating JSONL writer | Sprint 2 writer issue | Writer tests validate time and size rotation triggers and UTC rotated names such as ecg-current-YYYYmmddTHHMMSSZ.jsonl with numeric collision suffixes. |
| Prune closed files older than 12 hours and oldest closed files at 75 percent disk use. | Storage policy | Later storage issue | Mocked storage tests validate age and high-water pruning. |
| Never delete active output or active audit file. | Storage policy | Later storage issue | Active-file protection tests validate deletion exclusions. |
| Block writer if pruning cannot lower disk use below high-water threshold. | Storage, service | Later failure behavior issue | Failure behavior tests validate writer_blocked_disk_high and drop counters. |
| Fatal alert or nonzero exit at critical disk threshold, default 95 percent. | Storage policy, later service/audit integration | Sprint 2 storage issue | Mocked critical-threshold tests validate critical result after best-effort pruning; later service issue converts this to audit/status evidence and nonzero exit. |
| Emit audit JSONL and status JSON. | Audit, metrics | Later audit issue | Audit/status tests validate ecg-audit.jsonl and ecg-status.json. |
| Provide Filebeat/Elastic Agent handoff assumptions. | Filebeat/Elastic handoff docs | Sprint 2 Filebeat handoff issue | Static tests validate Elastic Agent/Filebeat 8.17.3 assumption, append-style collection of ecg-current.json and ecg-audit.jsonl only, local-only ecg-status.json, JSONL suffix behavior, ownership boundary, and no site-specific values. |
| Provide sanitized 6100 PPS best-effort acceptance harness. | Synthetic acceptance script, service, metrics, docs | Sprint 2 acceptance issue | Harness tests validate synthetic-only report schema, target PPS fields, counters, warning/malformed accounting, no PCAP or operational payload use, and documented limitations for Oracle Linux Server 9.6 target evidence. |
| Add 6100 PPS peak one-hour acceptance path. | Benchmark, reports | Later benchmark issue | Benchmark command and acceptance report capture received, dropped, parsed, emitted, and malformed counters. |
| Avoid real PCAP, raw operational payloads, secrets, and site-sensitive artifacts in repo. | Fixtures, source-pack, docs | #1 and later source-pack issue | Source-pack tests and docs maintain sanitized artifact policy. |

## Sprint 3 TEVV coverage addendum

Issue #37 adds release-hardening TEVV coverage in `docs/design/acceptance-test.md`.

The TEVV matrix links release gates to existing implementation and validation areas without changing parser/runtime behavior or adding radar semantics.

| Coverage area | Primary TEVV reference | Implementation or artifact references | Status |
|---|---|---|---|
| Compile/syntax checks | `docs/design/acceptance-test.md` | `oad_parser/`, `scripts/` | Covered by local/CI gate. |
| Unit tests | `docs/design/acceptance-test.md` | `oad_parser/tests/` | Covered by local/CI gate. |
| CLI compatibility | `docs/design/acceptance-test.md` | `oad_parser/cli.py`, `oad_parser/__main__.py` | Covered by local/CI gate. |
| Config validation | `docs/design/acceptance-test.md` | `config/ecg_conf.example.ini`, `oad_parser/config.py` | Covered locally; target config remains a release-hardening gate. |
| Parser correctness | `docs/design/acceptance-test.md` | `oad_parser/parsers/`, `oad_parser/transformers/legacy_ecg.py` | Covered by synthetic platform validation. |
| Malformed ECG handling | `docs/design/acceptance-test.md` | `oad_parser/tests/test_live_parse_errors.py` and related tests | Covered by local tests. |
| JSONL output contract | `docs/design/acceptance-test.md` | `oad_parser/live/writer.py`, `oad_parser/live/audit.py` | Covered locally; target output path validation remains pending. |
| Null/unknown policy | `docs/design/acceptance-test.md` | `oad_parser/transformers/legacy_ecg.py` | Covered by transformer and contract tests. |
| SHA-256 ECG payload hash policy | `docs/design/acceptance-test.md` | `oad_parser/transformers/legacy_ecg.py` | Covered by local tests. |
| Non-ECG drop/count behavior | `docs/design/acceptance-test.md` | `oad_parser/live/classifier.py`, `oad_parser/live/metrics.py`, `oad_parser/live/pipeline.py` | Covered by local tests. |
| Storage rotation/pruning/high-water/critical threshold | `docs/design/acceptance-test.md` | `oad_parser/live/storage.py`, `oad_parser/live/writer.py`, `oad_parser/live/service.py` | Covered locally; target disk behavior remains pending. |
| Audit/status behavior | `docs/design/acceptance-test.md` | `oad_parser/live/audit.py`, `oad_parser/live/service.py` | Covered locally; target output validation remains pending. |
| Systemd template static validation | `docs/design/acceptance-test.md` | `deploy/systemd/ecg-parser@.service`, `docs/ops/systemd-live-parser.md` | Static gate covered; root/systemd target validation remains pending. |
| Filebeat/Elastic handoff docs | `docs/design/acceptance-test.md` | `docs/ops/filebeat-elastic-agent-handoff.md` | Static doc gate covered; SIEM owner confirmation remains pending. |
| Source-pack hygiene | `docs/design/acceptance-test.md` | `oad_parser/source_pack.py`, `scripts/check_source_pack_manifest.py` | Covered by internal engineering source-pack gate. |
| Customer-pack hygiene | `docs/design/acceptance-test.md` | Planned `scripts/make_customer_pack.sh`, planned `scripts/validate_customer_pack.py` | Planned gate for Issue #40 and Issue #41. |
| 6100 PPS synthetic acceptance | `docs/design/acceptance-test.md` | `scripts/run_live_acceptance_6100pps.py` | Covered by short synthetic acceptance gate. |
| Optional one-hour 6100 PPS acceptance | `docs/design/acceptance-test.md` | `scripts/run_live_acceptance_6100pps.py` future optional mode | Optional P1 target gate; not an initial handoff blocker. |
