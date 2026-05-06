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
