# Acceptance Test

## Foundation acceptance

The parser-platform foundation is accepted when these pass from the repository root:

    python3 -m oad_parser --help
    python3 -m unittest discover -s oad_parser/tests -p "test_*.py"
    python3 -m oad_parser validate-platform
    scripts/validate_sanitized_release.sh
    scripts/validate_release_readiness.sh

## Customer-safe release acceptance

The customer source pack is accepted when:

- Required handoff docs are present.
- Source-pack generation uses tracked files by default.
- `SOURCE-PACK-MANIFEST.json` contains only customer-safe relative file metadata.
- Private captures, raw payloads, generated reports, caches, archives, and Git internals are excluded.
- Local pcap validation remains internal-only unless reports are separately sanitized.

## Validation meaning

Unit tests and platform validation support parser-platform release readiness. They do not prove operational radar semantic correctness.
## Sprint 2 synthetic 6100 PPS acceptance harness

The Sprint 2 acceptance harness is:

    scripts/run_live_acceptance_6100pps.py

It generates deterministic synthetic Ethernet/IPv4/UDP ECG candidate frames in memory and runs them through the live service pipeline. It does not read PCAP files, capture live traffic, or include operational payloads.

Example short smoke run:

    python3.9 scripts/run_live_acceptance_6100pps.py --duration-seconds 1 --target-pps 100 --output /tmp/oad-live-acceptance.json

Example best-effort target run:

    python3.9 scripts/run_live_acceptance_6100pps.py --duration-seconds 1 --target-pps 6100 --output reports/validation/live-acceptance-6100pps.json

The report includes target PPS, duration, frames generated, frames processed, observed PPS, packets received, packets dropped, packets parsed, ECG candidates, valid ECG payloads, parse warning count, malformed count, emitted records, error records, output drops, writer blocked seconds, rotated files, and pruned files.

Limitations:

- Synthetic in-memory frames only.
- No real PCAP replay.
- No live raw socket capture.
- No operational payloads.
- One-hour operational acceptance must be collected on Oracle Linux Server 9.6 target hardware before production acceptance.

## Sprint 3 release-hardening TEVV matrix

This TEVV matrix defines the release-hardening validation plan for the Sprint 2 live parser foundation before customer handoff.

Scope constraints:

- Python 3.9.2 is the target runtime.
- The implementation remains standard-library-only.
- This matrix does not add parser behavior, radar semantics, or new operational interpretation.
- Real PCAP data, raw operational payloads, secrets, local reports, runtime outputs, and site-sensitive artifacts must not be committed.
- Generated evidence under `reports/` is not committed by default.
- Target-environment evidence may contain site-sensitive details and must remain local unless explicitly sanitized and approved.
- Oracle Linux Server 9.6 target validation is a remaining gate and is not claimed complete by this document.
- Customer-pack validation is a planned gate until the customer-pack generator and validator exist.
- Optional one-hour 6100 PPS acceptance is P1 and is not a blocker for the initial customer runtime/operator handoff package.

### Gate matrix

| Gate | Owner role | Classification | Command or checklist reference | Pass/fail criteria | Evidence path | Limitations or notes |
|---|---|---|---|---|---|---|
| Compile and syntax checks | Python maintainer | Local and CI | `.venv/bin/python -m compileall -q oad_parser scripts` | Exit code 0 | `reports/tevv/compile.txt` when run by future TEVV runner | Syntax only; does not validate runtime environment. |
| Unit tests | Python maintainer | Local and CI | `.venv/bin/python -m unittest discover -s oad_parser/tests -p "test_*.py"` | Exit code 0 and full suite passes | `reports/tests/junit.xml` when run by future TEVV runner | Uses synthetic fixtures only. |
| CLI compatibility | Python maintainer | Local and CI | `.venv/bin/python -m oad_parser --help` and `.venv/bin/python -m oad_parser live --help` | Exit code 0 and expected commands/options remain visible | `reports/validation/cli-help.txt` and `reports/validation/cli-live-help.txt` | Dev-only CLI commands may remain; customer sanitization is handled by docs and package profiles. |
| Config validation | Production maintainer | Local and target | Load `config/ecg_conf.example.ini` through the repo config path | Config loads successfully and target defaults remain documented | `reports/tevv/config-validation.txt` | Does not prove site-specific `/etc/oad-parser/ecg_conf.ini` is valid on target. |
| Parser correctness | Python maintainer | Local and CI | `.venv/bin/python -m oad_parser validate-platform --json` | JSON output includes `"passed": true` | `reports/validation/platform-validation.json` | Synthetic corpus only; no operational radar semantic validation. |
| Malformed ECG handling | Python maintainer | Local and CI | Unit tests covering malformed ECG and live parse-error flow | Malformed frames produce expected parse warnings/errors without crashing | `reports/tests/junit.xml` | No real payloads are committed. |
| JSONL output contract | Python maintainer | Local and target | Unit tests for live writer/audit writer plus target output inspection | Append-only JSON Lines behavior is preserved for active output and audit output | `reports/tests/junit.xml`; target evidence under `reports/target/` if sanitized | The active output path may use `.json` suffix while containing JSON Lines. |
| Null/unknown policy | Python maintainer | Local and CI | Legacy ECG transformer tests and input/output contract review | Null is used for fields that exist but cannot be parsed; `"unknown"` is reserved for categorical compatibility where required | `reports/tests/junit.xml` | This policy does not create new radar semantics. |
| SHA-256 ECG payload hash policy | Python maintainer | Local and CI | Transformer/hash policy tests | Valid and error ECG records hash the ECG payload, not the full packet byte stream | `reports/tests/junit.xml` | Hashes must not expose raw payload bytes. |
| Non-ECG drop/count behavior | Python maintainer | Local and CI | Classifier, pipeline, and metrics tests | Non-ECG frames are dropped or counted as designed and do not emit ECG records | `reports/tests/junit.xml` | Synthetic frames only. |
| Storage rotation/pruning/high-water/critical threshold | Production maintainer | Local and target | Storage, writer, CLI-live integration, and service tests | Rotation, pruning, high-water blocking, active-file protection, and critical threshold behavior match documented policy | `reports/tests/junit.xml`; target evidence under `reports/target/` if sanitized | Target disk behavior must be validated on Oracle Linux Server 9.6 before operational acceptance. |
| Audit/status behavior | Production maintainer | Local and target | Audit/status writer tests and target output inspection | Audit JSONL and status snapshot are emitted as documented | `reports/tests/junit.xml`; target evidence under `reports/target/` if sanitized | Status file is local status evidence, not the MVP SIEM collection stream. |
| Systemd template static validation | Production maintainer | Local and target | Unit tests for `deploy/systemd/ecg-parser@.service` plus target checklist | Template remains present and statically aligned with docs | `reports/tests/junit.xml`; `reports/target/systemd-validation.md` if sanitized | Root runtime/systemd execution must be validated on target. |
| Filebeat/Elastic handoff docs | SIEM engineer and release engineer | Local doc gate and target handoff | Unit tests and documentation review for `docs/ops/filebeat-elastic-agent-handoff.md` | Parser-owned files and SIEM-owned responsibilities are clearly separated | `reports/tests/junit.xml`; `reports/siem/handoff-validation.md` if sanitized | Filebeat/Elastic Agent 8.17.3 is expected but final version/site config must be confirmed by the SIEM owner. |
| Source-pack hygiene | Release engineer | Local and CI | `.venv/bin/python -m oad_parser create-source-pack --output reports/source-pack/oad-parser-source-pack-smoke.tar.gz --tracked-only --json` and `scripts/check_source_pack_manifest.py` | Source pack builds and manifest checks pass | `reports/source-pack/source-pack-manifest-check.json` | Internal engineering source pack remains separate from the customer runtime/operator handoff pack. |
| Customer-pack hygiene | Release engineer and sanitization reviewer | Planned local gate | Planned `scripts/make_customer_pack.sh` and planned `scripts/validate_customer_pack.py` | Customer pack includes only approved runtime/operator content and excludes internal/dev-only material | `reports/customer-pack/customer-pack-validation.json` | Planned gate until Issue #40 and Issue #41 implement customer-pack generation and validation. |
| 6100 PPS synthetic acceptance | TEVV planner | Local and target-like | `.venv/bin/python scripts/run_live_acceptance_6100pps.py --duration-seconds 1 --target-pps 6100 --output reports/validation/live-acceptance-6100pps.json` | Exit code 0 and report shows target met on a best-effort synthetic basis | `reports/validation/live-acceptance-6100pps.json` | Synthetic acceptance only; does not prove live operational traffic performance. |
| Optional one-hour 6100 PPS acceptance | TEVV planner and production maintainer | Optional target gate | Planned one-hour mode for `scripts/run_live_acceptance_6100pps.py` | Target host completes one-hour synthetic run within documented limitations | `reports/validation/live-acceptance-6100pps-1hr.json` | Optional P1 gate; not a blocker for the initial customer handoff package. |

### Local versus target-environment gates

Local and CI gates are intended to run without root privileges and without site data:

- Compile and syntax checks
- Unit tests
- CLI compatibility
- Config example validation
- Platform validation
- Static systemd template validation
- Static Filebeat/Elastic handoff documentation checks
- Source-pack hygiene
- Planned customer-pack hygiene
- Short synthetic 6100 PPS acceptance

Target-environment gates require Oracle Linux Server 9.6 or a target-like host:

- Python 3.9.2 target validation
- Root runtime validation
- Systemd start, stop, status, and restart behavior
- `/nsm/ecg` ownership, permissions, and output-path behavior
- Connected ECG interface validation for `eno1` through `eno5` as applicable
- Filebeat/Elastic Agent 8.17.3 handoff confirmation by the SIEM owner
- Optional one-hour synthetic 6100 PPS acceptance

### Evidence schema

Future TEVV automation should emit a machine-readable evidence record for each gate with these fields:

| Field | Required | Description |
|---|---|---|
| `command` | Yes | Exact command executed, or checklist identifier for manual target validation. |
| `profile` | Yes | Execution profile, such as `local`, `ci`, `target-oracle`, `siem-handoff`, or `customer-pack`. |
| `start_time` | Yes | UTC start timestamp for the gate. |
| `end_time` | Yes | UTC end timestamp for the gate. |
| `return_code` | Yes | Process return code, or null for checklist-only gates. |
| `status` | Yes | Gate result, such as `passed`, `failed`, `skipped`, or `not_applicable`. |
| `evidence_files` | Yes | List of generated evidence paths. Generated evidence under `reports/` is not committed by default. |
| `limitations` | Yes | Notes describing synthetic-only scope, target-only requirements, skipped gates, or sanitization limits. |

Example evidence paths for future automation:

- `reports/tevv/tevv-report.json`
- `reports/tevv/tevv-report.md`
- `reports/tevv/tevv-evidence-manifest.json`
- `reports/tests/junit.xml`
- `reports/validation/platform-validation.json`
- `reports/validation/live-acceptance-6100pps.json`
- `reports/source-pack/source-pack-manifest-check.json`
- `reports/customer-pack/customer-pack-validation.json`
- `reports/target/target-environment-validation.md`
- `reports/siem/handoff-validation.md`

These paths are generated artifacts and are not committed by default.

### TEVV runner usage

Issue #38 adds the local TEVV suite runner:

    .venv/bin/python scripts/run_tevv_suite.py --profile local --report-dir reports/tevv

The runner emits:

- `reports/tevv/tevv-report.json`
- `reports/tevv/tevv-report.md`
- `reports/tevv/tevv-evidence-manifest.json`

The `target-oracle` profile is available for target-environment context and manual/checklist gates:

    .venv/bin/python scripts/run_tevv_suite.py --profile target-oracle --report-dir reports/tevv-target

The runner does not implement customer-pack generation, customer-pack validation, one-hour 6100 PPS mode, or target root/systemd execution. Customer-pack validation remains `skipped` until Issue #40 and Issue #41 are complete. Generated TEVV evidence under `reports/` is not committed by default.
