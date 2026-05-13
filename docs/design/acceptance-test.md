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
