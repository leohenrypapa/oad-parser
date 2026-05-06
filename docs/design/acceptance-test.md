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
