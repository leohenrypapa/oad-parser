# Release checklist

## Customer pack checklist

Before handoff, the release owner must confirm:

- Customer pack generation completed.
- Customer pack validation passed.
- CUSTOMER-PACK-MANIFEST.json is present and parseable.
- Manifest hashes and sizes match archive contents.
- Source provenance is present in the manifest.
- The generator script path and hash are truthful where locally verifiable.
- The customer CLI help output excludes development-only commands.
- Customer-included docs do not instruct operators to run omitted development files.
- Runtime import works from outside the extracted pack root after installation.
- The systemd template uses /opt/oad-parser/venv/bin/python.

## Runtime install check

From the extracted customer pack root:

    sudo python3.9 scripts/install_customer_runtime.py --source . --prefix /opt/oad-parser --force

From another directory:

    cd /
    /opt/oad-parser/venv/bin/python -c "import oad_parser; print(oad_parser.__version__)"
    /opt/oad-parser/venv/bin/python -m oad_parser --help
    /opt/oad-parser/venv/bin/python -m oad_parser live --help

## Target-site boundary

Do not mark target-site acceptance complete from customer-pack validation alone. Target-site acceptance requires approved host evidence for Oracle Linux, Python runtime, systemd, connected interfaces, /nsm/ecg storage, default live SIEM handoff output, optional observability output only when enabled, and SIEM handoff assumptions.

## Governance boundary

Do not mark GitLab/platform controls closed from this customer runtime pack batch. Platform controls remain governed by the WSL management control plane.
