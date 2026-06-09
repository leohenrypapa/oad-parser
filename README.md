# OAD Parser Customer Runtime

This repository mirrors the current OAD Parser customer runtime and publishes the installable customer pack as a GitHub Release asset.

## Latest customer pack

Release tag:
customer-pack-20260609T212256Z-2921953b7733

Asset:
oad-parser-customer-runtime-20260609T212256Z-2921953b7733.tar.gz

SHA256:
aff21881b539b23abc02ff6ae3997e53a8de1708833aace945ac9621eef5662f

## Sensor5 parser fix marker

The current runtime includes the Sensor5 parser fix in:

oad_parser/parsers/ecg.py

Expected markers:
- record.extra["classification_flags"] = ["rtqc_bit_set"]
- record.fingerprint = sha256(

## Acceptance boundary

Publication does not claim target-site acceptance. Confirm Sensor5 pcap or live-stream smoke separately before operational closure.
