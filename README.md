# OAD Parser Customer Runtime

This repository mirrors the current OAD Parser customer runtime and publishes the installable customer pack as a GitHub Release asset.

## Latest customer pack

Release tag:
customer-pack-20260609T215421Z-e4333966af5f

Asset:
oad-parser-customer-runtime-20260609T215421Z-e4333966af5f.tar.gz

SHA256:
4914901ad620956eb1e84d22ad72c1ed6aca8d12be6248fb1735f0898c77cdee

Source commit:
e4333966af5fbc35a8424d1ced239d342a62739c

## Sensor5 live transformer fix marker

The current runtime includes live field projection in:

oad_parser/transformers/legacy_ecg.py

Expected markers:
- PROJECTABLE_RADAR_MESSAGES = {"cd-2", "cd-asr", "mar"}
- def _project_legacy_radar_fields
- fields["range_nm"]
- fields["azimuth_degrees"]
- fields["mode_3_code"]
- fields["altitude_feet"]

## Acceptance boundary

Publication does not claim target-site acceptance. Confirm Sensor5 live output separately before operational closure.
