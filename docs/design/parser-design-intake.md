# Parser Design Intake

## Names

- Python package: `oad_parser`
- Canonical invocation: `python3 -m oad_parser`
- Project scope: OAD parser platform for packet replay, ECG parsing, CD2 protocol helpers, detector scaffolding, regression checks, and JSONL-oriented output workflows.

## Working assumptions

- Preserve compatibility-oriented behavior through tests and comparison workflows.
- Treat authoritative CD2 references as protocol-layer inputs, not as proof of ECG wrapper or radar semantic details.
- Keep raw captures and generated reports out of the repository and customer source pack.
- Treat semantic decoder expansion as evidence-gated future work.

## Foundation goal

Provide a package and CLI that can support approved capture replay, ECG/CD2 extraction, controlled comparison, corpus regression, golden fixtures, and safe source-pack handoff.

## Out of scope for the foundation release

- Authoritative operational radar semantic decoding.
- Private capture release.
- System service deployment.
- Dashboard or downstream SIEM deployment.
