# AI Context for OAD Parser Continuation

## Python compatibility

Maintain compatibility with Python 3.9.2 or newer. Avoid Python 3.10-only runtime features such as dataclass `slots=True`, unguarded PEP 604 annotation evaluation, and `match`/`case`.

## Purpose

This file defines safe context for AI-assisted continuation of the OAD parser platform. Use it to avoid over-claiming parser semantics or leaking local operational artifacts.

## Authority order

Use this order when resolving conflicts:

1. Current source code and tests in `oad_parser/`
2. `START_HERE.md`
3. `README.md`
4. `docs/release/CUSTOMER_HANDOFF.md`
5. `docs/release/RELEASE_CHECKLIST.md`
6. `docs/design/TRACEABILITY_MATRIX.md`
7. `docs/adr/0001-platform-foundation-scope.md`
8. Other design notes, which may be historical context

## Hard prohibitions

Do not invent radar message semantics.

Do not treat `beacon-candidate` as authoritative.

Do not use private pcap filenames, observed IP addresses, ports, local paths, or operator machine details as customer-facing evidence.

Do not claim that synthetic fixtures, golden fixtures, corpus comparisons, or `validate-platform` prove operational semantic correctness.

Do not add captures, raw payloads, generated JSONL, generated corpus reports, archives, caches, or secrets to the repository or source pack.

## Current release meaning

This release is a parser-platform foundation. Validation proves that the package, command surface, fixture generation, regression checks, and source-pack guardrails work together on controlled inputs.

Validation does not prove that radar plot fields are operationally correct for real systems.

## Acceptable evidence for semantic expansion

New semantic decoding work needs at least one of the following:

- Approved sanitized captures with explicit release authority
- Authoritative message-format references
- Customer-provided expected outputs
- Human-reviewed golden vectors with traceability

If that evidence is unavailable, keep work at the framing, extraction, registry, regression, or documentation layer.

## Safe AI tasks

- Improve tests for existing behavior without changing semantics
- Improve documentation clarity and release hygiene
- Add source-pack safety checks
- Add customer-safe validation summaries
- Refactor internals when tests preserve behavior
- Add explicit TODOs for semantic work that requires approved evidence

## Stop conditions

Stop and request approved data or human decision when a task asks for:

- New authoritative radar field meanings
- Claims about operational correctness
- Use of private captures or unsanitized reports
- Release of local paths, packet names, addresses, or traffic observations

Maintain compatibility with Python 3.9.2 or newer. Avoid Python 3.10-only runtime features such as dataclass slots=True and match/case.
