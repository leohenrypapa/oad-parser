# ADR 0001 - Platform Foundation Scope

## Status

Accepted for the `0.1.0` foundation release.

## Context

The project has reached a clean parser-platform stopping point with unit tests, platform validation, corpus and golden workflows, synthetic fixture generation, release helper scripts, and source-pack generation.

The project does not include approved sanitized operational captures or authoritative message-format evidence sufficient to claim complete radar semantic correctness.

## Decision

The release is scoped as a parser-platform foundation.

The release may claim:

- ECG/CD2 parser-platform structure is present.
- Regression and compatibility workflows are present.
- Source-pack handoff guardrails are present.
- Validation commands pass on controlled inputs.

The release must not claim:

- Authoritative radar message semantics.
- Operational correctness from synthetic fixtures.
- Customer evidence from private captures that are not included and approved for release.

The `beacon-candidate` decoder remains provisional until validated against approved sanitized captures or authoritative message-format references.

## Consequences

Future semantic decoder work must be evidence-driven.

AI-assisted continuation must follow `AI_CONTEXT.md` and must not infer missing radar semantics from historical notes or synthetic fixtures.

Customer handoff should emphasize platform readiness, source-pack safety, and remaining evidence needs.
