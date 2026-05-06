# CD2 parser roadmap

## Purpose

This project currently has a working legacy-compatible ECG/CD2 event extractor. The next target is a layered parser platform that can decode CD2 more directly from the protocol specification and still preserve the existing pcap/live-capture workflow.

## Current baseline

The current operational path is:

    Ethernet/IP/UDP frame -> ECG wrapper -> legacy CD2/radar message extraction -> JSONL -> detectors

That path should remain stable because it already works against the known positive pcap corpus.

## Spec-backed CD2 layer

DC-900-1607F adds requirements below the current ECG payload parser:

- CD2 serial data is transmitted as 13-bit words.
- The idle word is `0001111111111`.
- Receive synchronization starts when one or more idle words are detected.
- A message starts at the first non-idle word after idle synchronization.
- A message ends at the first idle word after message start.
- Data words carry 12 data bits and, when parity is client-visible, one parity bit.
- Receive diagnostics must preserve parity error and EOM error conditions.
- Receive frame size must be configurable per link/profile.
- Data inversion, add/remove parity, and error screening are link behaviors, not hard-coded parser assumptions.
- Link option metadata from Table 2-1 is tracked separately from parser behavior so manual-derived values can be tested without over-modeling runtime state.

## Implementation status

Implemented in `oad_parser.parsers.cd2`:

- `Cd2LinkConfig`
- `Cd2Word`
- `Cd2Frame`
- idle-word detection
- 13-bit MSB-first byte-stream extraction
- 13-bit message framing from idle synchronization
- parity calculation and validation with configurable odd/even mode
- receive-frame-size EOM detection
- data inversion handling
- spec-layout client data-area word extraction
- backward-compatible legacy helper preservation
- manual provenance metadata for CD2 constants
- Table 2-1 link option metadata in `oad_parser.protocols.cd2_link_options`

## Next increments

1. Add a profile file format for per-link parser configuration.
2. Add a CLI command such as `decode-cd2-words` for raw hex/word troubleshooting.
3. Add a decoder registry for radar message families: CD-2, CD-ASR, MAR, RTQC, and future site-specific formats.
4. Add golden vectors from sanitized captures and hand-built protocol examples.
5. Use DC-900-1602 to model the generic Protogate client/ICP header and command/response behavior.

## Scope guard

DC-900-1607F defines the CD2 protocol and link behavior. It does not fully define every field in every radar message variant. Radar semantic decoding should remain evidence-based: legacy parser behavior, sanitized corpus validation, site profiles, and additional authoritative message references.
