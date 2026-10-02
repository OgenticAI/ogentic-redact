# ADR-0004: One-way separation and lossless restoration

Status: implemented in the pre-release working tree, 2026-09-22.
Amends ADR-0002/ADR-0003 where their descriptions conflict with the contracts below.

## Problem

The audit found that native APIs called one-way returned plaintext mappings,
canonicalized values lost exact original spelling on restore, literal tokens
could alias emitted tokens, and transport chunks escaped before classification
could identify a sensitive value spanning their boundary. These are failures of
the intended privacy and round-trip contracts.

## Corrective decisions

1. Public default native results contain only redacted text and a detection count.
   Explicit reversible sessions return opaque mapping IDs. Raw mapping adapters
   remain explicitly sensitive low-level operations for separate stores/files;
   they are not default outbound results.
2. Token identity uses the exact original string and label. Canonical grouping
   cannot collapse distinct originals into one restoration value. Repeated exact
   strings can still reuse a token. The native HMAC input is label plus exact
   original, replacing ADR-0003's canonicalized-value input.
3. Reserve token-shaped literals in source text before assigning new tokens.
   Extend colliding discriminators until unique, including beyond twelve hex
   digits; do not overwrite an earlier mapping. Restore in one pass without
   scanning inserted originals again.
4. Native mapping IDs are random. Stores expose explicit deletion and atomic
   consumption. Python stores also expose optional expiry and capacity controls.
   Expiry prevents access and is purged on operations; SQLite uses bounded write
   cleanup or explicit maintenance so ordinary reads do not acquire a writer
   lock. This does not imply a secure background erasure service.
5. Classification failure and malformed responses must not be represented as
   an empty successful detection set. Validate offsets, source text when present,
   and confidence before redaction; use the provider's actual profile/group schema.
6. Python transport chunk boundaries do not establish safe classification
   finalization. Buffer one bounded finite record, then classify and acknowledge
   mandatory audit before any output. Live callers submit finalized utterances.
   Swift/C sentence delivery is explicitly batch classification with lazy output.
7. Rust's new span API validates UTF-8 byte boundaries and rejects overlaps.
   Python now protects complete overlap unions, choosing a deterministic label
   by group/start/length/type. Local streaming also protects overlap unions. A single shared policy
   across all language surfaces is subsequent consolidation work.
8. Local detector policies must be supported by the installed analyzer. Reject
   unsupported entities before releasing output; an explicitly empty selection
   performs no detection or model loading. Shield workflow names do not install
   equivalent local recognizers.
9. Restoration defaults to 16 MiB UTF-8 output and 100,000 mapped replacements,
   with configurable budgets and checked preflight. Invalid or excessive output
   leaves mappings available. Consuming restoration validates and builds the
   result before atomic consumption; only one consumer can return successfully.
10. CLI vault publication refuses existing paths and symlinks and uses owner-only
    Unix permissions. A complete vault must be published before redacted stdout.

## Compatibility

The project remains pre-release. Removing default `tokens` / `tokenMap`, changing
native token identity for case/spacing variants, lengthening Python class tokens,
requiring strict classifier fields, and buffering Python records are intentional
behavior changes. Existing stored mappings can still be restored through explicit
mapping helpers because the parser grammar remains compatible. Rebuild bindings
and their native libraries together. See the API guide for migration examples.

## Verification

Regression suites cover no-original default serialization, exact mixed-case and
Unicode restoration, source literals, forced and real token collisions, malformed
classifier replies, scoped deletion/consumption, audit rollback, every two-chunk
split of sample entities, one-character chunks, model absence, and package loading.
No detector is claimed to find every sensitive value. No secure-erasure or
end-to-end sub-100ms unfinished-stream guarantee is introduced.
