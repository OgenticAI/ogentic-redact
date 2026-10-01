# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-10-01

First public release. Published to PyPI; crates.io and npm follow once their
registry tokens are configured.

### Privacy and correctness

- Preserve the entire union of overlapping Python detections and select labels
  deterministically; audit counts now describe protected regions.
- Reject unsupported local profile entities before output; empty entity lists
  explicitly disable detection and model loading.
- Bound restored output to 16 MiB and 100,000 mapped occurrences by default, with
  configurable limits. Invalid or failed restoration no longer consumes mappings.
- Refuse existing CLI vault destinations and publish complete owner-only Unix
  vaults without overwriting source files or following destination symlinks.
- Make SQLite fetches read-only, index and bound expiry cleanup, and start TTL
  after writer waits. Count only live mappings when enforcing capacity.
- Default native, Python top-level, Node, C, and Swift redaction results now
  contain only text and a detection count, with no plaintext reversal mapping.
  Use explicit reversible sessions or Python `Redactor(reversible=True)` to
  retain mappings. This intentionally changes the pre-release return shape.
- Preserve exact original values, reserve source token literals, and resolve
  token collisions without overwriting mappings. Python restoration now accepts
  partial LLM responses and substitutes only once.
- Validate Shield response envelopes, source spans and confidence configuration;
  send the provider's plural `profiles` field and preserve category-group policy.
- Buffer finite Python transcript records until finalization and mandatory audit
  acknowledgement before output. Chunk boundaries no longer expose sensitive
  prefixes. Buffer limits fail closed; local model loading never downloads.
- Add mapping deletion and atomic consumption. Python stores also support
  optional expiry/capacity, and failed audited redactions clean up their mapping.
- Preserve all whitespace during Swift/C sentence delivery and use pull-based
  delivery after batch redaction.

### Integration and release

- Fix Swift linking from an independent consumer and add its CI smoke test.
- Exclude checksum manifests from their own input and verify generated checksums.
- Declare and test the actual Rust 1.88 minimum supported compiler.
- Add a validated Rust UTF-8 span API and instance-scoped reversible Node/Swift/C
  APIs. Native mapping identifiers are random and diagnostics omit originals.
- Fix npm CLI v2 configuration and Apple Silicon dependency selection; remove
  duplicate publication, enforce binding-load failures, and test built artifacts.
- Document migration requirements and current limits in `docs/api-guide.md`.

### Added

#### Core library (`ogentic-redact-core`)
- One-way redaction (`redact_one_way`) with `[TYPE_N]` token format
- Reversible redaction (`unredact_one_way`) via in-memory vault
- Span type with `(start, end, entity_type, group)` for precise entity location
- Apache-2.0 license

#### Rule pack loader (`ogentic-redact-rules`)
- Entity-detection rule pack loader and validator

#### CLI (`ogentic-redact`)
- `ogentic-redact` binary: redact files and streams from the command line

#### Python bindings (`ogentic-redact` on PyPI)
- `redact_stream()` — sub-100ms streaming redaction using Presidio + spaCy
- `Redactor` class — one-way and reversible redaction with per-call salt
- `Profile` and `DEFAULT_ENTITY_TYPES` for configurable entity sets
- Category-aware profile defaults (`shield-legal`, `shield-finance`)
- F3 cross-language conformance vectors (15 golden test cases shared with Rust, Node, Swift)
- Property-based determinism and round-trip tests (hypothesis)

#### Node.js bindings (`@ogenticai/redact` on npm)
- napi-rs v2 bindings for `ogentic-redact-core`
- `version()` — returns library version string
- Platform packages: `linux-x64-gnu`, `darwin-arm64`, `win32-x64-msvc`

#### Swift bindings
- `OgenticRedact` Swift Package with C FFI
- `redact()`, `unredact()`, `redactStream()` Swift wrappers
- F3 conformance vectors tested in CI

#### CI / Release
- Full CI pipeline: Rust lint/test/audit/coverage, Python test/coverage, benchmarks
- F3 cross-language conformance suite (Rust, Python, Node, Swift)
- Swift FFI CI (arm64)
- Release pipeline: crates.io + PyPI + npm + signed GitHub Release

[0.1.0]: https://github.com/OgenticAI/ogentic-redact/releases/tag/v0.1.0
