# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-07-17

### Added

#### Core library (`ogentic-redact-core`)
- One-way redaction (`redact_one_way`) with `[TYPE_N]` token format
- Reversible redaction (`unredact_one_way`) via in-memory vault
- Span type with `(start, end, entity_type, group)` for precise entity location
- Apache-2.0 license, published to [crates.io](https://crates.io/crates/ogentic-redact-core)

#### Rule pack loader (`ogentic-redact-rules`)
- Entity-detection rule pack loader and validator
- Published to [crates.io](https://crates.io/crates/ogentic-redact-rules)

#### CLI (`ogentic-redact`)
- `ogentic-redact` binary: redact files and streams from the command line
- Published to [crates.io](https://crates.io/crates/ogentic-redact)

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
