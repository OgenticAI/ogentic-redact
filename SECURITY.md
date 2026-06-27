# Security Policy

`ogentic-redact` is a privacy-critical library. We take findings against the redaction engine, the entity-recognition pipeline, or any data-handling invariant very seriously and will treat them as priority-zero work.

## Reporting a vulnerability

**Do not open a public issue or pull request for security findings.**

Email **security@ogenticai.com** with:

- A description of the issue and the affected component (core engine, CLI, Python/Node/Swift bindings, rule-pack loader).
- The version (commit SHA or release tag) you tested against.
- Reproduction steps, ideally including a minimal test case or PoC.
- Your assessment of impact (data exposure, PII leakage, bypass of redaction, etc.).
- Whether you would like public credit when the fix ships.

We will acknowledge receipt within **3 business days** and aim to provide an initial triage within **7 business days**. Coordinated-disclosure timelines are typically **90 days** from the date of acknowledgement, shorter if the issue is being actively exploited and longer by mutual agreement when a fix requires a format change.

## Scope

In scope:

- The Rust crates under `crates/`.
- The Python bindings under `python/`.
- The Node bindings under `packages/ogentic-redact-node/`.
- The Swift bindings under `swift/OgenticRedact/`.
- The rule-pack format and loader under `crates/ogentic-redact-rules/`.

Out of scope at v0.1:

- Network-level adversaries — the v0.1 library performs no network I/O by default.
- Side-channel attacks against the underlying NER model.
- Multi-tenant server deployments (deferred to a server-side roadmap).

## Supported versions

`ogentic-redact` is pre-1.0. Until v0.1.0 is tagged, only the `main` branch is supported.

## PGP

A PGP key for `security@ogenticai.com` will be published alongside the v0.1.0 release.
