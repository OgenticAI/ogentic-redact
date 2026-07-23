# ADR-0002: Stack — Rust Core with Bindings; Detection Belongs to Shield

| Field      | Value                                      |
|------------|--------------------------------------------|
| **Number** | 0002                                       |
| **Status** | Accepted                                   |
| **Date**   | 2026-07-21                                 |
| **Ticket** | [OGE-1177](https://linear.app/ogenticai/issue/OGE-1177) |
| **Deciders** | David (CTO)                              |
| **Consulted** | ADR-0001 (token format), OGE-934 (demo design), OGE-1230 (Shield span integration), OGE-1188 (test vectors) |

---

## Context and Problem Statement

OGE-1177 was raised because three sources disagreed about what this library is:

- the Linear v0.1 milestone — "Rust core + Python/Node/Swift bindings; crates.io + PyPI + npm";
- repo `CLAUDE.md` §2 — "Python OSS library, extends Microsoft Presidio, PyPI";
- the OGE-934 demo design — Python `Redactor(reversible=True)` + FastMCP.

The ticket observed that "these cannot both be built."

**They were both built anyway**, and both merged to `main` under the v0.1 GA milestone (2026-07-17). Note: the release pipeline (`release.yml`) fires only on a `v*` tag, and no tag has ever been pushed — so nothing is published to crates.io, PyPI or npm. The divergence lives in `main`, not in any registry.

### What is actually in the tree

| Surface | Detection engine | Token format emitted |
|---|---|---|
| Rust core, vault API (`redact`/`unredact`) | EMAIL byte-scan | `<<EMAIL_0>>` |
| Rust core, one-way (`redact_one_way`) | EMAIL/PHONE/SSN byte-scan | `[EMAIL_1]` |
| Python `stream.py` (OGE-1200) | **Presidio + spaCy** | `<<ENTITY_TYPE_N>>` |
| Python `Redactor` (OGE-1274) | caller-supplied spans | `[RTKN_3a7f9c12ab01]` |

Two further facts settle the question of which stack "won":

1. **The Python package does not use the Rust core.** `python/ogentic_redact/*.py` imports exactly one symbol from the extension module — `__version__`. The PyO3 module exports `redact` and `unredact`; nothing in the Python package calls them. `pip install ogentic-redact` yields a Presidio library with a Rust extension attached that supplies a version string.

2. **ADR-0001 is not implemented by anything.** It is `Status: Accepted` (2026-07-16) and specifies a fifth format, `[[CATEGORY_nn]]` — double brackets, zero-padded, starting at `01`, with defined escaping for literal `[[`. No surface emits it.

So F0 was never decided. It was answered twice, in parallel, and both answers were merged.

### The reframing

The choice is not "Rust vs Python." It is **what Redact's detection engine is** — and the project brief already answers that:

> Redact redacts — reversible on-device redaction with vault-persisted mappings. **The production-workflow surface that builds on Shield's classification.**

together with OGE-1230, `[REDACT-INT-SHIELD] Integration: consume Shield classification spans`.

Redact is not a detector. Detection is `ogentic-shield`'s job. Redact's job is span → token substitution, vault persistence, per-call salt, and reversible restoration.

Seen that way the Rust core is not a weak redactor — it is a **correctly-scoped** one whose built-in byte-scanner is a development convenience. The anomaly is `stream.py` importing Presidio and spaCy: that is Redact duplicating Shield's responsibility, and it is the sole reason the Python and Rust surfaces have different capabilities.

---

## Decision

**Rust-core-with-bindings.**

### 1. The core owns the redaction algorithm, not detection

`ogentic-redact-core` owns: span → token substitution, token grammar, per-call salt, vault records, `unredact`, and overlap resolution (REDACT-R5). This is pure algorithm — no ML, no model weights, no Python runtime. It is small, fast, embeddable, and is the only form of this library that can target iOS/Swift and `wasm32`.

### 2. Detection is out of scope for this library

Spans arrive from one of:

- `ogentic-shield` (OGE-1230) — the supported production path;
- the caller, supplied directly;
- the built-in byte-scanner — **a development and demo convenience only.**

The built-in scanner MUST be documented as such everywhere it is user-visible. It MUST NOT be presented as "the redactor." Its current coverage (EMAIL, and PHONE/SSN on the one-way path) is not a bug to be fixed by growing it toward Presidio parity; growing it is explicitly a non-goal.

### 3. Python is a binding, not a parallel implementation

`python/ogentic_redact` becomes a thin binding over the Rust core. The Presidio/spaCy path in `stream.py` is either rewritten over the core, or renamed and explicitly scoped as a standalone convenience detector that is not the library's redaction engine.

**This is sequenced behind OGE-1230** — see Consequences.

### 4. `CLAUDE.md` §2 is superseded

"Python OSS library … Extends Microsoft Presidio for entity recognition" is withdrawn. Presidio is not a dependency of this library's redaction path; where entity recognition is needed it comes from Shield. §2 must be rewritten to describe the Rust workspace, and its `Commands` block — still `# (fill in once the build system is initialised)` — must be filled in.

### 5. Enforcement — the part ADR-0001 lacked

An accepted ADR that nothing implements is worse than no ADR, because it reads as settled. ADR-0001 has been `Accepted` since 2026-07-16 while five formats coexist.

Therefore this decision is only complete when it is **mechanically enforced**:

- the conformance vector suite (`conformance/vectors.json`) is the enforcement point for the token grammar across every surface, and must be extended to assert the ADR-0001 grammar rather than one of the incumbent formats;
- CI must fail when any surface emits a token that does not match;
- any future ADR in this repo that specifies a wire format MUST name its enforcement mechanism in the ADR itself.

---

## Consequences

### Positive

- One redaction algorithm, one place. The current four-way divergence becomes structurally impossible.
- Swift/iOS and `wasm32` become reachable; under Python-only they are permanently out of reach.
- Sotto Desktop (Tauri, Rust) can link the core directly rather than bundling a Python runtime.
- The shipped FFI crate, Swift binding, and napi binding stop being orphans.

### Negative — accepted with open eyes

- **This would be a capability regression for PyPI users once published.** The current (unpublished) Python path detects everything Presidio detects; over the Rust core alone it detects EMAIL. Nothing is on PyPI yet, so no existing user is affected — but this is the strongest argument for Python-only and it is real for the first release.
- Mitigation, and a hard sequencing constraint: **OGE-1230 (Shield span integration) lands before `stream.py` is touched.** Until Shield can supply spans to the Python surface, removing Presidio would strand users. No ticket may narrow the Python detection surface ahead of OGE-1230.
- The binding matrix (PyO3, napi, C FFI, Swift) is a standing maintenance cost — four release targets and four CI paths, as the 2026-07-20 CI repair demonstrated.

### Neutral

- v0.1 is built and merged to `main` under the divergent behaviour described above, but **not tagged and not published** to any registry. The reconciliation therefore lands *before* the first release tag — there is no shipped artifact to retract and no external consumer to migrate.

---

## Alternatives considered

**Python-only.** Rejected. It forfeits Swift/iOS and wasm permanently, makes Sotto Desktop's on-device story a bundled Python runtime, and discards a working Rust core, FFI crate, and Swift binding. It also would not fix the token-format divergence, which is orthogonal to language choice. Its one genuine merit — no capability regression for future PyPI users — is addressed by the sequencing constraint above.

**Status quo (ship both).** Rejected. It is what produced five token formats and an unimplemented ADR. A token emitted by one surface cannot be unredacted by another, silently — a correctness defect in a shipped GA release.

---

## Follow-ups

- Token-format reconciliation across all surfaces, enforced by conformance vectors — **blocks further R-series work.**
- OGE-1188 `[F3]` to be re-verified: the current vectors pin `[EMAIL_1]`, certifying agreement on a format ADR-0001 rejects.
- OGE-1230 `[REDACT-INT-SHIELD]` is promoted to a prerequisite for any change to the Python detection surface.
- `CLAUDE.md` §2 rewrite and `Commands` block (AC of OGE-1177).
- OGE-934 demo design reconciled to the Rust CLI/FFI path (AC of OGE-1177).
