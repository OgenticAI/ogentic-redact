# ADR-0003: Ecosystem Token Grammar — Shield-Aligned `[Label_<salted-hex>]`

| Field      | Value                                      |
|------------|--------------------------------------------|
| **Number** | 0003                                       |
| **Status** | Accepted                                   |
| **Date**   | 2026-07-23                                 |
| **Ticket** | [OGE-1684](https://linear.app/ogenticai/issue/OGE-1684) |
| **Deciders** | David (CTO)                              |
| **Supersedes** | [ADR-0001](0001-reversible-redaction-token-format.md) (token grammar + salt algorithm) |
| **Consulted** | [ADR-0002](0002-stack-rust-core-with-bindings.md) §5 (enforcement), OGE-1230 (Shield spans), OGE-1188 (vectors), OGE-1192 (threat model) |

---

## Context and Problem Statement

Five incompatible token grammars are live in `main`, and a sixth ships in the published `ogentic-shield`
(v0.6.1 on PyPI). A token emitted by one surface silently fails to unredact through another — for a
reversible-redaction library, a correctness defect. Nothing in `ogentic-redact` is published yet (no `v*`
tag; `release.yml` fires only on such a tag — verified 2026-07-23), so this is a **pre-release**
reconciliation with no external consumer to migrate. It must land before the first tag and it blocks the
R-series (every core/binding ticket emits or parses a token).

The incumbents:

| Surface | Grammar |
|---|---|
| Rust core vault `redact` | `<<TYPE_0>>` (0-indexed) |
| Rust core one-way `redact_one_way` | `[TYPE_1]` (1-indexed) |
| Python `stream.py` | `<<TYPE_N>>` (1-indexed) |
| Python `Redactor` | `[RTKN_<12hex sha256(salt:val:type)>]` |
| Node / Swift / FFI | `[TYPE_1]` (the FFI crate carries its own copy of detect+emit) |
| ADR-0001 (accepted, unimplemented) | `[[CATEGORY_nn]]` |
| **`ogentic-shield` v0.6.1 (published)** | `[Label_<6hex sha256(salt+val)>]`, e.g. `[Email_3f8a2c]` |

Two facts constrain the choice. **(a)** ADR-0002 scoped detection out of Redact: spans arrive from Shield
(OGE-1230) or the caller; Redact owns span→token, vault, salt, unredact. So the grammar embeds *Shield's*
category vocabulary. **(b)** Shield is published and Redact is not — so alignment costs Shield nothing and
Redact everything, which is the correct direction to bend.

## Decision

### 1. Token grammar

```
token          = "[" label "_" discriminator "]"
label          = [A-Z][A-Za-z]{0,31}     ; CamelCase, contains NO underscore
discriminator  = [0-9a-f]{8}             ; lowercase hex (may extend — see §4)
parse regex    = \[([A-Za-z]+)_([0-9a-f]{8,})\]
```

Examples: `[Email_3f8a2c1b]`, `[Ssn_9be10422]`, `[Person_a3f9c1b2]`, `[CreditCard_0d4e8817]`.

This matches `ogentic-shield`'s shipped shape (`redaction.py:170`). Single brackets, a CamelCase label,
an underscore, a lowercase-hex discriminator, close bracket.

**Why this parses unambiguously.** Shield's labels never contain an underscore — `_label_for` maps entity
types to CamelCase (`EMAIL_ADDRESS`→`Email`, `US_SSN`→`Ssn`), and the fallback is
`entity_type.title().replace("_", "")`. So the single `_` in a token is always the label/discriminator
separator, and the discriminator charset (`[0-9a-f]`) is disjoint from the uppercase start of a label. No
backtracking, no ambiguity — unlike a grammar whose category itself contains underscores (e.g. `US_SSN`).

### 2. Label derivation

Redact receives Shield category strings (`EMAIL_ADDRESS`, `US_SSN`, …) and maps them to labels via the
**shared category→label table** (see §6). Unknown categories fall back to `title-case, underscores removed`.

### 3. Discriminator derivation

```
discriminator = first 8 hex chars of  HMAC-SHA256(key = call_salt, msg = label || ":" || canonical_value)
canonical_value = whitespace-normalized, lowercased value        (grouping form; the vault stores exact bytes)
call_salt       = 16 random bytes, fresh per redaction call, stored in the vault header
```

- **The salt reaches the emitted token** (via the hex), so the same value produces a *different* token in a
  different call. This is the cross-call-unlinkability property ADR-0001 claimed but did not deliver.
- **HMAC, not plain SHA-256** (Shield's current `sha256(salt+value)`), and the label is part of the message
  so two categories sharing a value do not collide. This is an internal improvement invisible at the grammar
  level: tokens are per-call salted and vaults are ephemeral, so no persisted consumer depends on the exact
  hex — only the *grammar shape* must match Shield for pipeline coherence. (Shield may adopt HMAC in a later
  minor version; not required by this ADR.)
- **Within-call stability**: the same `(canonical_value, label)` in one call yields the same token, so
  unredact restores every occurrence.

### 4. Collision handling

8 hex = 32 bits. On a within-call collision (two distinct `(label, canonical_value)` pairs producing the
same 8-hex discriminator), the colliding token extends to **12 hex** for that entry; the parse regex already
accepts `{8,}`. Implementations MUST detect and resolve this deterministically, not emit a duplicate token.

### 5. Modes

- **Default (category-visible):** label names the category — `[Email_…]` — for LLM output quality.
- **Opaque (opt-in):** a fixed generic label — `[Redacted_…]` — for callers who cannot tolerate category
  leakage. Same grammar, same derivation; only the label is replaced. Selected per call, not global.

One-way and reversible redaction share this one grammar. One-way simply keeps no vault (the token is
terminal); it still emits `[Label_<salted-hex>]`.

### 6. The category→label table is a shared, conformance-tested fixture

The mapping from Shield category (`EMAIL_ADDRESS`) to label (`Email`) is the coupling point between two
independently-released packages. It ships as a JSON fixture that both repos load, and a conformance test
asserts Redact's table equals Shield's (`shield/src/ogentic_shield/redaction.py:32-57`,
`CATEGORY_LABEL_TO_ENTITY_TYPES`). Absent that test the labels drift silently and re-create the divergence
this ADR closes.

### 7. Unredaction is scan-and-lookup, not blind replace

Every surface unredacts by scanning the text for the parse regex and doing an exact vault-key lookup — the
approach the Rust vault path already uses (`core/src/lib.rs:255-404`). The naive `str.replace`-over-vault
loops on the other surfaces are removed: they double-substitute when one token's bytes are a substring of
another's, a bug independent of grammar. A token that parses but is absent from the vault is left verbatim.

### 8. Escaping

Because the discriminator is 32 random bits, source text would have to contain a literal
`[Label_<8 matching hex>]` to be mistaken for a token — negligible. Implementations SHOULD still escape a
literal `[` that begins a token-shaped run in source text (and unescape on restore) for the pathological
case; this is a SHOULD, not the load-bearing defense the ambiguous ADR-0001 grammar required.

### 9. Enforcement (per ADR-0002 §5)

This grammar is real only when mechanically enforced:

- `conformance/vectors.json` is the enforcement point across all surfaces and is re-pinned to this grammar.
- Vectors run under a **fixed test salt** so the salted hex is reproducible for byte-exact cross-language
  assertion; vectors also assert the round-trip (`unredact(redact(x)) == x`) and the cross-call property
  (same input, two salts → different tokens, both restore).
- CI fails when any surface emits a non-conforming token — demonstrated by a deliberate temporary break.

## Consequences

### Positive
- One token grammar across the Redact surfaces and coherent with the published Shield pipeline.
- The cross-call-unlinkability guarantee actually holds (salt in the token), and the claim in the threat
  model becomes true rather than aspirational.
- Scan-and-lookup unredaction removes the substring-collision bug class.
- The vault record gains `call_salt` + per-entry `label`/`canonical`, realizing ADR-0001 §3.

### Negative / costs
- The Rust core gains `sha2`/`hmac`/`rand` dependencies (it had none).
- A new cross-repo coupling: the category→label table. Mitigated by making it a conformance-tested shared
  fixture (§6) — but it is a coupling that did not exist before and must be maintained.
- Salted hex is longer than a counter and marginally more prone to being rewritten by an LLM mid-response;
  mitigated by the recognizable `[Label_…]` marker and a deployment-time system-prompt "copy verbatim"
  instruction (out of scope here, noted for the integration guide).

### Neutral
- v0.1 is merged to `main` under the old divergence but unpublished; this reconciliation lands before the
  first `v*` tag. No shipped artifact to retract.

## Alternatives considered

- **`[[UPPER_SNAKE_hex]]`** (double-bracket, Shield category verbatim): viable, but not aligned with the
  published Shield grammar and its underscore-bearing category is marginally harder to parse. Rejected by the
  align-to-Shield decision.
- **Numeric counter `[Label_01]`**: shortest and most LLM-robust, but linkable across calls — the same value
  is the same token every call. Rejected; cross-call unlinkability is in the threat model.
- **Opaque/self-contained (AES ciphertext in the token, Presidio-`encrypt` style)**: reversible without a
  vault, no category leak — but LLM-hostile and long. Retained as the opt-in opaque *mode* (§5), not the default.
- **Realistic surrogates** (fake-but-plausible values): highest LLM utility, but harder and riskier to
  reverse. Deferred to a future ADR.

## Follow-ups

- Implement across core + bindings + conformance (OGE-1684 acceptance criteria).
- OGE-1188 `[F3]` vectors move off `[EMAIL_1]` onto this grammar.
- `stream.py` migration is gated behind OGE-1230 (do not narrow the Python detection surface first — ADR-0002).
- Optional: propose Shield adopt HMAC derivation in a later minor version for exact-byte parity.
