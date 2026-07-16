# ADR-0001: Reversible-Redaction On-The-Wire Format — Token Scheme + Per-Call Salt

| Field      | Value                                      |
|------------|--------------------------------------------|
| **Number** | 0001                                       |
| **Status** | Accepted                                   |
| **Date**   | 2026-07-16                                 |
| **Ticket** | [OGE-1185](https://linear.app/ogenticai/issue/OGE-1185) |
| **Deciders** | David (CTO)                              |
| **Consulted** | OGE-1188 (test vectors), OGE-1192 (threat model), OGE-934 (demo design) |

---

## Context and Problem Statement

`ogentic-redact` implements reversible redaction: it replaces sensitive spans in text with
opaque tokens, stores the original values in a separate vault, and later restores the
originals from the vault using the tokens as keys.

For this round-trip to work correctly the token format and salt scheme must satisfy three
properties simultaneously:

1. **Stability within one call** — if the same value appears twice in one call, both
   occurrences must receive the same token so unredact can replace all occurrences.
2. **Variation across calls** — the same value must produce a *different* token in a
   second, independent call so an observer cannot correlate outputs across calls.
3. **Unambiguous grammar** — tokens must be distinguishable from surrounding text without
   false positives so the unredact pass can locate them reliably.

This ADR specifies the token grammar, the per-call salt algorithm, and the vault record
shape that satisfy these properties.

---

## Decision

### 1. Token Grammar

**Format:** `[[CATEGORY_nn]]`

```
token     = "[[" category "_" counter "]]"
category  = [A-Z_]{2,32}        ; uppercase ASCII letters and underscore only
counter   = [0-9]{2,}           ; zero-padded decimal, minimum 2 digits, starting at 01
```

**Examples:**

```
[[EMAIL_01]]
[[PHONE_01]]
[[PERSON_01]]
[[PERSON_02]]
[[CREDIT_CARD_01]]
```

**Reserved characters and escaping:**

The delimiter sequences `[[` and `]]` are reserved by this format. If the original text
contains a literal `[[` or `]]` that is *not* part of a redaction token, the redactor
MUST escape them before inserting tokens:

| In original text | Escaped form in redacted output |
|-----------------|----------------------------------|
| `[[`            | `\[\[`                           |
| `]]`            | `\]\]`                           |

The unredact pass MUST unescape these sequences after token substitution.

**Rationale for double-bracket syntax:**

Single brackets (`[text]`) collide with Markdown link syntax and are common in prose.
Double brackets (`[[...]]`) are rare in natural language and plain-text documents, making
accidental matches unlikely. The underscore separator between category and counter is
unambiguous because the category alphabet excludes digits.

---

### 2. Per-Call Salt Algorithm

A fresh cryptographically random 16-byte salt is generated once at the start of each
`redact()` call. This salt governs token assignment for the entire call and is stored in
the vault header.

#### 2a. Salt generation

```python
# Python
import os
call_salt: bytes = os.urandom(16)
```

```rust
// Rust
let call_salt: [u8; 16] = rand::random();
```

#### 2b. Canonical value

Before any key derivation, the matched span value is **canonicalized**:

```
canonical_value = whitespace_normalize(value).lower()
```

Where `whitespace_normalize` strips leading/trailing whitespace and collapses internal
runs of whitespace to a single space.

Examples:

| Original span          | Canonical value       |
|------------------------|-----------------------|
| `"  Alice Smith "`     | `"alice smith"`       |
| `"alice@EXAMPLE.COM"`  | `"alice@example.com"` |
| `"+1 (555) 123-4567"`  | `"+1 (555) 123-4567"` |

#### 2c. Token key derivation

For each unique `(category, canonical_value)` pair within a call:

```
token_key = HMAC-SHA256(key=call_salt, msg=category || ":" || canonical_value)
```

The `token_key` is used internally to determine whether two spans should share a token
(same key => same token) and to order the counter assignment (keys are sorted by first
occurrence, counters assigned 01, 02, ...). The `token_key` is **not** stored in the vault
or emitted in any output — it exists only in memory during the call.

#### 2d. Counter assignment

Within one call, counters are assigned per category in order of first occurrence:

```python
counters: dict[str, int] = {}   # category -> next counter
key_to_token: dict[bytes, str] = {}

for each span (in document order):
    key = hmac_sha256(call_salt, category + ":" + canonical_value)
    if key not in key_to_token:
        counters[category] = counters.get(category, 0) + 1
        token = f"[[{category}_{counters[category]:02d}]]"
        key_to_token[key] = token
    replace span with key_to_token[key]
```

**Within-call guarantee:** Two spans with the same `(category, canonical_value)` get the
same token. Two spans with the same category but different canonical values get different
counters.

**Cross-call guarantee:** Because `call_salt` is drawn from a cryptographically random
source, `HMAC-SHA256(call_salt_A, ...)` and `HMAC-SHA256(call_salt_B, ...)` are
independent with overwhelming probability even for identical inputs. Consequently, the
same value produces a different token assignment in a second call.

---

### 3. Vault Record Shape

The vault is a JSON document written separately from the redacted output. It is
identified by a `call_id` (UUIDv4) that is also returned as the `mapping_id` in the MCP
wire format. The vault is **never** returned inline with the redacted text.

#### 3a. Top-level structure

```json
{
  "schema_version": 1,
  "call_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "call_salt": "base64-encoded-16-bytes==",
  "created_at": "2026-07-16T09:42:00Z",
  "entries": { ... }
}
```

| Field            | Type   | Description                                                          |
|------------------|--------|----------------------------------------------------------------------|
| `schema_version` | int    | Format version. Currently `1`. Bump on breaking changes.            |
| `call_id`        | string | UUIDv4. Used as `mapping_id` on the MCP surface.                   |
| `call_salt`      | string | Base64-encoded 16-byte random salt used during this call.           |
| `created_at`     | string | UTC ISO-8601 timestamp of the redaction call.                       |
| `entries`        | object | Map from token string to `VaultEntry` (see §3b).                   |

#### 3b. VaultEntry

```json
"[[EMAIL_01]]": {
  "original": "alice@example.com",
  "category": "EMAIL",
  "canonical": "alice@example.com",
  "spans": [
    { "start": 42, "end": 59 }
  ]
}
```

| Field       | Type         | Description                                                              |
|-------------|--------------|--------------------------------------------------------------------------|
| `original`  | string       | Exact original text, byte-for-byte (including leading/trailing space).   |
| `category`  | string       | Recogniser category (e.g. `"EMAIL"`).                                    |
| `canonical` | string       | Whitespace-normalized, lowercased form used for key derivation.          |
| `spans`     | list[object] | List of `{start, end}` byte offsets (UTF-8) in the *original* text.      |

`spans` lists all positions where this value appeared. When the same value appears
multiple times, all occurrences share one `VaultEntry` and are listed in `spans` in
document order.

`start` is inclusive; `end` is exclusive. Offsets are byte offsets in the UTF-8-encoded
original text, not character offsets.

#### 3c. Complete example

Original text:
```
Alice Smith sent a report to alice@example.com. Alice Smith is the contact.
```

After redaction:
```
[[PERSON_01]] sent a report to [[EMAIL_01]]. [[PERSON_01]] is the contact.
```

Vault:
```json
{
  "schema_version": 1,
  "call_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "call_salt": "dGhpcyBpcyBhIHNhbHQ=",
  "created_at": "2026-07-16T09:42:00Z",
  "entries": {
    "[[PERSON_01]]": {
      "original": "Alice Smith",
      "category": "PERSON",
      "canonical": "alice smith",
      "spans": [
        { "start": 0, "end": 11 },
        { "start": 44, "end": 55 }
      ]
    },
    "[[EMAIL_01]]": {
      "original": "alice@example.com",
      "category": "EMAIL",
      "canonical": "alice@example.com",
      "spans": [
        { "start": 29, "end": 46 }
      ]
    }
  }
}
```

---

### 4. Contrast with ogentic-shield

`ogentic-shield` and `ogentic-redact` solve different problems and must not be conflated.

| Dimension            | ogentic-shield (`shield.redact`)           | ogentic-redact                              |
|----------------------|--------------------------------------------|---------------------------------------------|
| **Mapping location** | Inline in the response body                | Separate vault, never collocated            |
| **Wire format**      | `{redacted_text: str, mapping: dict}`      | `{redacted: str, mapping_id: str}`          |
| **Mapping lifetime** | Ephemeral — caller owns the context        | Persistent — vault survives the call        |
| **Salt scheme**      | Stateless — no per-call randomness         | Per-call random salt                        |
| **Cross-call tokens**| Same input => same token (deterministic)   | Same input => different token across calls  |
| **Primary use case** | Analyze-before-sending (single-turn)       | Send-to-LLM, restore-after-response (multi-turn) |
| **Reversibility**    | Caller-managed (inline mapping)            | Vault-managed, opaque ID                   |

The key architectural commitment from `CLAUDE.md §4`:

> Reversible (tokenised) mode requires `Redactor(reversible=True)` and emits a
> separate vault file — **never inlined**.

Shield's inline mapping is not a simplification of Redact's vault design — it is a
fundamentally different trade-off. The two libraries complement each other; Redact is
not "Shield with persistence."

See also: `docs/redact-demo-design.md §1` for the two-phase demo illustration.

---

### 5. Threat Note: Per-Call Salt vs Cross-Prompt Token-Reversal

#### The threat

An adversary who observes redacted outputs across multiple LLM calls (e.g. by monitoring
a shared LLM endpoint, or by receiving redacted text from multiple calls) may attempt
**cross-prompt correlation**:

1. Observe that `[[EMAIL_01]]` appears in call A and call B.
2. Infer (correctly, with a deterministic scheme) that the same email address was
   redacted in both calls.
3. Use frequency analysis, side-channels, or prior knowledge to narrow down the
   original value.

Without per-call salt, a deterministic token scheme makes step 2 trivial: identical
input => identical token across all calls.

#### The defense

Per-call salt breaks step 2. Because `call_salt` is drawn fresh from a cryptographically
random source for each call:

- The same email address produces `[[EMAIL_01]]` in call A and also `[[EMAIL_01]]` in
  call B — but these two tokens are not linked by their string identity alone.
- An observer cannot confirm, without access to both vaults, that the two `[[EMAIL_01]]`
  tokens refer to the same address. The token string encodes only category and counter,
  not any function of the value.

#### Scope of this defense

This defense applies to **cross-prompt correlation via token strings**. It does not
defend against:

- **Vault exfiltration**: if an attacker obtains the vault, they have the originals.
  Vault access control is a deployment concern, not addressed by this ADR.
- **Content inference from context**: if enough context surrounds a token (e.g., "The
  CEO, `[[PERSON_01]]`, signed the contract"), the original may be inferable. This is
  a recogniser coverage problem, not a token format problem.
- **Timing/size side-channels**: vault size or redaction latency may leak information
  about entity count. Out of scope here.

---

## Consequences

### Positive

- Token grammar is unambiguous and regex-matchable: `\[\[[A-Z_]{2,32}_\d{2,}\]\]`
- Per-call salt makes cross-call correlation via token strings infeasible
- Vault schema is self-describing (`schema_version`, `call_id`, `call_salt`) and
  forward-compatible
- Vault entries include byte-offset spans, enabling span-accurate restoration and future
  diff/highlight features
- Explicit Shield contrast prevents architectural confusion in downstream integrations

### Negative / trade-offs

- Canonical value lowercasing means the token key does not distinguish `"Alice"` from
  `"alice"`. The `original` field preserves the exact form; only the grouping key is
  case-insensitive. This is intentional — the same person should not receive two tokens
  due to capitalisation variation.
- Counter assignment is deterministic within a call (first occurrence wins), but the
  absolute counter value (01 vs 02) depends on document order. Cross-call counter values
  are not meaningful.
- Vault files grow linearly with entity count. No compaction mechanism is specified here;
  that is a storage concern for R-series tickets.

---

## Implementation Notes

This ADR governs the following downstream tickets:

- **OGE-1188 (REDACT-F3)** — spec + golden deterministic test vectors for the
  round-trip. Test vectors must use a fixed `call_salt` (passed as a parameter in test
  mode) to make outputs deterministic.
- **OGE-1192 (REDACT-F4)** — threat model + privacy-guarantee brief. The threat note in
  §5 above is the seed; OGE-1192 expands it.
- **REDACT-R series** — core implementation tickets. The `Redactor` struct in
  `crates/ogentic-redact-core` must implement the token grammar and salt scheme
  described here.

The `schema_version` field enables non-breaking extensions (adding optional fields to
`VaultEntry`) and breaking migrations (bumping the version). Breaking changes to this
format require a new ADR.

---

## Alternatives Considered

### A. UUID tokens (`[[xxxxxxxx-xxxx-...]]`)

Provides guaranteed uniqueness and makes correlation impossible even within one call.
Rejected because: tokens in LLM context would be opaque to the model (category
information helps the model understand what kind of entity was replaced), and the
format is harder to validate visually.

### B. Category-only tokens with sequential global counter (`[[EMAIL_1]]`)

Simpler grammar, no underscore separator needed.
Rejected because: a global sequential counter leaks the total entity count per category
across the document. Zero-padded two-digit minimum counter was chosen for readability;
category-scoped counting is consistent.

### C. Deterministic hash tokens (no per-call salt)

`token = HMAC-SHA256(static_secret, category + ":" + canonical_value)`
Produces stable tokens across calls — useful for "same token always means the same
value" semantics.
Rejected because: it enables cross-prompt correlation (threat in §5). If a use case
genuinely needs cross-call token stability, it should use a named-entity registry, not
this format.

### D. Encrypt-then-encode (AES-GCM ciphertext as token body)

Token embeds the encrypted original, eliminating the vault.
Rejected because: it makes the token order-of-magnitude larger (base64 ciphertext is
long), breaks the "never collocated" architectural commitment, and moves key management
into the hot path.
