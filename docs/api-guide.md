# API guide — modes, salt, and the mapping-id lifecycle

This is the cross-surface reference for `ogentic-redact`. It explains the two
redaction modes, the token grammar and salt semantics, and the reversible
`mapping_id` / vault contract — the guarantees an integrator needs before wiring
Redact into a pipeline. Per-surface API reference (generated) is linked in
[§6](#6-generated-api-reference).

> **Scope reminder (ADR-0002).** Redact is *not* a detector. It turns
> **spans → tokens**, persists reversible mappings, and restores them. Spans come
> from [`ogentic-shield`](https://github.com/OgenticAI/ogentic-shield) (the
> production path, OGE-1230) or from the caller. A built-in byte-scanner
> (EMAIL / PHONE / US_SSN) exists as a **development convenience** and is called
> out as such wherever it appears below — it is not "the redactor".

---

## 1. Two modes

| | **One-way** | **Reversible** |
|---|---|---|
| Restores original? | No | Yes |
| What it emits | redacted text | redacted text **+** an opaque `mapping_id` |
| Where the mapping lives | discarded | a separate **mapping store** (never inline) |
| Use when | you only need to strip PII | you need to restore after an LLM round-trip |

One-way is the default. Reversible is explicit — `Redactor(reversible=True)` in
Python, `RedactMode::Reversible` in the Rust core, a `--mapping <file>` on the
CLI, or the `redact.outbound` MCP tool. The mapping is **never** returned inline
alongside the redacted text; that separation is a deliberate architectural
commitment (demo-design §1), so redacted text and its reversal secret are never
collocated after the call returns.

---

## 2. Token grammar

The ecosystem grammar (ADR-0003) is **`[Label_<discriminator>]`**, aligned with
published `ogentic-shield` (e.g. `[Email_3f8a2c1b]`):

```
token          = "[" label "_" discriminator "]"
label          = CamelCase, no underscore   ; EMAIL_ADDRESS→Email, US_SSN→Ssn
discriminator  = 8 lowercase hex            ; extends to 12 on a within-call collision
```

The discriminator is the first 8 hex of `HMAC-SHA256(call_salt, label:canonical_value)`.
Because the per-call salt is mixed in, the same value produces a **different**
token in a different call (see [§3](#3-salt-semantics)). Parsing is unambiguous:
labels never contain `_`, so the single `_` before the hex is the separator.

> **One surface still diverges.** The Python `Redactor` class emits the legacy
> `[RTKN_<12-hex>]` grammar. It is the last holdout of the OGE-1684 unification and
> converges onto `[Label_<hex>]` once Shield span integration lands (OGE-1230);
> until then, tokens minted by `Redactor` interoperate only with `Redactor`. Every
> other surface — Rust core, CLI, MCP, Node, Swift, and the Python `_native`
> functions — emits `[Label_<hex>]`.

---

## 3. Salt semantics

A fresh **128-bit random salt** is generated on every redaction call. Two
consequences:

- **Cross-call unlinkability.** The same value (`alice@example.com`) redacts to a
  *different* token in two independent calls, so an observer cannot correlate
  documents by their tokens.
- **Within-call stability.** Inside a single call the salt is fixed, so the same
  value maps to the same token every time it occurs — a document stays internally
  consistent.

For reproducible output (cross-language conformance vectors, golden tests) each
surface exposes a fixed-salt entry point: `redact_one_way_with_salt` (Rust),
`redact_with_salt` (Python `_native`), `redactWithSalt` (Node),
`redact(_:salt:)` (Swift). Do **not** use a fixed salt in production — it
reintroduces cross-call linkability.

---

## 4. The reversible `mapping_id` / vault lifecycle

Reversible mode stores each call's `token → original` table in a **mapping store**
and hands back an opaque `mapping_id`:

```
redact(text, …reversible…)  ─►  (redacted_text, mapping_id)
                                     │  store: {mapping_id → {token → original}},
                                     │         scoped by matter_id (tenant)
unredact(redacted_text, mapping_id) ─►  original_text
```

Contract:

1. **Opaque handle.** `mapping_id` is the only thing that crosses the wire; the
   plaintext mapping is never returned inline.
2. **Tenant scoping.** Every store/fetch is scoped by a `matter_id` (tenant). A
   `mapping_id` issued for tenant A returns an **error** — never the wrong vault —
   when presented under tenant B (demo-design §6). On the MCP server the tenant is
   bound to the session principal, never a tool argument.
3. **Restoration is scan-then-lookup.** `unredact` scans for `[Label_<hex>]`
   tokens and restores each by exact map lookup — never a blind substring replace —
   so one token's bytes being a substring of another's cannot cause a double
   substitution. Tokens absent from the mapping are left verbatim (a model that
   drops or rewords part of the input still round-trips safely).
4. **Lifetime.** The in-process store lives for the process; the SQLite store
   survives restarts; the CLI persists the mapping to the `--mapping <file>` you
   choose. An unknown or expired `mapping_id` is an error, not a silent pass.

Store implementations: in-process (`InProcessMappingStore` / core `MappingStore`),
on-device SQLite (`SQLiteMappingStore`), or the CLI's JSON `--mapping` file.

---

## 5. Per-surface quickstart

### Rust core

```rust
use ogentic_redact_core::{redact, unredact, MappingStore, RedactMode};

let store = MappingStore::new();
let (redacted, id) = redact("Contact alice@example.com", "default",
                            RedactMode::Reversible, Some(&store))?;
let mapping_id = id.expect("reversible mode returns an id");
let original = unredact(&redacted, &mapping_id, &store)?;
```

One-way, detection included (dev byte-scanner):

```rust
let out = ogentic_redact_core::redact_one_way("Contact alice@example.com");
// out.text == "Contact [Email_…]"; out.tokens maps token → original
```

### CLI

```bash
# redact → stdout, mapping vault → file (reversible via the file)
ogentic-redact report.txt --mapping vault.json > redacted.txt
# restore, byte-for-byte
ogentic-redact unredact redacted.txt --mapping vault.json > restored.txt
```

Without `--mapping` the redaction is one-way. See [redact-demo-design §2](redact-demo-design.md).

### Python

Detection + one-way (core byte-scanner, `[Label_<hex>]`):

```python
import ogentic_redact._native as native
out = native.redact("email alice@example.com, ssn 123-45-6789")
# out["text"]  -> "email [Email_…], ssn [Ssn_…]"
# out["tokens"] -> {token: original}
```

Reversible with caller-supplied spans (`Redactor`, legacy `[RTKN_<hex>]` grammar —
see [§2](#2-token-grammar)):

```python
from ogentic_redact import Redactor, Span

r = Redactor(reversible=True)
text = "Alice Johnson, SSN 123-45-6789, called about her claim."
spans = [Span(start=0, end=13, entity_type="PERSON", group=0),
         Span(start=19, end=30, entity_type="US_SSN", group=0)]
res = r.redact(text, spans)
# res.text       -> "[RTKN_…], SSN [RTKN_…], called about her claim."
# res.mapping_id -> opaque id;  res.vault == {} (deprecated, never inline)
original = r.unredact(res.text, res.mapping_id)
```

`Redactor` takes spans because detection is Shield's job (ADR-0002); pass the
spans Shield returns, or use the `_native` byte-scanner above for a dev demo.

### MCP server (optional `[mcp]` extra)

```bash
pip install 'ogentic-redact[mcp]'
python -m ogentic_redact.mcp          # stdio transport
```

Tools: `redact.outbound(text, profile) -> {redacted, mapping_id}` and
`redact.unredact_response(text, mapping_id) -> str`. The mapping is stored
server-side under the session tenant and never returned inline. See
[redact-demo-design §3](redact-demo-design.md).

### Node.js

```js
const { redact, unredact } = require('@ogenticai/redact')
const { text, tokens } = redact('Contact alice@example.com')
const original = unredact(text, tokens)   // { text, tokens }: see index.d.ts
```

### Swift

```swift
import OgenticRedact

let result = try OgenticRedact.redact("Contact alice@example.com")
let original = try OgenticRedact.unredact(result.text, using: result.tokenMap)
```

---

## 6. Generated API reference

Each surface's symbol-level reference is generated from in-source docs:

| Surface | Source of truth | Hosted at |
|---|---|---|
| Rust core / rules / CLI | rustdoc (`#![deny(missing_docs)]`) | [docs.rs/ogentic-redact-core](https://docs.rs/ogentic-redact-core) *(on first crates.io release)* |
| Python | docstrings + `_native.pyi` stub | rendered from the package |
| Node | `packages/ogentic-redact-node/index.d.ts` (napi-generated) | npm package types |
| Swift | doc comments in `OgenticRedact.swift` | Swift-DocC |

Build the Rust reference locally:

```bash
cargo doc --no-deps --workspace --open
```

CI enforces that rustdoc builds with **no warnings** (`RUSTDOCFLAGS="-D warnings"`),
so the reference cannot silently rot.

> **Publishing status.** docs.rs builds automatically on the first crates.io
> release; nothing is published to any registry yet (no `v*` tag). Until then the
> canonical reference is the in-tree source and `cargo doc` above.
