# ogentic-redact

[![PyPI](https://img.shields.io/pypi/v/ogentic-redact)](https://pypi.org/project/ogentic-redact/)
[![npm](https://img.shields.io/npm/v/@ogenticai/redact-darwin-arm64)](https://www.npmjs.com/package/@ogenticai/redact-darwin-arm64)
[![Crates.io](https://img.shields.io/crates/v/ogentic-redact)](https://crates.io/crates/ogentic-redact)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/OgenticAI/ogentic-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/OgenticAI/ogentic-redact/actions/workflows/ci.yml)

**Real-time, on-device sensitive-content redaction** — the second step in the OgenticAI privacy pipeline.

---

## What it is

`ogentic-redact` strips PII and other sensitive content from text before it reaches an LLM or any downstream service. It runs entirely on-device by default (no network calls), produces cryptographically isolated redaction tokens, and supports a reversible vault mode so the original content can be restored after the LLM has responded.

### What it is NOT

| It is not… | That's… |
|------------|---------|
| A PII classifier | `ogentic-shield` — run Shield first to decide *what* needs redacting |
| A text synthesiser | `ogentic-convert` — Convert regenerates content from structured data |
| A request router | `ogentic-router` — Router decides *where* a request goes after redaction |
| A compliance audit trail | `ogentic-audit` — Audit records what happened at each step |

---

## Pipeline position

Redact sits between classification (Shield) and routing, feeding a clean text surface to every downstream service:

```
┌─────────┐  classify   ┌────────┐  redact+vault   ┌────────┐
│  Shield │ ──────────► │ Redact │ ──────────────► │ Router │
└─────────┘             └────────┘                 └────────┘
                                                        │
                                            synthesize  ▼
                                                   ┌─────────┐
                                                   │ Convert │
                                                   └─────────┘
                                                        │
                                            audit trail ▼
                                                   ┌───────┐
                                                   │ Audit │
                                                   └───────┘
```

In **Sotto Meeting Mode** (step 2): Shield classifies the meeting transcript, Redact strips PII before the transcript is sent to any LLM for summarisation, and Audit records every redaction event.

---

## Install

**Python (PyPI)**

```bash
pip install ogentic-redact
```

**Node.js (npm)**

```bash
npm install @ogenticai/redact-darwin-arm64   # macOS arm64
# or
npm install @ogenticai/redact-linux-x64-gnu  # Linux x64
# or
npm install @ogenticai/redact-win32-x64-msvc # Windows x64
```

**Rust (Cargo)**

```toml
[dependencies]
ogentic-redact-core = "0.1"
```

---

## Quickstart

### One-way redaction (CLI)

Redaction is non-reversible by default. The CLI redacts on-device — detection uses
the built-in byte-scanner (EMAIL / PHONE / US_SSN), a development convenience;
production spans come from [`ogentic-shield`](https://github.com/OgenticAI/ogentic-shield).

```bash
echo "Send the report to alice@example.com by Friday." | ogentic-redact -
# Send the report to [Email_3f8a2c1b] by Friday.
```

Each native redaction call uses a fresh 128-bit random salt. This reduces cross-call correlation; shortened token discriminators are not a guarantee of global uniqueness. One-way results contain redacted text and a detection count, never a reversal mapping.

### Reversible round-trip

Enable the vault to restore original content after LLM processing:

`Redactor` acts on **spans** — detection is Shield's job (ADR-0002). Pass the spans
Shield returns; the example supplies them directly.

```python
from ogentic_redact import Redactor, Span

redactor = Redactor(reversible=True)

# Step 1 — redact before sending to LLM (spans would come from Shield in production)
text = "Alice Johnson, SSN 123-45-6789, called about her claim."
spans = [
    Span(start=0, end=13, entity_type="PERSON", group=0),
    Span(start=19, end=30, entity_type="US_SSN", group=0),
]
result = redactor.redact(text, spans)
print(result.text)
# [RTKN_…], SSN [RTKN_…], called about her claim.

# Step 2 — send result.text to your LLM (it never sees PII); keep result.mapping_id
llm_response = result.text.replace("called about her claim", "has a pending claim")

# Step 3 — restore original values via the opaque mapping_id
restored = redactor.unredact(llm_response, result.mapping_id)
print(restored)
# Alice Johnson, SSN 123-45-6789, has a pending claim.
```

The token→original mapping is held in a separate **mapping store** and referenced by
the opaque `result.mapping_id` — it is **never returned inline** (`result.vault` is
deprecated and always empty). This is a deliberate architectural commitment:
redacted text and its reversal secret must not be collocated after the call returns.
See the [API guide](docs/api-guide.md) for the full `mapping_id` lifecycle.

---

## Redact vs `shield.redact_document()`

Both libraries can redact text, but they solve different problems:

| Dimension | `ogentic-redact` | `shield.redact_document()` |
|-----------|-----------------|---------------------------|
| **Mapping location** | Separate vault — opaque `mapping_id`, never inline | Inline in response `{"mapping": {...}}` |
| **Reversibility** | Explicit opt-in: `Redactor(reversible=True)` | No — one-way only |
| **Salt / de-correlation** | Per-call random salt; probabilistic cross-call de-correlation | None |
| **Category-aware defaults** | `Profile` system — `DEFAULT_ENTITY_TYPES`, `KNOWN_PROFILES` | Fixed entity set |
| **On-device guarantee** | Default path: zero network calls | Depends on shield configuration |

Use `ogentic-shield` when you need lightweight, inline redaction in a single-shot context where the caller owns the conversation. Use `ogentic-redact` when you need vault isolation, reversibility, or stronger de-correlation guarantees.

---

## Profiles

`ogentic-redact` ships with category-aware redaction profiles tied to Shield workflow profiles. The default covers common PII types; Shield-specific profiles add domain entities:

```python
from ogentic_redact.profile import Profile, DEFAULT_ENTITY_TYPES, KNOWN_PROFILES

# Inspect what's available
print(KNOWN_PROFILES)   # frozenset({'shield-legal', 'shield-finance'})
print(DEFAULT_ENTITY_TYPES)  # ['PERSON', 'EMAIL_ADDRESS', 'US_SSN', ...]

# Load a named profile (e.g. legal adds CASE_NUMBER, BATES_NUMBER)
profile = Profile.from_shield_profile("shield-legal")
print(profile.entity_types)
```

Named profiles describe policy; they do not install local recognizers. Local
streaming validates every requested entity against its analyzer and fails before
output when a recognizer is missing. The stock local analyzer cannot fulfill
`shield-legal`'s CASE_NUMBER/BATES_NUMBER entities; use Shield classification for
that workflow. An explicit empty entity selection performs no detection.

Shield HTTP classification is an explicit optional integration:

```bash
pip install 'ogentic-redact[shield]'
```

`ShieldAdapter` sends the original text to the configured service. Use a local
Shield service for local processing. The `cloud` flag is not a network sandbox
for caller-supplied classifiers; there is no `[cloud]` extra.

### Finalized transcript records

`redact_stream(chunks, profile)` buffers one finite record until its input ends,
then classifies and audits it before yielding redacted chunks. This prevents an
email, phone number, or other entity split across transport chunks from leaking
its prefix. Live integrations should call it for each **finalized utterance**.
The default limits are 100,000 characters and 4,096 chunks; exceeding either
raises without releasing output. Detection still depends on the local model.

Install the streaming model explicitly during setup:

```bash
python -m spacy download en_core_web_sm
```

Runtime initialization never downloads a missing model. See the [API guide](docs/api-guide.md)
for retention controls, native reversible sessions, and the pre-release API migration.

Restoration defaults to a 16 MiB UTF-8 output limit and 100,000 mapped replacements.
Configure larger budgets explicitly when needed. Invalid or oversized responses
leave the mapping available for retry. Source builds require Rust 1.88 or newer.

---

## Status

**v0.1.0 — pre-release (nothing published to a registry yet)**

The core redaction engine, the Python/Node/Swift bindings, the CLI, and the optional MCP server are implemented. No `v*` release has been tagged, so nothing is on PyPI / npm / crates.io yet; the public API may change before v1.0.

Supported platforms: macOS arm64, Linux x64, Windows x64.

---

## Further reading

- [API guide — modes, salt, and the mapping-id lifecycle](docs/api-guide.md)
- [ADR-0004 — Privacy contract corrections and migration](docs/adr/0004-privacy-contract-hardening.md)
- [ADR-0003 — Ecosystem token grammar (Shield-aligned)](docs/adr/0003-ecosystem-token-grammar.md)
- [ADR-0002 — Stack: Rust core with bindings](docs/adr/0002-stack-rust-core-with-bindings.md)
- [Threat model](docs/threat-model.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
