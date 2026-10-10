# Privacy guarantees and trust boundaries

Updated 2026-09-22 for the pre-release privacy hardening changes. This document
describes technical behavior, not a compliance certification.

## Scope

Redact replaces classified spans before text reaches a downstream system. The
production boundary is Shield/caller classification followed by redaction.
The native email/phone/SSN scanner is a development convenience. The Python local
streaming adapter retains Presidio/spaCy detection. Neither path guarantees
complete identification of sensitive content or resistance to adversarial text.

Callers, configured classifiers, and mapping-store implementations are trusted.
The library cannot protect originals that callers transmit or log before
redaction, or recover safety after compromise of the calling process.

## Default one-way mode

Public native default and fixed-salt functions return redacted text and a
non-sensitive count. They neither return nor retain reversal mappings. Python
`Redactor()` returns placeholders with no mapping ID and an empty deprecated
`vault` field. C/Swift sentence delivery retains only the redacted document.

This is an API/state guarantee, not secure memory erasure. Original input exists
in caller memory and transient processing buffers; allocators, crash dumps,
swapping and backups are outside this guarantee. A process compromise may still
recover caller-owned originals or unzeroed memory. Recognizer misses and
quasi-identifiers can also leave identifying information in output.

Internal adapters `redact_to_mapping` and Python `_native._redact_to_mapping`
explicitly produce sensitive mappings for separate store/file integration.
They are not default one-way output and must not be serialized downstream with
the text. Their use creates the same protection obligations as reversible mode.

## Explicit reversible mode

Use Python `Redactor(reversible=True)`, Rust `RedactMode::Reversible`,
Node/Swift `ReversibleRedactor`, an explicit C redactor handle, the CLI
`--mapping` option, or MCP's outbound/reversal pair. Public application results
contain redacted text plus an opaque mapping ID, not the mapping itself. The
CLI writes its mapping separately from standard output.

Native IDs contain fresh 128-bit random values. Python IDs use UUID4. Node, Swift,
and C mappings belong to their creating instance/handle. Python and MCP stores
also scope operations by trusted `matter_id`/tenant. Rust's standalone store
has no tenant parameter: server applications must isolate stores or enforce
authentication/authorization before looking up an ID. A random ID is not a
substitute for access control.

Python store interfaces support `delete` and atomic `consume`; native stores
support `delete` and atomic `unredact_and_delete`. Removing a mapping prevents
future library lookups. Callers should delete or consume when a round trip is
finished, or release the entire session/store. Python's configurable TTL denies
access after expiry; SQLite cleanup runs in bounded batches on writes or explicit
maintenance, and reads never require a cleanup write. This is not a background
timer. Optional capacity bounds reject new writes rather than evict
live mappings. Defaults do not impose a TTL or capacity limit.

SQLite and CLI mappings remain plaintext. New Python SQLite files and Unix CLI
vault files are created with owner-only permissions. CLI vault creation refuses
existing paths (including symlinks) and publishes a complete file before emitting
redacted stdout. Existing SQLite permissions are not silently changed.
Callers remain responsible for encryption, access controls, backup exclusion,
key management, and retention outside the running library. Deletion does not
guarantee erasure from snapshots, backups, or external storage implementations.
Loss of the mapping makes restoration impossible through the library.

Restoration checks configured output and replacement limits before rendering.
Defaults are 16 MiB of restored UTF-8 output and 100,000 mapped occurrences.
Malformed UTF-8 or exceeded budgets fail without consuming a mapping. Consuming
restoration deletes atomically after successful rendering; concurrent consumers
have one successful result. Custom stores must keep records immutable under each
mapping ID. These budgets do not bound original input size or total vault bytes.

## Identity, token syntax and residual correlation

Native tokens use a random per-call salt and HMAC-derived discriminator.
Within-call assignment keeps distinct exact originals separate, handles token
collisions, and avoids source literals that already resemble emitted tokens.
Repeated exact originals intentionally reuse a token. Shortened discriminators
provide probabilistic cross-call de-correlation, not global uniqueness.

Fixed-salt APIs exist for tests. Reusing a known salt in production permits
correlation and guessing against low-entropy original values. The salt is not
an application encryption key. A mapping and its originals remain sensitive
regardless of how tokens are derived.

Category labels, token counts, text structure, and untouched quasi-identifiers
remain observable. Python's span class and local streaming adapter retain their
legacy token formats; streaming counter tokens do not claim the native HMAC
privacy properties. Restoration scans the response once and does not recursively
substitute newly restored originals. Unknown tokens stay unchanged; partial
responses may omit stored tokens.

## Classification and network behavior

The default span-based and native paths make no network requests. The Python
streaming model must be installed separately; runtime loading never downloads
it. Missing local models fail before output. Detection runs locally when this
adapter is used.

`ShieldAdapter`, installed with `[shield]`, is an explicit HTTP integration. It
sends raw input to the caller-configured service. Point it at a local service for
local classification. Callers control endpoint trust, transport protection,
retention, and authentication. `cloud=False` does not sandbox arbitrary injected
classifiers or prevent them from using a network. No `[cloud]` extra is provided;
the compatibility flag is not an enforcement boundary.

Malformed Shield responses fail with `ClassifierError`. An explicit empty
`entities` array remains a valid zero-detection result, which can reflect a
recognizer miss. Invalid offsets, mismatched supplied source text, and invalid
confidence configuration are rejected. Correct shape alone cannot guarantee
that a classifier found every sensitive value.

## Finalization and audit

Python `redact_stream` processes one finite finalized record. It receives all
transport chunks before classifying or releasing output. A cross-chunk entity
cannot leak its earlier prefix through a previous yield. Buffer size/chunk-count
limits fail without output. Callers must submit finalized records; an unfinished
live stream is not implicitly safe to flush. Classifier recall remains a separate
limitation. Overlapping local detections protect the union of their ranges.

When an audit emitter is supplied, events must be acknowledged before output is
returned/yielded. Audit failures raise without delivering that operation's result.
Python reversible redaction attempts to delete the new mapping if its audit
fails. A custom store can itself fail cleanup; that failure is logged without
raw payloads and the redaction still raises. Store persistence and external audit
sinks do not form a distributed transaction. Earlier acknowledged events may
record an attempt that ultimately failed.

Events contain category/count/mode and context rather than original values.
Exception messages from external emitters are not copied into structured logs.
Callers must also configure their own logs, sinks and transports to avoid
capturing raw requests or mapping contents.

Swift/C sentence delivery first redacts the complete document, then delivers
exact slices. It is batch processing, not a live classification stream. No
claim of first-sentence output before complete redaction is made.

## Non-guarantees and remaining work

- Complete PII detection, semantic anonymization, k-anonymity and differential privacy.
- Secure erasure of all process/OS/storage copies or resilience to caller compromise.
- Automatic network sandboxing of user-provided classifiers or stores.
- Built-in encryption, backup management, or authentication for every embedding application.
- Guaranteed globally unique tokens or unchanged output from an external LLM.
- Unified detection and token grammar across every historical API.

The remaining consolidation work is to migrate Python span and streaming
algorithms onto the validated Rust core, establish a single public contract,
and expand platform-installed and end-to-end pipeline testing.
