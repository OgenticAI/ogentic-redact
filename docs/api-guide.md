# API guide — redaction modes and mapping lifecycle

Redact replaces sensitive spans and optionally restores their exact originals.
Shield or the caller supplies production classifications. The built-in native
EMAIL / PHONE / US_SSN scanner is a development convenience, not a complete PII
classifier.

## One-way results

Default native calls return only redacted text and a non-sensitive detection
count. They never return or retain a reversal mapping. This applies to fixed-salt
calls as well. Fixed salts are intended for tests, not production correlation
protection.

```python
from ogentic_redact import redact
result = redact('Email alice@example.com')
assert 'tokens' not in result
print(result['text'], result['redaction_count'])
```

```javascript
const { redact } = require('@ogenticai/redact')
const result = redact('Email alice@example.com')
console.log(result.text, result.redactionCount)
```

Rust exposes `redact_one_way` / `redact_one_way_with_salt`. C JSON uses
`redaction_count`; Swift exposes `redactionCount`. Text with no recognized entity
is returned unchanged. Lack of a detection is not a privacy certification.

## Explicit reversible redaction

Python's span-based class stores mappings separately, scoped by `matter_id`:

```python
from ogentic_redact import Redactor, Span, InProcessMappingStore

store = InProcessMappingStore(ttl_seconds=300, max_entries=1000)
r = Redactor(reversible=True, mapping_store=store)
result = r.redact('Alice wrote to alice@example.com', [
    Span(start=0, end=5, entity_type='PERSON', group=3),
    Span(start=15, end=32, entity_type='EMAIL_ADDRESS', group=3),
], matter_id='matter-1')
# Send only result.text to the model. Keep result.mapping_id in trusted context.
# A response may retain only some tokens; unused mappings are skipped.
restored = r.unredact(result.text, result.mapping_id, matter_id='matter-1', consume=True)
```

`consume=True` deletes atomically after successful restoration. A second lookup
fails, and only one concurrent consumer can return a result. Invalid text or
exceeded restoration limits leave the mapping available for retry. For
multiple responses, omit `consume` and explicitly call
`store.delete(mapping_id, matter_id)` when finished. Missing, expired, or
cross-matter IDs fail. Tenant identity must come from trusted application state.

`InProcessMappingStore` and `SQLiteMappingStore` support optional `ttl_seconds`
and `max_entries`. Expiry prevents retrieval; it is not a background erasure
timer. SQLite fetches are read-only point lookups. Writes purge expired rows in
batches of at most 1,000, and `store.purge_expired(limit=1000)` can explicitly
run bounded maintenance. Capacity counts live mappings and rejects new mappings
rather than evicting live ones. Defaults remain unlimited for compatibility.
SQLite persists across restarts; new files use owner-only permissions. Mappings
remain plaintext, and deletion does not erase backups or filesystem snapshots.
A failed mandatory audit attempts to remove the newly written mapping before
raising. Custom stores must implement the lifecycle protocol for this cleanup.

Node and Swift offer explicit `ReversibleRedactor` instances. A mapping belongs
to the instance that created it; a different instance cannot restore it. Close
or release the instance when its mappings are no longer needed. These convenience
sessions use the development scanner, not Shield classification.

```javascript
const { ReversibleRedactor } = require('@ogenticai/redact')
const session = new ReversibleRedactor()
const { text, mappingId } = session.redact('Email alice@example.com')
const original = session.unredact(text, mappingId, true) // consume the mapping
```

C uses `ogentic_redactor_open`, `ogentic_redactor_redact`,
`ogentic_redactor_unredact`, `ogentic_redactor_delete`, and
`ogentic_redactor_close`. Returned buffers must be freed once with the matching
length via `ogentic_redact_free`. A store handle must not be closed while a call
uses it. Rust exposes `MappingStore`, `RedactMode::Reversible`, `unredact`,
`unredact_and_delete`, and `MappingStore::delete`.

The Rust `redact_to_mapping` functions and Python private
`_native._redact_to_mapping` are explicitly sensitive low-level adapters for
separate stores and CLI files. Their raw maps are not safe outbound results and
must never be forwarded with the text. They are not the default one-way APIs.
The legacy explicit-map restoration helpers remain available for caller-owned
mappings; new application code should use scoped stores.

## Shield boundary and caller spans

```python
from ogentic_redact import Redactor, ShieldAdapter, SHIELD_LEGAL

r = Redactor(classifier=ShieldAdapter('http://127.0.0.1:8600'))
result = r.redact('Alice, SSN 219-09-9999', profile=SHIELD_LEGAL)
```

`ShieldAdapter` POSTs `{text, profiles: [profile]}` to `/analyze` for an explicit
profile. The `default` sentinel omits `profiles` and uses the service configuration.
It requires a
valid response containing an `entities` array; missing or malformed fields raise
`ClassifierError`, rather than treating the input as clean. Span offsets must be
integers, confidence must be finite and in range, and supplied matched text must
agree with the original range. Shield's `category_group` determines precedence.
Unknown category labels remain supported.

`min_confidence` must be finite and in `[0, 1]`. It filters validated detections;
raising it trades coverage for fewer false positives. With no classifier and no
spans, `Redactor` performs no replacements. Explicit `spans=[]` intentionally
bypasses classification.

Python offsets are Unicode code-point offsets. Rust `redact_spans` accepts UTF-8
byte offsets and rejects invalid boundaries, out-of-bounds ranges, and overlaps.
Callers must convert coordinate systems explicitly; JavaScript UTF-16 indices
and Swift grapheme indices are not interchangeable with either. Python merges
each connected group of overlapping spans into its entire covered region.
The replacement label is chosen by lower group, earlier start, longer span,
then entity type, independent of input order. Adjacent spans remain separate.
Reversal stores the full original region, and audit counts protected regions.

The HTTP adapter is an explicit network integration installed with `[shield]`.
It sends original input to the configured endpoint. Point it at a local Shield
service for local processing. `cloud=False` does not sandbox arbitrary injected
classifiers; there is no `[cloud]` extra.

## Finalized records and delivery

Python `redact_stream(chunks, profile)` accepts transport chunks of one finite
record. It waits for the iterable to end, classifies the complete record, and
acknowledges configured audit events before yielding any output. It still yields
one pair per input chunk; a cross-chunk entity is replaced once where it starts,
and its remaining portions are suppressed. Events use each original chunk's
coordinates; audit counts count the whole protected region once.

This finalization is intentional. An arbitrary transport chunk cannot prove a
name or number is complete. Live callers should submit finalized utterances or
records, rather than an unending stream. Buffer limits default to 100,000
characters and 4,096 chunks and can be set through `max_buffer_chars` and
`max_chunks`. Exceeding either fails without output. Overlapping local detections
protect their entire union, labeled by the strongest detection.

Streaming uses the installed English `en_core_web_sm` model. Install it during
setup using `python -m spacy download en_core_web_sm`; runtime loading never
initiates a download. `cloud=True` is unsupported on this local streaming API.
Requested entity types must be supported by that installed analyzer; a capability
mismatch raises before any output. For example, the stock analyzer cannot fulfill
the CASE_NUMBER/BATES_NUMBER entities in `shield-legal`. Use Shield classification
for that policy or explicitly install the matching local recognizers. An explicit
`Profile(entity_types=[])` disables detection and does not load the local model.

Swift/C sentence delivery is a different API: it first redacts the whole supplied
document, then delivers exact slices on demand. It preserves whitespace but is
not incremental detection. Do not interpret its first-result latency as live
transcription latency.

## Tokens and restoration

Native tokens use `[Label_<hex>]`, per-call random salts and HMAC. Collision
handling and source-literal reservation keep distinct originals distinct within
a call. Exact spelling is retained; case variants no longer restore as the first
spelling. Tokens are not globally unique, and repeated exact values within one
call intentionally correlate.

Python `Redactor` currently retains `[RTKN_<hex>]` with a 128-bit discriminator; the local streaming adapter
retains `<<ENTITY_TYPE_N>>`. These are still separate implementations. Use the
same API and mapping store for reversal. Restoration is single-pass: restored
originals are not scanned again, missing mapping keys are left unchanged, and
unused mappings do not make partial model replies fail.

Restoration is bounded by default to **16 MiB of UTF-8 output** and **100,000
mapped token occurrences**. Size is checked before constructing the restored
output. Python `Redactor.unredact` and native `unredact` accept keyword options
`max_output_bytes` and `max_replacements`. Both are non-negative; zero can prohibit
output or replacements. Larger documents require an explicit larger budget.
Rust exposes `RestorationLimits` and `unredact*_with_limits` variants. Native
sessions also accept configured limits. Failed validation/restoration must not
consume the mapping.

## CLI and MCP

```bash
# One-way: no mapping file
ogentic-redact report.txt > redacted.txt
# Explicit reversible: mapping is a separate sensitive file
ogentic-redact report.txt --mapping mapping.json > redacted.txt
ogentic-redact unredact redacted.txt --mapping mapping.json > restored.txt
```

The CLI rejects unsupported mapping-format versions. Creating a mapping refuses
an existing destination, including symlinks and the input file itself. New Unix
vault files use owner-only permissions and are published only after the complete
vault is written. Keep mapping files separate from outbound text and apply
retention and access controls.

The optional `[mcp]` extra exposes `redact.outbound` and
`redact.unredact_response`. Mapping values stay in the server store; requests
receive only redacted text and `mapping_id`. The server binds tenant scope at
construction. Its scanner and profile-selection limitations remain documented
in `python/ogentic_redact/mcp/server.py`; it is not a replacement for the Shield
production classification path.
`build_server(max_output_bytes=..., max_replacements=...)` sets restoration budgets
for the session. Tool callers cannot raise those server-owned limits.

## Pre-release migration

Default native/Python top-level/Node/C/Swift results no longer have `tokens` or
`tokenMap`. Code restoring through those fields must use an explicit reversible
session or Python `Redactor(reversible=True)`. The native result now carries only
text and a count; sentence-delivery chunks carry only text. This is an intentional
privacy correction to the pre-release API.

Python custom mapping stores must add scoped `delete` and atomic `consume`.
Mapping IDs identify immutable records and must never be reused for another
mapping. Restoration may fetch/validate before attempting atomic consumption.
Rust's explicit-map `unredact_one_way` helper now returns a `Result` so limit
errors cannot silently return partial output. Source builds require Rust 1.88
or newer; CI checks that declared minimum.
Python streaming callers must finalize each record and account for buffering
before first output. Existing model setup should be explicit. Consumers must
rebuild native extensions and Swift static libraries together with the updated
headers and bindings.
