# Redact Demo Path Design — CLI Round-Trip + MCP Server

**Status:** Wave 2 planning (CLI and MCP are stubs today; implementation target September)
**Ticket:** [OGE-934](https://linear.app/ogenticai/issue/OGE-934)
**Last updated:** 2026-06-27

---

## 1. Why — the reversible-mapping differentiator

`ogentic-redact` occupies a different position in the pipeline than `ogentic-shield`.

**Shield (`shield.redact`)** is one-way + inline: the mapping is returned directly in
the response payload (`{redacted_text: str, mapping: dict}`). The caller gets everything
in one shot. This works for shield's "analyze before sending" use case, where the
mapping is ephemeral and the caller owns the conversation context.

**Redact** is two-phase with a separate vault: the redacted text and the mapping are
never collocated after the call returns. The MCP tool returns `{redacted: str,
mapping_id: str}` — an opaque identifier, not the inline mapping. The vault that
holds the actual token-to-original table is written separately, either to a local
file (CLI mode) or to a server-side store (MCP/server mode).

This distinction is not a limitation; it is the architectural commitment stated in
`CLAUDE.md` §4:

> Reversible (tokenised) mode requires `Redactor(reversible=True)` and emits a
> separate vault file — never inlined.

The demo must make this fork visible. Showing it side-by-side with shield's inline
response is the clearest way to communicate the design intent to an evaluator.

---

## 2. CLI surface

The CLI is a Wave 2 target. Today the entry point is a stub. The intended surface is:

**Forward redaction (write vault to file):**

```
ogentic-redact <input-file> --mapping <out.json>
```

- Requires `Redactor(reversible=True)` internally. Without the flag the vault is not
  written and the `--mapping` output file is not produced.
- Writes the redacted text to stdout (or `--output <file>` when added).
- Writes the mapping vault to `<out.json>`.

**Reverse redaction (restore from vault):**

```
ogentic-redact unredact <redacted-file> --mapping <in.json>
```

- Reads the vault from `<in.json>`.
- Writes the restored text to stdout.

Both commands are on-device by default — no network calls. Cloud-assisted recognisers
are opt-in via the `[cloud]` extra and emit a runtime warning on first use.

---

## 3. MCP tool surface

The MCP server follows the pattern established in `ogentic-shield` (see
`shield/src/ogentic_shield/mcp/server.py`). It uses `mcp>=1.0` FastMCP with
`@server.tool(name="...")` decorators. Tool inputs are JSON-friendly primitives
(strings), not dataclasses.

The server is an optional dependency:

```
pip install 'ogentic-redact[mcp]'
```

Two tools are exposed:

**`redact.outbound`**

```
Input:  text: str, profile: str
Output: { redacted: str, mapping_id: str }
```

Applies the named redaction profile to `text` and stores the mapping vault under
`mapping_id`. The mapping is never returned inline — only the opaque ID is returned.
The `_KNOWN_PROFILES` guard applies: unknown profile names are rejected before any
processing occurs, mirroring shield's hostile-profile injection defence.

**`redact.unredact_response`**

```
Input:  text: str, mapping_id: str
Output: str  (restored text)
```

Looks up the vault by `mapping_id` and restores the original tokens in `text`.
Returns an error if `mapping_id` is unknown or the vault has expired.

---

## 4. What a 30-second demo looks like

These three steps are Wave 2 targets. They are written here so the API surface is
shaped by the demo's needs from day one.

1. **Forward redact with mapping file.**
   Run `ogentic-redact sample.txt --mapping vault.json`. Show the redacted output and
   the vault file side-by-side. Point out that the vault is separate — it was never
   part of the response.

2. **Illustrative LLM call.**
   Paste the redacted text into any LLM (the demo does not call one programmatically —
   the point is that the text sent to the model contains no real PII). Read back the
   model's response.

3. **Unredact.**
   Run `ogentic-redact unredact response.txt --mapping vault.json`. Show the restored
   text. The full round-trip is complete without the LLM ever having seen the original
   sensitive content.

---

## 5. Open question: mapping_id persistence

How the vault is stored is not decided. Three options are on the table — this section
surfaces them, it does not choose between them.

**(a) In-process dict (dev/demo)**
The `mapping_id` keys an in-memory `dict` in the running process. Zero dependencies.
Survives only as long as the process lives; dies on restart. Acceptable for local demos
and unit tests, not for any multi-request or multi-process scenario.

**(b) Local SQLite vault**
The mapping store is a SQLite file on disk. Survives restarts, still fully on-device,
no external dependencies. Fits the "on-device by default" constraint from `CLAUDE.md` §4.
Likely the right answer for the CLI flow and single-user MCP server deployments.

**(c) Tenant-keyed external store**
For multi-tenant MCP server deployments the vault needs to be an external service
(e.g. a keyed Redis or a simple REST vault). This is the option that requires the
`[cloud]` extra and triggers the runtime warning. It is also the option that brings
tenant isolation into scope (see §6).

The Wave 2 implementation decision should be made before the MCP server stub is
filled in. The API surface (`mapping_id: str` as the opaque identifier) is intentionally
store-agnostic so any of the three can be swapped in.

---

## 6. Tenant isolation

This applies when option (c) or any server-side store is used.

Any server-side mapping store must be scoped per-tenant. `mapping_id` values must not
be resolvable across tenant boundaries — a `mapping_id` issued for `tenant_id=A` must
return an error (not the wrong vault) when presented under `tenant_id=B`.

`tenant_id` is derived from the authenticated principal at the MCP session boundary,
never from the request body. This mirrors the pattern enforced across the OgenticAI
service layer.

For the in-process dict and local SQLite options (a and b above), tenant isolation is
trivially satisfied by process/file ownership. It becomes an explicit enforcement
requirement only when an external shared store is introduced.

---

## 7. References

- [OGE-927 — Public demo surfaces for every OSS primitive](https://linear.app/ogenticai/issue/OGE-927/public-demo-surfaces-for-every-oss-primitive)
- [OGE-928 — feat(audit): MCP server — audit.append / verify / export_pdf / tail](https://linear.app/ogenticai/issue/OGE-928/feataudit-mcp-server-auditappend-verify-export-pdf-tail)
- `ogentic-shield` MCP pattern: `shield/src/ogentic_shield/mcp/server.py`
- `CLAUDE.md` §4 — architecture rules (reversible mode, on-device constraint)
